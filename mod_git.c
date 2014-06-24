/* Copyright (c) 2011, Ben Noordhuis <info@bnoordhuis.nl>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "httpd.h"
#include "http_log.h"
#include "http_config.h"
#include "http_request.h"
#include "http_protocol.h"
#include "ap_config.h"

#include "git2.h"

/* per-directory config */
typedef struct {
	int prefix_len;
	const char *path;
	const char *ref;
} mod_git_dconf;

module AP_MODULE_DECLARE_DATA git_module;

static void *mod_git_create_dir_config(apr_pool_t *p, char *path) {
	mod_git_dconf *dc = apr_pcalloc(p, sizeof *dc);

	dc->prefix_len = path != NULL ? strlen(path) : 0;

	return dc;
}

static void *mod_git_merge_dir_config(apr_pool_t *p, void *basev, void *addv) {
	mod_git_dconf *base = basev;
	mod_git_dconf *add = addv;
	mod_git_dconf *dc = apr_pcalloc(p, sizeof *dc);

	dc->prefix_len = add->prefix_len;
	dc->path = add->path ? add->path : base->path;
	dc->ref = add->ref ? add->ref : base->ref;

	return dc;
}

static const char *oid2str(request_rec *r, const git_oid *oid) {
	char *buf = apr_palloc(r->pool, GIT_OID_HEXSZ + 1);
	git_oid_to_string(buf, GIT_OID_HEXSZ + 1, oid);
	return buf;
}

static int mod_git_handler(request_rec *r) {
	const git_oid *oid;
	git_repository *repo;
	git_reference *ref;
	git_tree *tree;
	git_tree_entry *entry;
	git_object *obj;
	git_blob *blob;
	const char *refname;
	const char *content;
	mod_git_dconf *dc;
	int rv, status, size;

	dc = ap_get_module_config(r->per_dir_config, &git_module);

	if (dc->path == NULL) {
		return DECLINED;
	}

	repo = NULL;
	ref  = NULL;
	tree = NULL;
	obj  = NULL;
	blob = NULL;

	rv = HTTP_INTERNAL_SERVER_ERROR;

	status = git_repository_open(&repo, dc->path);
	if (status < 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "git_repository_open(%s): %s", dc->path, git_strerror(status));
		goto cleanup;
	}

	/* TODO support short branch/tag names */
	refname = dc->ref ? dc->ref : "refs/heads/master";

	status = git_reference_lookup(&ref, repo, refname);
	if (status < 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "git_reference_lookup(%s): %s", refname, git_strerror(status));
		goto cleanup;
	}

	oid = git_reference_oid(ref);
	if (oid == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "git_reference_oid(%s): not an OID", refname);
		goto cleanup;
	}

	const char *filename = r->uri + dc->prefix_len;

	if (filename[0] == '/') {
		filename++;
	}

	if (filename[0] == '\0') {
		filename = "index.html";
	}

	status = git_object_lookup(&obj, repo, oid, GIT_OBJ_ANY);
	if (status < 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "git_object_lookup(%s): %s",
				oid2str(r, oid), git_strerror(status));
		goto cleanup;
	}

	switch (git_object_type(obj)) {
	case GIT_OBJ_COMMIT:
		{
			git_commit *commit = NULL;

			status = git_commit_lookup(&commit, repo, git_object_id(obj));
			if (status < 0) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "git_commit_lookup(%s): %s",
						oid2str(r, git_object_id(obj)), git_strerror(status));
				goto cleanup;
			}

			/* cast away constness, the git_tree_* functions only accept mutable trees */
			tree = (git_tree *) git_commit_tree(commit);
		}
		break;

	default:
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "%s objects not yet supported",
				git_object_type2string(git_object_type(obj)));
		goto cleanup;
	}

	if (tree == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "no matching tree");
		goto cleanup;
	}

	entry = git_tree_entry_byname(tree, filename);
	if (entry == NULL) {
		rv = HTTP_NOT_FOUND;
		goto cleanup;
	}

	status = git_tree_entry_2object(&obj, entry);
	if (status < 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "git_tree_entry_2object(%s): %s",
				git_tree_entry_name(entry), git_strerror(status));
		goto cleanup;
	}

	oid = git_object_id(obj);

	status = git_blob_lookup(&blob, repo, oid);
	if (status < 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "git_blob_lookup(%s): %s",
				oid2str(r, oid), git_strerror(status));
		goto cleanup;
	}

	/* TODO look up content type */
	ap_set_content_type(r, "text/plain");

	size = git_blob_rawsize(blob);

	if (r->header_only) {
		ap_set_content_length(r, size);
	}
	else {
		content = git_blob_rawcontent(blob);
		if (content == NULL) {
			/* defense in depth, this should never happen */
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "git_blob_rawcontent(%s): %s",
					oid2str(r, oid), git_strerror(status));
		}
		else {
			ap_rwrite(content, size, r);
		}
	}

	rv = OK;

cleanup:
	if (repo != NULL) {
		git_repository_free(repo);
	}

	return rv;
}

static void mod_git_register_hooks(apr_pool_t *p) {
	ap_hook_handler(mod_git_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

static const char *mod_git_cmd_git(cmd_parms *cmd, void *mconf, const char *arg1, const char *arg2) {
	mod_git_dconf *dc = mconf;

	dc->path = arg1;
	dc->ref = arg2;

	return NULL;
}

static const command_rec mod_git_cmds[] = {
	AP_INIT_TAKE12("Git", mod_git_cmd_git, NULL, ACCESS_CONF,
			"Path to the bare Git repository, optionally followed by the ref name (defaults to 'master')"),
	{ NULL }
};

module AP_MODULE_DECLARE_DATA git_module = {
	STANDARD20_MODULE_STUFF,
	mod_git_create_dir_config,
	mod_git_merge_dir_config,
	NULL,
	NULL,
	mod_git_cmds,
	mod_git_register_hooks
};
