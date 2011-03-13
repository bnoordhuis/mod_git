#include "httpd.h"
#include "http_log.h"
#include "http_config.h"
#include "http_request.h"
#include "http_protocol.h"
#include "ap_config.h"

#include "apr_strings.h"

#include "git2.h"

/* per-directory config */
typedef struct {
	int prefix_len;
	const char *path;
	const char *ref;
} mod_git_dconf;

/* per-request config */
typedef struct {
	git_repository *repo;
	const git_oid *oid;       /* OID of the object this request points to */
	int status_code;          /* HTTP status code to return in the handler */
	const char *filename;
	apr_filetype_e filetype;
} mod_git_rconf;

module AP_MODULE_DECLARE_DATA git_module;

static const char *oid2str(request_rec *r, const git_oid *oid) {
	if (oid == NULL) {
		return "(null)";
	}
	else {
		char *buf = apr_palloc(r->pool, GIT_OID_HEXSZ + 1);
		git_oid_to_string(buf, GIT_OID_HEXSZ + 1, oid);
		return buf;
	}
}

static apr_status_t rconf_cleanup(void *arg) {
	mod_git_rconf *rc = arg;
	git_repository_free(rc->repo);
	return APR_SUCCESS;
}

static mod_git_rconf *find_object(request_rec *r) {
	const git_oid *oid;
	git_reference *ref;
	git_tree *tree;
	git_tree_entry *entry;
	git_object *obj;
	git_blob *blob;
	const char *refname;
	int status, size;
	mod_git_dconf *dc;
	mod_git_rconf *rc;

	dc = ap_get_module_config(r->per_dir_config, &git_module);
	if (dc->path == NULL) {
		return NULL;
	}

	rc = apr_pcalloc(r->pool, sizeof *rc);
	rc->status_code = HTTP_INTERNAL_SERVER_ERROR;
	rc->filetype = APR_NOFILE;
	apr_pool_cleanup_register(r->pool, rc, rconf_cleanup, NULL);

	status = git_repository_open(&rc->repo, dc->path);
	if (status < 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "git_repository_open(%s): %s", dc->path, git_strerror(status));
		return rc;
	}

	/* TODO resolve short branch/tag names */
	refname = dc->ref ? dc->ref : "refs/heads/master";

	status = git_reference_lookup(&ref, rc->repo, refname);
	if (status < 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "git_reference_lookup(%s): %s", refname, git_strerror(status));
		return rc;
	}

	oid = git_reference_oid(ref);
	if (oid == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "git_reference_oid(%s): not an OID", refname);
		return rc;
	}

	rc->filename = r->uri + dc->prefix_len;
	rc->filetype = APR_REG;

	if (rc->filename[0] == '/') {
		rc->filename++;
	}

	if (rc->filename[0] == '\0') {
		rc->filetype = APR_DIR;
		return rc;
	}

	status = git_object_lookup(&obj, rc->repo, oid, GIT_OBJ_ANY);
	if (status < 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "git_object_lookup(%s): %s",
				oid2str(r, oid), git_strerror(status));
		return rc;
	}

	switch (git_object_type(obj)) {
	case GIT_OBJ_COMMIT:
		{
			git_commit *commit = NULL;

			status = git_commit_lookup(&commit, rc->repo, git_object_id(obj));
			if (status < 0) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "git_commit_lookup(%s): %s",
						oid2str(r, git_object_id(obj)), git_strerror(status));
				return rc;
			}

			status = git_commit_tree(&tree, commit);
			if (status < 0) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "git_commit_tree(%s): %s",
						oid2str(r, git_commit_id(commit)), git_strerror(status));
				return rc;
			}
		}
		break;

	default:
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "%s objects not yet supported",
				git_object_type2string(git_object_type(obj)));
		return rc;
	}

	if (tree == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "no matching tree");
		return rc;
	}

	entry = git_tree_entry_byname(tree, rc->filename);
	if (entry == NULL) {
		rc->status_code = HTTP_NOT_FOUND;
		rc->filetype = APR_NOFILE;
		return rc;
	}

	status = git_tree_entry_2object(&obj, entry);
	if (status < 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "git_tree_entry_2object(%s): %s",
				git_tree_entry_name(entry), git_strerror(status));
		return rc;
	}

	rc->oid = git_object_id(obj);
	rc->status_code = OK;

	return rc;
}

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

static int mod_git_translate_name(request_rec *r) {
	mod_git_rconf *rc;

	rc = find_object(r);
	if (rc == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "no mapping for %s", r->uri);
		return DECLINED;
	}
	else {
		ap_set_module_config(r->request_config, &git_module, rc);

		/* this makes mod_dir and mod_mime perform their magic */
		r->filename = apr_pstrdup(r->pool, rc->filename);
		r->finfo.filetype = rc->filetype;

		ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "%s mapped to %s", r->uri, r->filename);
		return DECLINED;
	}
}

static int mod_git_handler(request_rec *r) {
	const void *content;
	int status, size;
	git_blob *blob;
	mod_git_rconf *rc;

	rc = ap_get_module_config(r->request_config, &git_module);

	if (rc == NULL) {
		return DECLINED;
	}

	ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "status_code == %d", rc->status_code);

	if (rc->status_code != OK) {
		return rc->status_code;
	}

	status = git_blob_lookup(&blob, rc->repo, rc->oid);
	if (status < 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "git_blob_lookup(%s): %s",
				oid2str(r, rc->oid), git_strerror(status));
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	size = git_blob_rawsize(blob);

	if (r->header_only) {
		ap_set_content_length(r, size);
	}
	else {
		content = git_blob_rawcontent(blob);
		if (content == NULL) {
			/* defense in depth, this should never happen */
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "git_blob_rawcontent(%s): %s",
					oid2str(r, rc->oid), git_strerror(status));
			return HTTP_INTERNAL_SERVER_ERROR;
		}
		else {
			ap_rwrite(content, size, r);
		}
	}

	return OK;
}

static void mod_git_register_hooks(apr_pool_t *p) {
	ap_hook_translate_name(mod_git_translate_name, NULL, NULL, APR_HOOK_MIDDLE);
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

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(git);
#endif
