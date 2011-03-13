#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "git2.h"

static const char *oid2str(const git_oid *oid) {
	if (oid == NULL) {
		return "(null)";
	}
	else {
		static char buf[GIT_OID_HEXSZ + 1];
		git_oid_to_string(buf, GIT_OID_HEXSZ + 1, oid);
		return buf;
	}
}

static const char *canonicalize_refname(git_repository *repo, const char *refname) {
	git_strarray refnames;
	const char *name = NULL;
	int status;
	int i;

	/* there are no quick opt outs here: ref names may contain slashes, start with "refs/", etc.
	 * we'll simply have to iterate through them all and learn to live with the performance penalty
	 *
	 * $ git branch refs/heads/master # perfectly legal
	 *
	 * TODO the matching algorithm should handle ambiguities better
	 *
	 * "master"            -> "refs/heads/master" but not "refs/heads/master/refs/heads/master"
	 * "refs/heads/master" -> "refs/heads/master/refs/heads/master" if that ref exists, otherwise "refs/heads/master"
	 */
	memset(&refnames, 0, sizeof refnames);

	status = git_reference_listall(&refnames, repo, GIT_REF_LISTALL);
	if (status < 0) {
		fprintf(stderr, "git_reference_listall: %s\n", git_strerror(status));
		return NULL;
	}

	for (i = 0; i < refnames.count; i++, name = NULL) {
		name = refnames.strings[i];

#define equals(a, b, c) (strncmp(a, b, sizeof(b) - 1) == 0 && strcmp(a + sizeof(b) - 1, c) == 0)
		if (strcmp(name, refname) == 0
			|| equals(name, "refs/tags/", refname)
			|| equals(name, "refs/heads/", refname)
			|| equals(name, "refs/remotes/", refname))
#undef equals
		{
			/* TODO replace with apr_pstrdup(), leaks memory now */
			name = strdup(name);
			break;
		}
	}

	git_strarray_free(&refnames);

	return name;
}

static git_commit *resolve_ref(git_repository *repo, const char *refname) {
	const char *canonicalized = NULL;
	const git_oid *oid = NULL;
	git_reference *ref = NULL;
	git_commit *commit = NULL;
	int status;

	canonicalized = canonicalize_refname(repo, refname);
	if (canonicalized == NULL) {
		/* not a ref but it could be a commit hash */
		return NULL;
	}

	status = git_reference_lookup(&ref, repo, canonicalized);
	if (status < 0) {
		fprintf(stderr, "git_reference_lookup(%s): %s", refname, git_strerror(status));
		return NULL;
	}

	oid = git_reference_oid(ref);
	if (oid == NULL) {
		fprintf(stderr, "git_reference_oid(%s): not an OID", refname);
		return NULL;
	}

	status = git_commit_lookup(&commit, repo, oid);
	if (status < 0) {
		fprintf(stderr, "git_commit_lookup(%s): %s", oid2str(oid), git_strerror(status));
		return NULL;
	}

	return commit;
}

static git_commit *resolve_hash(git_repository *repo, const char *hash) {
	git_oid oid[GIT_OID_HEXSZ + 1];
	git_commit *commit = NULL;
	int status;

	if (strlen(hash) != 40) {
		/* not a valid hash */
		fprintf(stderr, "resolve_commit(%s): %s", hash, git_strerror(GIT_ENOTOID));
		return NULL;
	}

	status = git_oid_mkstr(oid, hash);
	if (status < 0) {
		fprintf(stderr, "git_oid_mkstr(%s): %s", hash, git_strerror(status));
		return NULL;
	}

	status = git_commit_lookup(&commit, repo, oid);
	if (status < 0) {
		fprintf(stderr, "git_commit_lookup(%s): %s", oid2str(oid), git_strerror(status));
		return NULL;
	}

	return commit;
}

static git_tree *resolve_tree(git_repository *repo, const char *treeish) {
	git_commit *commit = NULL;
	git_tree *tree = NULL;
	int status;

	if (NULL == (commit = resolve_ref(repo, treeish)) && NULL == (commit = resolve_hash(repo, treeish))) {
		fprintf(stderr, "resolve_tree(%s): tag, branch or commit not found", treeish);
		return NULL;
	}

	status = git_commit_tree(&tree, commit);
	if (status < 0) {
		fprintf(stderr, "git_commit_tree(%s): %s", oid2str(git_commit_id(commit)), git_strerror(status));
		return NULL;
	}

	return tree;
}

static const char *next_path_segment(const char *path, char *buf, int size, const char **state) {
	const char *p, *q;
	int len;

	if (size > 0) {
		buf[0] = '\0';
	}

	if (*state == NULL) {
		*state = path;
	}

	/* trim leading slashes */
	for (p = *state; *p == '/' && *p != '\0'; p++);

	if (*p == '\0') {
		return NULL;
	}

	q = strchr(p, '/');
	if (q == NULL) {
		q = p + strlen(p);
	}
	len = q - p;

	memcpy(buf, p, len);
	buf[len] = '\0';

	*state = q;

	return buf;
}

static git_object *resolve_object(git_repository *repo, const char *treeish, const char *path) {
	git_tree_entry *entry = NULL;
	git_object *obj = NULL;
	git_tree *tree = NULL;
	const char *state = NULL;
	char ps[256];
	int status;

	tree = resolve_tree(repo, treeish);
	if (tree == NULL) {
		return NULL;
	}

	while (next_path_segment(path, ps, sizeof ps, &state)) {
		entry = git_tree_entry_byname(tree, ps);
		if (entry == NULL) {
			fprintf(stderr, "git_tree_entry_byname(%s): not found", ps);
			return NULL;
		}

		status = git_tree_entry_2object(&obj, entry);
		if (status < 0) {
			fprintf(stderr, "git_tree_entry_2object(%s): %s", git_tree_entry_name(entry), git_strerror(status));
			return NULL;
		}

		if (git_object_type(obj) == GIT_OBJ_TREE) {
			tree = (git_tree *) obj;
		}
		else {
			/* allow path info URLs */
			break;
		}
	}

	return obj;
}

static git_blob *resolve_blob(git_repository *repo, const char *treeish, const char *path) {
	git_object *obj = NULL;
	git_blob *blob = NULL;
	int status;

	obj = resolve_object(repo, treeish, path);
	if (obj == NULL) {
		return NULL;
	}

	if (git_object_type(obj) == GIT_OBJ_TREE) {
		puts("is_dir");
//		return NULL;
	}

	status = git_blob_lookup(&blob, repo, git_object_id(obj));
	if (status < 0) {
		fprintf(stderr, "git_blob_lookup(%s:%s): %s", treeish, path, git_strerror(status));
		return NULL;
	}

	return blob;
}

static void print(const char *repo_path, const char *treeish, const char *path) {
	git_repository *repo = NULL;
	git_tree_entry *e = NULL;
	git_object *obj = NULL;
	git_blob *blob = NULL;
	int i, status;

	status = git_repository_open(&repo, repo_path);
	if (status < 0) {
		fprintf(stderr, "git_repository_open(%s): %s\n", repo_path, git_strerror(status));
		return;
	}

	obj = resolve_object(repo, treeish, path);
	if (obj == NULL) {
		return;
	}

	switch (git_object_type(obj)) {
	case GIT_OBJ_TREE:
	{
		for (i = 0; (e = git_tree_entry_byindex((git_tree *) obj, i)); i++) {
			printf("[%i] %s\n", i, git_tree_entry_name(e));
		}
		break;
	}

	case GIT_OBJ_BLOB:
	{
		status = git_blob_lookup(&blob, repo, git_object_id(obj));
		if (status < 0) {
			fprintf(stderr, "git_blob_lookup(%s:%s): %s", treeish, path, git_strerror(status));
		}
		else {
			const char *content = git_blob_rawcontent(blob);
			int size = git_blob_rawsize(blob);
			fwrite(content, 1, size, stdout);
		}
		break;
	}

	default:
		fprintf(stderr, "type %s not handled", git_object_type2string(git_object_type(obj)));
	}

	git_repository_free(repo);
}

#if 0
static void ps_test_one(const char *path) {
	const char *state, *ps;
	char buf[64];

	printf("*** %s\n", path);

	state = NULL;
	while ((ps = next_path_segment(path, buf, sizeof(buf), &state))) {
		puts(ps);
	}
}

static void ps_test_all(void) {
	ps_test_one("");
	ps_test_one("/");
	ps_test_one("index.html");
	ps_test_one("/index.html");
	ps_test_one("foo/bar/");
	ps_test_one("/foo/bar/");
	ps_test_one("foo/bar///");
	ps_test_one("/foo/bar///");
	ps_test_one("foo/bar/baz.txt");
	ps_test_one("/foo/bar/baz.txt");
}
#endif

int main(int argc, char **argv) {
	print(argv[1], argv[2], argv[3]);
	return 0;
}
