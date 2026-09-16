package server

import "strings"

// repoBeforeLastSuffix returns the substring of path that precedes the last
// occurrence of any of the given markers, or "" if none matches at a positive
// index. Repository names may contain "/" (multi-level namespaces) and may even
// contain a reserved segment like "tags" or "manifests", so callers must not
// split on "/" naively. Matching the *last* marker (rather than the first) keeps
// e.g. "team/tags/tags" and "a/manifests/b/manifests/v1" intact instead of
// truncating them to the parent namespace. This helper is the single source of
// truth for locating where the repo name ends and a known API/registry sub-path
// begins.
func repoBeforeLastSuffix(path string, markers ...string) string {
	best := -1
	for _, marker := range markers {
		if idx := strings.LastIndex(path, marker); idx > best {
			best = idx
		}
	}
	if best <= 0 {
		return ""
	}
	return path[:best]
}

// v2SubPathSuffixes are the registry sub-path markers that follow a repo
// name in a /v2/ URL.
var v2SubPathSuffixes = []string{"/manifests/", "/blobs/", "/tags/list"}

// apiRepoSubPathSuffixes are the UI-API sub-path markers that follow a repo
// name under /api/repositories/.
var apiRepoSubPathSuffixes = []string{
	"/tags", "/manifests/", "/blobs/", "/stats", "/tag-policy", "/init",
	"/manifests/batch-delete", "/retention-preview", "/retention-run",
}

// extractV2RepoPath extracts the repository path from a /v2/ URL.
// Returns "" for /v2/ (root) and /v2/_catalog which are not repo-specific.
func extractV2RepoPath(path string) string {
	if !strings.HasPrefix(path, "/v2/") {
		return ""
	}
	rest := strings.TrimPrefix(path, "/v2/")
	if rest == "" || rest == "_catalog" || strings.HasPrefix(rest, "_catalog/") {
		return ""
	}
	if repo := repoBeforeLastSuffix(rest, v2SubPathSuffixes...); repo != "" {
		return repo
	}
	return rest
}

// extractRepoNameFromPath extracts the repository name from a subroute path
// under /api/repositories/. e.g. "library/nginx/tags" -> "library/nginx",
// "library/sub/repo/manifests/v1" -> "library/sub/repo",
// "team/tags/tags" -> "team/tags".
func extractRepoNameFromPath(path string) string {
	return repoBeforeLastSuffix(path, apiRepoSubPathSuffixes...)
}
