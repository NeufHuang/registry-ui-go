package server

import "testing"

// TestV2PullResourceRepoPath pins the parsing used to decide anonymous pull.
// It must agree with extractV2RepoPath, including for repositories whose own
// name contains a reserved segment such as "manifests" or "blobs".
func TestV2PullResourceRepoPath(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/v2/", ""},
		{"/v2", ""},
		{"/v2/_catalog", ""},
		{"/v2/team/app/manifests/latest", "team/app"},
		{"/v2/team/app/manifests/sha256:abc", "team/app"},
		{"/v2/team/app/blobs/sha256:abc", "team/app"},
		{"/v2/python/manifests/3.13-alpine", "python"},
		{"/v2/team/app/tags/list", ""},
		{"/v2/team/app", ""},
		{"/v2/team/manifests/app/manifests/v1", "team/manifests/app"},
		{"/v2/team/blobs/app/blobs/sha256:abc", "team/blobs/app"},
	}
	for _, tc := range cases {
		if got := v2PullResourceRepoPath(tc.path); got != tc.want {
			t.Errorf("v2PullResourceRepoPath(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

// TestPullAndAuthRepoPathsAgree guarantees the anonymous-pull decision and the
// namespace-authorization decision resolve the same repository name; a
// mismatch would either leak content or deny legitimate pulls.
func TestPullAndAuthRepoPathsAgree(t *testing.T) {
	paths := []string{
		"/v2/team/app/manifests/latest",
		"/v2/team/app/blobs/sha256:abc",
		"/v2/team/manifests/app/manifests/v1",
		"/v2/a/blobs/b/blobs/sha256:abc",
		"/v2/python/manifests/3.13-slim",
	}
	for _, p := range paths {
		if pull, auth := v2PullResourceRepoPath(p), extractV2RepoPath(p); pull != auth {
			t.Errorf("%s: anonymous-pull repo %q != authorization repo %q", p, pull, auth)
		}
	}
}
