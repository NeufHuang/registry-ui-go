package store

import (
	"context"
	"database/sql"
	"sync"
	"testing"
)

// TestPragmasAppliedToEveryConnection is the regression test for the per-
// connection PRAGMA bug: the pragmas were executed once on the migration
// connection, so the other pooled connections silently ran with
// foreign_keys=0 and busy_timeout=0.
func TestPragmasAppliedToEveryConnection(t *testing.T) {
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()

	const n = 4 // matches db.SetMaxOpenConns(4)
	conns := make([]*sql.Conn, n)
	acquired := make(chan struct{}, n)
	release := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, cerr := st.db.Conn(ctx)
			if cerr != nil {
				t.Errorf("acquire conn %d: %v", i, cerr)
				acquired <- struct{}{}
				return
			}
			conns[i] = c
			acquired <- struct{}{}
			<-release // hold the connection until every goroutine has one
		}(i)
	}
	// Receiving from the channel establishes the happens-before edge for the
	// conns[i] writes, so the checks below are race-free.
	for i := 0; i < n; i++ {
		<-acquired
	}

	for i, c := range conns {
		if c == nil {
			continue
		}
		var fk, bt int
		if err := c.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&fk); err != nil {
			t.Errorf("conn %d: read foreign_keys: %v", i, err)
			continue
		}
		if err := c.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&bt); err != nil {
			t.Errorf("conn %d: read busy_timeout: %v", i, err)
			continue
		}
		if fk != 1 {
			t.Errorf("conn %d: foreign_keys=%d, want 1", i, fk)
		}
		if bt != 5000 {
			t.Errorf("conn %d: busy_timeout=%d, want 5000", i, bt)
		}
	}

	close(release)
	wg.Wait()
	for _, c := range conns {
		if c != nil {
			_ = c.Close()
		}
	}
}

// TestDeleteUserCascadesPermissionsAndTokens verifies the ON DELETE CASCADE
// actually fires now that foreign_keys is enabled on every connection.
func TestDeleteUserCascadesPermissionsAndTokens(t *testing.T) {
	ctx := context.Background()
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	u, err := st.CreateUser(ctx, "temp", "hash", false, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertUserPermission(ctx, UserPermission{UserID: u.ID, NamespacePattern: "lib", CanRead: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateAPIToken(ctx, APIToken{UserID: u.ID, Name: "t", TokenHash: "h", TokenPrefix: "pfx"}); err != nil {
		t.Fatal(err)
	}

	if err := st.DeleteUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	perms, err := st.ListUserPermissions(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(perms) != 0 {
		t.Errorf("permissions survived user deletion: %+v", perms)
	}
	if _, err := st.GetAPITokenByPrefix(ctx, "pfx"); err == nil {
		t.Error("api token survived user deletion")
	}
}

// TestDeleteNamespaceRemovesRepositories guards against the orphaned-repository
// rows that deleting only the namespaces row used to leave behind.
func TestDeleteNamespaceRemovesRepositories(t *testing.T) {
	ctx := context.Background()
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	ns, err := st.UpsertNamespace(ctx, "lib")
	if err != nil {
		t.Fatal(err)
	}
	repo, err := st.UpsertRepository(ctx, ns.ID, "nginx")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SyncImage(ctx, Image{RepositoryID: repo.ID, Tag: "v1", Digest: "sha256:abc"}); err != nil {
		t.Fatal(err)
	}

	if err := st.DeleteNamespace(ctx, ns.ID); err != nil {
		t.Fatal(err)
	}
	names, err := st.ListAllRepoNames(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if name == "lib/nginx" {
			t.Error("repository row survived namespace deletion")
		}
	}
	if _, err := st.GetRepositoryByNamespacedName(ctx, "lib", "nginx"); err == nil {
		t.Error("repository is still queryable after namespace deletion")
	}
	if _, err := st.GetNamespace(ctx, "lib"); err == nil {
		t.Error("namespace still present after deletion")
	}
}

// TestGetRepoStatsSingleSegment covers root-namespace repositories, which used
// to make GetRepoStats return an error and report a hard 0 size.
func TestGetRepoStatsSingleSegment(t *testing.T) {
	ctx := context.Background()
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	ns, err := st.UpsertNamespace(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	repo, err := st.UpsertRepository(ctx, ns.ID, "python")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SyncImage(ctx, Image{RepositoryID: repo.ID, Tag: "3.12", Digest: "sha256:x", Size: 4096}); err != nil {
		t.Fatal(err)
	}

	count, size, err := st.GetRepoStats(ctx, "python")
	if err != nil {
		t.Fatalf("GetRepoStats(single segment) returned error: %v", err)
	}
	if count != 1 || size != 4096 {
		t.Errorf("GetRepoStats(python) = (%d, %d), want (1, 4096)", count, size)
	}
	// Multi-level names still work and match the first slash.
	if _, _, err := st.GetRepoStats(ctx, "lib/nginx"); err != nil {
		t.Errorf("GetRepoStats(multi-level) returned error: %v", err)
	}
}

// TestListFavoriteImagesCanonicalRepoName verifies favorites report
// "namespace/name" and never a leading-slash name for root-namespace repos.
func TestListFavoriteImagesCanonicalRepoName(t *testing.T) {
	ctx := context.Background()
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	rootNs, err := st.UpsertNamespace(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	rootRepo, err := st.UpsertRepository(ctx, rootNs.ID, "python")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertImage(ctx, Image{RepositoryID: rootRepo.ID, Tag: "3.12", Favorite: true}); err != nil {
		t.Fatal(err)
	}
	libNs, err := st.UpsertNamespace(ctx, "lib")
	if err != nil {
		t.Fatal(err)
	}
	libRepo, err := st.UpsertRepository(ctx, libNs.ID, "nginx")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertImage(ctx, Image{RepositoryID: libRepo.ID, Tag: "latest", Favorite: true}); err != nil {
		t.Fatal(err)
	}

	favs, err := st.ListFavoriteImages(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(favs) != 2 {
		t.Fatalf("got %d favorites, want 2", len(favs))
	}
	got := map[string]bool{}
	for _, f := range favs {
		got[f.Repo] = true
	}
	if !got["python"] || !got["lib/nginx"] {
		t.Errorf("favorite repo names = %v, want python and lib/nginx", got)
	}
}
