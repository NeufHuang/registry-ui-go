package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

// sha256HexForTest mirrors the legacy hash computation: with an empty salt,
// the stored hash is hex(sha256(password)).
func sha256HexForTest(password string) string {
	sum := sha256.Sum256([]byte(password))
	return hex.EncodeToString(sum[:])
}

func TestHashAndVerifyPassword(t *testing.T) {
	hash, err := HashPassword("s3cret")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !VerifyPasswordHash(hash, "s3cret") {
		t.Error("correct password should verify")
	}
	if VerifyPasswordHash(hash, "wrong") {
		t.Error("wrong password should not verify")
	}
	if NeedsPasswordUpgrade(hash) {
		t.Error("bcrypt hash should not need upgrade")
	}
}

func TestLegacySHA256VerifyAndUpgrade(t *testing.T) {
	// sha256$<hexsalt>$<hexhash> with empty salt for determinism.
	// hash = sha256("" + password). Build it the same way the verifier does.
	// salt bytes are empty, so expected = sha256(password).
	password := "legacypw"
	// Compute legacy hash inline using the package's own helpers indirectly:
	// salt = "" (hex ""), expected = sha256(password).
	legacy := "sha256$$" + sha256HexForTest(password)
	if !VerifyPasswordHash(legacy, password) {
		t.Fatal("legacy hash should verify")
	}
	if !NeedsPasswordUpgrade(legacy) {
		t.Error("legacy hash should need upgrade")
	}
	upgraded, err := UpgradePassword(legacy, password)
	if err != nil {
		t.Fatalf("UpgradePassword: %v", err)
	}
	if NeedsPasswordUpgrade(upgraded) {
		t.Error("upgraded hash should be bcrypt")
	}
	if !VerifyPasswordHash(upgraded, password) {
		t.Error("upgraded hash should verify original password")
	}
}

func TestProtectionCodeRoundTrip(t *testing.T) {
	for _, s := range []string{"rules", "overwrite", "immutable"} {
		code := ProtectionStringToCode(s)
		if ProtectionCodeToString(code) != s {
			t.Errorf("protection round-trip failed for %q", s)
		}
	}
	if ProtectionStringToCode("bogus") != ProtectionModeUnset {
		t.Error("unknown protection string should map to Unset")
	}
}

func TestOverwriteCodeRoundTrip(t *testing.T) {
	for _, s := range []string{"recycle", "keep"} {
		code := OverwriteStringToCode(s)
		if OverwriteCodeToString(code) != s {
			t.Errorf("overwrite round-trip failed for %q", s)
		}
	}
	if OverwriteStringToCode("bogus") != OverwriteActionUnset {
		t.Error("unknown overwrite string should map to Unset")
	}
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestSetSettingRejectsBadNumericValues(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)

	for _, bad := range []string{"-1", "-5", "abc", "99999"} {
		err := st.SetSetting(ctx, "recycleGCDays", bad)
		if err == nil {
			t.Errorf("SetSetting(recycleGCDays=%q) should be rejected", bad)
			continue
		}
		var invalid *InvalidSettingError
		if !errors.As(err, &invalid) {
			t.Errorf("SetSetting(recycleGCDays=%q) error should be *InvalidSettingError, got %T", bad, err)
		}
	}
	if err := st.SetSetting(ctx, "recycleGCDays", "30"); err != nil {
		t.Errorf("valid recycleGCDays rejected: %v", err)
	}
	if err := st.SetSetting(ctx, "recycleGCDays", "0"); err != nil {
		t.Errorf("recycleGCDays=0 (disable) should be valid: %v", err)
	}
	// Non-numeric settings are unaffected.
	if err := st.SetSetting(ctx, "theme", "dark"); err != nil {
		t.Errorf("non-numeric setting rejected: %v", err)
	}
	// Clearing a numeric setting is still allowed.
	if err := st.SetSetting(ctx, "recycleGCDays", ""); err != nil {
		t.Errorf("clearing recycleGCDays should be allowed: %v", err)
	}
}

func TestListPendingGCRejectsNonPositiveDays(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	for _, days := range []int{0, -1, -30} {
		if _, err := st.ListPendingGC(ctx, days); err == nil {
			t.Errorf("ListPendingGC(%d) should return an error", days)
		}
	}
}

func TestMarkRecycleGCFailureParksItem(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	if err := st.AddRecycleItem(ctx, RecycleItem{Repo: "foo/bar", Reference: "v1", Digest: "sha256:dead", ManifestBody: []byte("{}")}); err != nil {
		t.Fatalf("AddRecycleItem: %v", err)
	}
	items, err := st.ListAllPendingGC(ctx)
	if err != nil || len(items) != 1 {
		t.Fatalf("ListAllPendingGC: items=%d err=%v", len(items), err)
	}
	id := items[0].ID
	for i := 1; i < 5; i++ {
		failed, err := st.MarkRecycleGCFailure(ctx, id, "boom", 5)
		if err != nil {
			t.Fatalf("MarkRecycleGCFailure: %v", err)
		}
		if failed {
			t.Fatalf("item parked after only %d attempts", i)
		}
	}
	failed, err := st.MarkRecycleGCFailure(ctx, id, "boom", 5)
	if err != nil {
		t.Fatalf("MarkRecycleGCFailure: %v", err)
	}
	if !failed {
		t.Fatal("item should be parked as gc_failed after 5 attempts")
	}
	item, err := st.GetRecycleItem(ctx, id)
	if err != nil {
		t.Fatalf("GetRecycleItem: %v", err)
	}
	if item.Status != "gc_failed" {
		t.Errorf("status=%q want gc_failed", item.Status)
	}
	if item.Attempts != 5 {
		t.Errorf("attempts=%d want 5", item.Attempts)
	}
	// Parked items are no longer picked up by the pending GC query.
	pending, err := st.ListAllPendingGC(ctx)
	if err != nil {
		t.Fatalf("ListAllPendingGC: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("gc_failed item should not be listed as pending, got %d", len(pending))
	}
	pendingCount, _, err := st.GetPendingGCStats(ctx)
	if err != nil {
		t.Fatalf("GetPendingGCStats: %v", err)
	}
	if pendingCount != 0 {
		t.Errorf("pending GC stat should be 0 after parking, got %d", pendingCount)
	}
}
