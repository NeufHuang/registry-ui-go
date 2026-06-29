package store

import (
	"crypto/sha256"
	"encoding/hex"
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
