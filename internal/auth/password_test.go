package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func legacyHash(pw string) string {
	sum := sha256.Sum256([]byte(pw))
	return hex.EncodeToString(sum[:])
}

func TestVerifyPassword(t *testing.T) {
	bcryptHash, err := HashPassword("secret")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		hash       string
		pw         string
		wantOK     bool
		wantLegacy bool
	}{
		{name: "bcrypt match", hash: bcryptHash, pw: "secret", wantOK: true},
		{name: "bcrypt mismatch", hash: bcryptHash, pw: "nope"},
		{name: "legacy match", hash: legacyHash("secret"), pw: "secret", wantOK: true, wantLegacy: true},
		{name: "legacy mismatch", hash: legacyHash("secret"), pw: "nope", wantLegacy: true},
		{name: "garbage hash", hash: "xyz", pw: "secret"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, legacy := verifyPassword(tt.hash, tt.pw)
			if ok != tt.wantOK || legacy != tt.wantLegacy {
				t.Errorf("verifyPassword() = (%v, %v), want (%v, %v)", ok, legacy, tt.wantOK, tt.wantLegacy)
			}
		})
	}
}

func TestHashPasswordTooLong(t *testing.T) {
	if _, err := HashPassword(strings.Repeat("a", 100)); err == nil {
		t.Fatal("HashPassword() error = nil for a password over 72 bytes")
	}
}

func BenchmarkVerifyPassword(b *testing.B) {
	hash, err := HashPassword("secret")
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		verifyPassword(hash, "secret")
	}
}
