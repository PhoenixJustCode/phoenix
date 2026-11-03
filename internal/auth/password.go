// Package auth handles admin login and sessions.
package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// unsalted sha256 hex written by the first version of the site
const legacyHashLen = 64

// HashPassword returns a bcrypt hash of pw.
func HashPassword(pw string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(hash), nil
}

// verifyPassword reports whether pw matches hash and whether hash is a legacy one to upgrade.
func verifyPassword(hash, pw string) (ok, legacy bool) {
	if len(hash) == legacyHashLen && !strings.HasPrefix(hash, "$2") {
		sum := sha256.Sum256([]byte(pw))
		ok = subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(hash)) == 1
		return ok, true
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil, false
}
