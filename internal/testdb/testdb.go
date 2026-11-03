// Package testdb gives each test its own temporary postgres database.
package testdb

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/url"
	"os"
	"testing"

	"github.com/lib/pq"
)

// EnvURL points to a postgres server where tests may create and drop databases.
const EnvURL = "TEST_DATABASE_URL"

const nameRandomBytes = 6

// New creates an empty database dropped after the test and returns it with its DSN.
func New(t testing.TB) (*sql.DB, string) {
	t.Helper()
	base := os.Getenv(EnvURL)
	if base == "" {
		t.Skipf("%s is not set", EnvURL)
	}

	admin, err := sql.Open("postgres", base)
	if err != nil {
		t.Fatalf("open admin connection: %v", err)
	}
	name := "test_" + randomSuffix(t)
	ctx := context.Background()
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE "+pq.QuoteIdentifier(name)); err != nil {
		t.Fatalf("create database: %v", err)
	}

	dsn := withDatabase(t, base, name)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		_, _ = admin.ExecContext(ctx, "DROP DATABASE IF EXISTS "+pq.QuoteIdentifier(name)+" WITH (FORCE)")
		_ = admin.Close()
	})
	return db, dsn
}

func randomSuffix(t testing.TB) string {
	b := make([]byte, nameRandomBytes)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("random suffix: %v", err)
	}
	return hex.EncodeToString(b)
}

func withDatabase(t testing.TB, base, name string) string {
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse %s: %v", EnvURL, err)
	}
	u.Path = "/" + name
	return u.String()
}
