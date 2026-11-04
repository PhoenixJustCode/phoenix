package database_test

import (
	"context"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"phoenix/internal/database"
	"phoenix/internal/testdb"
)

const shortBudget = 1200 * time.Millisecond

func TestOpen(t *testing.T) {
	_, dsn := testdb.New(t)

	db, err := database.Open(context.Background(), dsn, time.Minute)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	_ = db.Close()
}

func TestOpenRetriesUnreachableServerUntilBudget(t *testing.T) {
	start := time.Now()
	_, err := database.Open(context.Background(), "postgres://u:p@127.0.0.1:1/db?sslmode=disable", shortBudget)
	if err == nil {
		t.Fatal("Open() error = nil, want timeout")
	}
	if elapsed := time.Since(start); elapsed < shortBudget {
		t.Errorf("Open() gave up after %s, want retries for %s", elapsed, shortBudget)
	}
}

func TestOpenFailsFastOnWrongPassword(t *testing.T) {
	_, dsn := testdb.New(t)
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword(u.User.Username(), "wrong-password")

	start := time.Now()
	if _, err := database.Open(context.Background(), u.String(), time.Minute); err == nil {
		t.Fatal("Open() error = nil, want auth error")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("Open() took %s on a permanent error, want fail fast", elapsed)
	}
}

func TestOpenRejectsInvalidDSNWithoutRetries(t *testing.T) {
	start := time.Now()
	if _, err := database.Open(context.Background(), "postgres://%zz", time.Minute); err == nil {
		t.Fatal("Open() error = nil, want dsn error")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Open() retried a malformed dsn for %s", elapsed)
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	db, _ := testdb.New(t)
	ctx := context.Background()

	for i := range 2 {
		if err := database.Migrate(ctx, db); err != nil {
			t.Fatalf("Migrate() run %d error = %v", i+1, err)
		}
	}
	for _, table := range []string{"visits", "admins", "sessions"} {
		var exists bool
		err := db.QueryRow("SELECT to_regclass($1) IS NOT NULL", table).Scan(&exists)
		if err != nil || !exists {
			t.Errorf("table %s missing after Migrate(): %v", table, err)
		}
	}
}

func TestMigrateConcurrentStarts(t *testing.T) {
	db, _ := testdb.New(t)
	const instances = 4
	errs := make(chan error, instances)
	for range instances {
		go func() { errs <- database.Migrate(context.Background(), db) }()
	}
	for range instances {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent Migrate() error = %v", err)
		}
	}
}

func TestMigrateReportsDatabaseError(t *testing.T) {
	db, _ := testdb.New(t)
	_ = db.Close()
	if err := database.Migrate(context.Background(), db); err == nil {
		t.Fatal("Migrate() error = nil on closed db")
	}
}

// destructive changes must be applied by hand, never by an automatic deploy
var destructive = regexp.MustCompile(`(?i)\b(DROP|TRUNCATE|RENAME|DELETE\s+FROM)\b|ALTER\s+COLUMN\s+\S+\s+TYPE`)

func TestMigrationsAreAdditive(t *testing.T) {
	err := fs.WalkDir(os.DirFS("migrations"), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		body, err := os.ReadFile(filepath.Join("migrations", path))
		if err != nil {
			return err
		}
		if m := destructive.Find(body); m != nil {
			t.Errorf("%s contains destructive statement %q", path, m)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
