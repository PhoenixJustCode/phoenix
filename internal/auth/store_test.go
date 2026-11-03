package auth

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"phoenix/internal/database"
	"phoenix/internal/testdb"
)

func newTestStore(t *testing.T) (*Store, *sql.DB) {
	t.Helper()
	db, _ := testdb.New(t)
	if err := database.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	return NewStore(db), db
}

func newStoreWithAdmin(t *testing.T) (*Store, *sql.DB) {
	t.Helper()
	s, db := newTestStore(t)
	if err := s.UpsertAdmin(context.Background(), "admin", "secret"); err != nil {
		t.Fatal(err)
	}
	return s, db
}

func TestAuthenticate(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertAdmin(ctx, "admin", "secret"); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name, user, pw string
		want           bool
	}{
		{name: "valid", user: "admin", pw: "secret", want: true},
		{name: "wrong password", user: "admin", pw: "nope"},
		{name: "unknown user", user: "ghost", pw: "secret"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := s.Authenticate(ctx, tt.user, tt.pw)
			if err != nil || got != tt.want {
				t.Errorf("Authenticate() = (%v, %v), want (%v, nil)", got, err, tt.want)
			}
		})
	}
}

func TestAuthenticateUpgradesLegacyHash(t *testing.T) {
	s, db := newTestStore(t)
	ctx := context.Background()
	if _, err := db.Exec("INSERT INTO admins (username, password_hash) VALUES ('old', $1)", legacyHash("pw")); err != nil {
		t.Fatal(err)
	}

	ok, err := s.Authenticate(ctx, "old", "pw")
	if err != nil || !ok {
		t.Fatalf("Authenticate() = (%v, %v), want (true, nil)", ok, err)
	}
	var hash string
	if err := db.QueryRow("SELECT password_hash FROM admins WHERE username = 'old'").Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$2") {
		t.Errorf("hash not upgraded to bcrypt: %q", hash[:4])
	}
}

func TestAuthenticateDatabaseError(t *testing.T) {
	s, db := newTestStore(t)
	_ = db.Close()
	if _, err := s.Authenticate(context.Background(), "admin", "pw"); err == nil {
		t.Fatal("Authenticate() error = nil on closed db")
	}
}

func TestUpgradeKeepsPasswordChangedMeanwhile(t *testing.T) {
	s, db := newTestStore(t)
	ctx := context.Background()
	if _, err := db.Exec("INSERT INTO admins (username, password_hash) VALUES ('old', $1)", legacyHash("pw")); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertAdmin(ctx, "old", "new-password"); err != nil {
		t.Fatal(err)
	}

	s.upgradeHash(ctx, "old", legacyHash("pw"), "pw")
	if ok, _ := s.Authenticate(ctx, "old", "new-password"); !ok {
		t.Error("stale upgrade overwrote a newer password")
	}
}

func TestUpsertAdminLogsOutSessions(t *testing.T) {
	s, _ := newStoreWithAdmin(t)
	ctx := context.Background()
	token, _, err := s.CreateSession(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertAdmin(ctx, "admin", "rotated"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.ValidSession(ctx, token); ok {
		t.Error("session survived a password change")
	}
}

func TestSessionOfDeletedAdminIsInvalid(t *testing.T) {
	s, db := newStoreWithAdmin(t)
	ctx := context.Background()
	token, _, err := s.CreateSession(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("DELETE FROM admins"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.ValidSession(ctx, token); ok {
		t.Error("session of a deleted admin is still valid")
	}
}

func TestSessionLifecycle(t *testing.T) {
	s, db := newStoreWithAdmin(t)
	ctx := context.Background()

	token, expires, err := s.CreateSession(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != tokenBytes*2 || time.Until(expires) < sessionTTL-time.Minute {
		t.Fatalf("CreateSession() = (%d chars, %v)", len(token), expires)
	}

	var stored string
	if err := db.QueryRow("SELECT token FROM sessions").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == token {
		t.Error("raw token stored in db, want only its hash")
	}

	if ok, err := s.ValidSession(ctx, token); err != nil || !ok {
		t.Errorf("ValidSession() = (%v, %v), want (true, nil)", ok, err)
	}
	if ok, _ := s.ValidSession(ctx, "forged"); ok {
		t.Error("ValidSession() accepted unknown token")
	}

	if err := s.DeleteSession(ctx, token); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.ValidSession(ctx, token); ok {
		t.Error("session still valid after DeleteSession()")
	}
}

func TestExpiredSessionsAreRejectedAndCleaned(t *testing.T) {
	s, db := newStoreWithAdmin(t)
	ctx := context.Background()

	past := utcNow().Add(-2 * sessionTTL)
	s.now = func() time.Time { return past }
	oldToken, _, err := s.CreateSession(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	s.now = utcNow

	if ok, _ := s.ValidSession(ctx, oldToken); ok {
		t.Error("expired session accepted")
	}
	if _, _, err := s.CreateSession(ctx, "admin"); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow("SELECT count(*) FROM sessions").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("sessions = %d, want expired one cleaned up", count)
	}
}

func TestStoreDatabaseErrors(t *testing.T) {
	s, db := newTestStore(t)
	_ = db.Close()
	ctx := context.Background()

	if _, _, err := s.CreateSession(ctx, "admin"); err == nil {
		t.Error("CreateSession() error = nil on closed db")
	}
	if _, err := s.ValidSession(ctx, "t"); err == nil {
		t.Error("ValidSession() error = nil on closed db")
	}
	if err := s.DeleteSession(ctx, "t"); err == nil {
		t.Error("DeleteSession() error = nil on closed db")
	}
	if err := s.UpsertAdmin(ctx, "a", "b"); err == nil {
		t.Error("UpsertAdmin() error = nil on closed db")
	}
}
