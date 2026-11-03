package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	sessionTTL = 24 * time.Hour
	tokenBytes = 32
)

const validSessionQuery = `
	SELECT s.expires_at FROM sessions s
	JOIN admins a ON a.username = s.username
	WHERE s.token = $1`

// compared against for unknown users, so response time doesn't reveal which usernames exist
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("dummy password"), bcrypt.DefaultCost)

// Store keeps admins and sessions in postgres.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// NewStore returns a Store backed by db.
func NewStore(db *sql.DB) *Store {
	return &Store{db: db, now: utcNow}
}

// expires_at is TIMESTAMP without zone, so all values are kept in UTC
func utcNow() time.Time { return time.Now().UTC() }

// UpsertAdmin creates the admin or replaces its password, logging out its sessions.
func (s *Store) UpsertAdmin(ctx context.Context, username, pw string) error {
	hash, err := HashPassword(pw)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin upsert admin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.ExecContext(ctx, `
		INSERT INTO admins (username, password_hash) VALUES ($1, $2)
		ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash`,
		username, hash)
	if err != nil {
		return fmt.Errorf("upsert admin: %w", err)
	}
	_, err = tx.ExecContext(ctx, "DELETE FROM sessions WHERE username = $1", username)
	if err != nil {
		return fmt.Errorf("delete admin sessions: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit upsert admin: %w", err)
	}
	return nil
}

// Authenticate checks credentials and upgrades a legacy hash after a successful login.
func (s *Store) Authenticate(ctx context.Context, username, pw string) (bool, error) {
	var hash string
	err := s.db.QueryRowContext(ctx,
		"SELECT password_hash FROM admins WHERE username = $1", username).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(pw))
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("load admin: %w", err)
	}

	ok, legacy := verifyPassword(hash, pw)
	if ok && legacy {
		s.upgradeHash(ctx, username, hash, pw)
	}
	return ok, nil
}

// upgradeHash is best effort: login must not fail because of it, the next login retries.
func (s *Store) upgradeHash(ctx context.Context, username, oldHash, pw string) {
	newHash, err := HashPassword(pw)
	if err != nil {
		slog.Error("failed to hash password for upgrade", "err", err)
		return
	}
	// the old hash in WHERE keeps a password changed meanwhile by create-admin
	_, err = s.db.ExecContext(ctx,
		"UPDATE admins SET password_hash = $1 WHERE username = $2 AND password_hash = $3",
		newHash, username, oldHash)
	if err != nil {
		slog.Error("failed to upgrade legacy password hash", "err", err)
	}
}

// CreateSession issues a random token; only its sha256 is stored, a db leak gives no sessions.
func (s *Store) CreateSession(ctx context.Context, username string) (string, time.Time, error) {
	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, fmt.Errorf("generate session token: %w", err)
	}
	token := hex.EncodeToString(raw)
	expires := s.now().Add(sessionTTL)

	_, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE expires_at < $1", s.now())
	if err != nil {
		return "", time.Time{}, fmt.Errorf("delete expired sessions: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		"INSERT INTO sessions (token, username, expires_at) VALUES ($1, $2, $3)",
		hashToken(token), username, expires)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("insert session: %w", err)
	}
	return token, expires, nil
}

// ValidSession reports whether token belongs to a not expired session of an existing admin.
func (s *Store) ValidSession(ctx context.Context, token string) (bool, error) {
	var expires time.Time
	err := s.db.QueryRowContext(ctx, validSessionQuery, hashToken(token)).Scan(&expires)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("load session: %w", err)
	}
	return expires.After(s.now()), nil
}

// DeleteSession removes the session if it exists.
func (s *Store) DeleteSession(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE token = $1", hashToken(token))
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
