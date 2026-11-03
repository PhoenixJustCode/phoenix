// Package database opens the postgres connection and applies the schema.
package database

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"time"

	"github.com/lib/pq"
)

const (
	initialBackoff = 500 * time.Millisecond
	maxBackoff     = 15 * time.Second
	pingTimeout    = 3 * time.Second
	maxOpenConns   = 10
	// equal to maxOpenConns: closing idle connections under load causes reconnect churn
	maxIdleConns    = maxOpenConns
	connMaxLifetime = 30 * time.Minute
)

// postgres error codes worth waiting for: starting up, connections full, connection failures
const (
	codeCannotConnectNow   = "57P03"
	codeTooManyConnections = "53300"
	classConnection        = "08"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Open connects with exponential backoff: after a reboot postgres may start later than the app.
func Open(ctx context.Context, dsn string, budget time.Duration) (*sql.DB, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)
	db.SetConnMaxLifetime(connMaxLifetime)

	if err := waitReady(ctx, db, budget); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func waitReady(ctx context.Context, db *sql.DB, budget time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	delay := initialBackoff
	for attempt := 1; ; attempt++ {
		err := ping(ctx, db)
		if err == nil {
			return nil
		}
		if !isTransient(err) {
			return fmt.Errorf("connect to database: %w", err)
		}
		slog.Warn("database not ready, retrying", "attempt", attempt, "delay", delay, "err", err)
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for database: %w (last error: %w)", ctx.Err(), err)
		case <-time.After(delay):
		}
		delay = min(delay*2, maxBackoff)
	}
}

func ping(ctx context.Context, db *sql.DB) error {
	ctx, cancel := context.WithTimeout(ctx, pingTimeout)
	defer cancel()
	return db.PingContext(ctx)
}

// isTransient separates outages (retry) from misconfiguration like a wrong password (fail fast).
func isTransient(err error) bool {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return pqErr.Code == codeCannotConnectNow ||
			pqErr.Code == codeTooManyConnections ||
			pqErr.Code.Class() == classConnection
	}
	// a host missing from DNS is a typo in config, not an outage
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return false
	}
	// *net.OpError, not net.Error: url parse errors implement net.Error too
	var opErr *net.OpError
	return errors.As(err, &opErr) ||
		errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, driver.ErrBadConn) ||
		errors.Is(err, io.EOF)
}

// Migrate runs every file on each start, so files must be idempotent and additive (rollback-safe).
func Migrate(ctx context.Context, db *sql.DB) error {
	files, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return fmt.Errorf("list migrations: %w", err)
	}
	for _, name := range files {
		query, err := migrations.ReadFile(name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}
		if _, err := db.ExecContext(ctx, string(query)); err != nil {
			return fmt.Errorf("apply migration %s: %w", name, err)
		}
	}
	return nil
}
