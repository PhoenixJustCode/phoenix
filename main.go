package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"phoenix/internal/auth"
	"phoenix/internal/config"
	"phoenix/internal/database"
	"phoenix/internal/health"
	"phoenix/internal/server"
	"phoenix/internal/visits"
	"phoenix/web"
)

// version is the git commit, set at build time with -ldflags "-X main.version=..."
var version = "dev"

const (
	dbConnectBudget = 2 * time.Minute
	// plus up to visits recordTimeout (10s) must fit into TimeoutStopSec=20 of the unit
	shutdownTimeout   = 5 * time.Second
	minPasswordLength = 12
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	// a second signal during a stuck shutdown must kill the process
	context.AfterFunc(ctx, stop)

	if err := run(ctx, os.Args[1:], os.Getenv, os.Stdin); err != nil {
		slog.Error("phoenix stopped", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, getenv func(string) string, stdin io.Reader) error {
	cfg, err := config.Load(getenv)
	if err != nil {
		return err
	}
	// temporary: fails only under systemd, to check that a broken release is rolled back
	if getenv("INVOCATION_ID") != "" {
		return errors.New("rollback check: refusing to start under systemd")
	}
	db, err := database.Open(ctx, cfg.DatabaseURL, dbConnectBudget)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	if err := database.Migrate(ctx, db); err != nil {
		return err
	}

	store := auth.NewStore(db)
	if len(args) > 0 && args[0] == "create-admin" {
		return createAdmin(ctx, store, args[1:], stdin)
	}

	authHandler := auth.NewHandler(store)
	rec := visits.NewRecorder(db, visits.NewGeo(cfg.GeoBaseURL))
	srv := server.New(server.Handlers{
		Auth:   authHandler,
		Visits: visits.NewHandler(rec, authHandler, web.Pages),
		Health: health.NewHandler(db, version),
	})

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	slog.Info("phoenix started", "addr", ln.Addr().String(), "version", version)
	// on error handlers may still be running, so waiting for recordings could race with new ones
	if err := server.Run(ctx, srv, ln, shutdownTimeout); err != nil {
		return err
	}
	rec.Wait()
	slog.Info("phoenix stopped gracefully")
	return nil
}

// createAdmin reads the password from stdin, so it never shows up in ps or shell history.
func createAdmin(ctx context.Context, store *auth.Store, args []string, stdin io.Reader) error {
	if len(args) != 1 {
		return errors.New("usage: phoenix create-admin <username>, password on stdin")
	}
	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read password: %w", err)
	}
	pw := strings.TrimSpace(line)
	if len(pw) < minPasswordLength {
		return fmt.Errorf("password must be at least %d characters", minPasswordLength)
	}
	if err := store.UpsertAdmin(ctx, args[0], pw); err != nil {
		return err
	}
	slog.Info("admin saved", "username", args[0])
	return nil
}
