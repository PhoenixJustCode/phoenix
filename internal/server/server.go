// Package server wires HTTP routes and runs the server with graceful shutdown.
package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"phoenix/internal/auth"
	"phoenix/internal/health"
	"phoenix/internal/visits"
	"phoenix/web"
)

const (
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 10 * time.Second
	writeTimeout      = 30 * time.Second
	idleTimeout       = 60 * time.Second
)

// Handlers groups the endpoint handlers the server routes to.
type Handlers struct {
	Auth   *auth.Handler
	Visits *visits.Handler
	Health *health.Handler
}

// New builds the HTTP server with all routes.
func New(h Handlers) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.Health.Healthz)
	mux.HandleFunc("GET /readyz", h.Health.Readyz)
	mux.HandleFunc("/track", h.Visits.Track)
	mux.HandleFunc("POST /login", h.Auth.Login)
	mux.HandleFunc("/logout", h.Auth.Logout)
	mux.HandleFunc("GET /api/visits", h.Visits.API)
	// "GET /" would conflict with method-less routes like /logout, so static checks the method itself
	mux.Handle("/", static())

	return &http.Server{
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}
}

// static serves only embedded public files and hides directory listings.
func static() http.Handler {
	files := http.FileServerFS(web.Public)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path != "/" && strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		files.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

// Run serves on ln until ctx is cancelled, then lets in-flight requests finish.
func Run(
	ctx context.Context, srv *http.Server, ln net.Listener, shutdownTimeout time.Duration,
) error {
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()

	select {
	case err := <-errCh:
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	if err := <-errCh; !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}
