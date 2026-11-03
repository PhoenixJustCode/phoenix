package server

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"phoenix/internal/auth"
	"phoenix/internal/database"
	"phoenix/internal/health"
	"phoenix/internal/testdb"
	"phoenix/internal/visits"
	"phoenix/web"
)

func newTestServer(t *testing.T) *http.Server {
	t.Helper()
	db, _ := testdb.New(t)
	if err := database.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	authHandler := auth.NewHandler(auth.NewStore(db))
	rec := visits.NewRecorder(db, visits.NewGeo("http://127.0.0.1:1"))
	t.Cleanup(rec.Wait)
	return New(Handlers{
		Auth:   authHandler,
		Visits: visits.NewHandler(rec, authHandler, web.Pages),
		Health: health.NewHandler(db, "test"),
	})
}

func TestRoutes(t *testing.T) {
	srv := newTestServer(t)
	tests := []struct {
		method, path string
		want         int
	}{
		{"GET", "/", 200},
		{"GET", "/style/style.css", 200},
		{"GET", "/robots.txt", 200},
		{"GET", "/healthz", 200},
		{"GET", "/readyz", 200},
		{"GET", "/track", 200},
		{"POST", "/track", 204},
		{"GET", "/api/visits", 401},
		{"GET", "/login", 404},
		{"GET", "/logout", 303},
		// nothing outside web.Public may leak
		{"GET", "/.env", 404},
		{"GET", "/.git/config", 404},
		{"GET", "/main.go", 404},
		{"GET", "/admin.html", 404},
		{"GET", "/login.html", 404},
		{"GET", "/js/", 404},
		{"POST", "/", 405},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			srv.Handler.ServeHTTP(w, httptest.NewRequest(tt.method, tt.path, nil))
			if w.Code != tt.want {
				t.Errorf("status = %d, want %d", w.Code, tt.want)
			}
			if w.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Error("security headers missing")
			}
		})
	}
}

func TestRunGracefulShutdown(t *testing.T) {
	srv := newTestServer(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, srv, ln, 5*time.Second) }()

	resp, err := http.Get("http://" + ln.Addr().String() + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() error = %v, want clean shutdown", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run() did not stop after cancel")
	}
}

func TestRunServeError(t *testing.T) {
	srv := newTestServer(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close()
	if err := Run(context.Background(), srv, ln, time.Second); err == nil {
		t.Fatal("Run() error = nil on closed listener")
	}
}
