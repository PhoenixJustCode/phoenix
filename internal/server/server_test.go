package server

import (
	"context"
	"io/fs"
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
		{"POST", "/logout", 303},
		// a GET logout would let any site log the admin out with a link
		{"GET", "/logout", 404},
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

func TestStaticCaching(t *testing.T) {
	srv := newTestServer(t)
	tests := []struct {
		path      string
		wantCache string
	}{
		{"/", "no-cache"},
		{"/image.jpg", assetCacheControl},
		{"/style/style.css", assetCacheControl},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			srv.Handler.ServeHTTP(w, httptest.NewRequest("GET", tt.path, nil))
			etag := w.Header().Get("ETag")
			if w.Code != http.StatusOK || etag == "" || w.Header().Get("Cache-Control") != tt.wantCache {
				t.Fatalf("got %d etag=%q cache=%q", w.Code, etag, w.Header().Get("Cache-Control"))
			}

			r := httptest.NewRequest("GET", tt.path, nil)
			r.Header.Set("If-None-Match", etag)
			w = httptest.NewRecorder()
			srv.Handler.ServeHTTP(w, r)
			if w.Code != http.StatusNotModified {
				t.Errorf("revalidation status = %d, want 304", w.Code)
			}
		})
	}
}

func TestMustHashFilesPanicsOnBrokenFS(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("mustHashFiles() did not panic on an unreadable FS")
		}
	}()
	mustHashFiles(brokenFS{})
}

type brokenFS struct{}

func (brokenFS) Open(string) (fs.File, error) { return nil, fs.ErrPermission }

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
