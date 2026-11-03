//go:build load

// Package loadtest checks latency and error rate under load; LOAD_URL targets a deployed site.
package loadtest

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"phoenix/internal/auth"
	"phoenix/internal/database"
	"phoenix/internal/health"
	"phoenix/internal/server"
	"phoenix/internal/testdb"
	"phoenix/internal/visits"
	"phoenix/web"
)

const (
	defaultDuration    = 10 * time.Second
	defaultConcurrency = 20
	maxErrorRate       = 0.01
	maxP95             = 300 * time.Millisecond
	requestTimeout     = 5 * time.Second
	percentile95       = 0.95
)

var paths = []string{"/", "/healthz", "/readyz", "/style/style.css", "/track"}

// status 0 means a transport error
type result struct {
	latency time.Duration
	status  int
	path    string
	err     error
}

func (r result) failed() bool {
	return r.status == 0 || r.status >= http.StatusInternalServerError
}

func TestLoad(t *testing.T) {
	base := os.Getenv("LOAD_URL")
	if base == "" {
		base = startLocal(t)
	}
	duration := envDuration(t, "LOAD_DURATION", defaultDuration)
	workers := envInt(t, "LOAD_CONCURRENCY", defaultConcurrency)

	results := hammer(base, duration, workers)
	if len(results) == 0 {
		t.Fatal("no requests were made")
	}
	latencies := make([]time.Duration, 0, len(results))
	failures := map[string]int{}
	failed := 0
	var firstErr error
	for _, r := range results {
		latencies = append(latencies, r.latency)
		if r.failed() {
			failed++
			failures[r.path+" "+strconv.Itoa(r.status)]++
		}
		if firstErr == nil && r.err != nil {
			firstErr = r.err
		}
	}
	if firstErr != nil {
		t.Logf("first transport error: %v", firstErr)
	}
	slices.Sort(latencies)
	p95 := latencies[int(float64(len(latencies))*percentile95)]
	errRate := float64(failed) / float64(len(results))
	rps := float64(len(results)) / duration.Seconds()
	t.Logf("requests=%d rps=%.0f p50=%s p95=%s errors=%.2f%% %v",
		len(results), rps, latencies[len(latencies)/2], p95, errRate*100, failures)

	if errRate > maxErrorRate {
		t.Errorf("error rate %.2f%% exceeds %.2f%%", errRate*100, maxErrorRate*100)
	}
	if p95 > maxP95 {
		t.Errorf("p95 latency %s exceeds %s", p95, maxP95)
	}
}

func hammer(base string, duration time.Duration, workers int) []result {
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	// keep-alive pool per worker, otherwise the generator runs out of ephemeral ports first
	client := &http.Client{
		Timeout:   requestTimeout,
		Transport: &http.Transport{MaxIdleConnsPerHost: workers, MaxIdleConns: workers},
	}

	var mu sync.Mutex
	var all []result
	var wg sync.WaitGroup
	for w := range workers {
		wg.Go(func() {
			var local []result
			for i := w; ctx.Err() == nil; i++ {
				local = append(local, hit(ctx, client, base, paths[i%len(paths)]))
			}
			mu.Lock()
			all = append(all, local...)
			mu.Unlock()
		})
	}
	wg.Wait()
	return all
}

func hit(ctx context.Context, client *http.Client, base, path string) result {
	start := time.Now()
	req, err := http.NewRequestWithContext(context.WithoutCancel(ctx), http.MethodGet, base+path, nil)
	if err != nil {
		return result{latency: time.Since(start), path: path, err: err}
	}
	resp, err := client.Do(req)
	if err != nil {
		return result{latency: time.Since(start), path: path, err: err}
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return result{latency: time.Since(start), status: resp.StatusCode, path: path}
}

func startLocal(t *testing.T) string {
	t.Helper()
	// database.Open, not the raw test db: the load must hit the production pool settings
	_, dsn := testdb.New(t)
	db, err := database.Open(context.Background(), dsn, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	geo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"country_name":"Kazakhstan","city":"Almaty"}`))
	}))
	t.Cleanup(geo.Close)

	authHandler := auth.NewHandler(auth.NewStore(db))
	rec := visits.NewRecorder(db, visits.NewGeo(geo.URL))
	srv := server.New(server.Handlers{
		Auth:   authHandler,
		Visits: visits.NewHandler(rec, authHandler, web.Pages),
		Health: health.NewHandler(db, "load"),
	})
	ts := httptest.NewServer(srv.Handler)
	t.Cleanup(func() {
		ts.Close()
		rec.Wait()
	})
	return ts.URL
}

func envDuration(t *testing.T, key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		t.Fatalf("%s: %v", key, err)
	}
	return d
}

func envInt(t *testing.T, key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		t.Fatalf("%s: %v", key, err)
	}
	return n
}
