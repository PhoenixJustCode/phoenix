package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"phoenix/internal/testdb"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().String()
}

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestRunServesAndStopsOnCancel(t *testing.T) {
	_, dsn := testdb.New(t)
	addr := freeAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, nil, envOf(map[string]string{"DATABASE_URL": dsn, "LISTEN_ADDR": addr}), nil)
	}()

	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, err := http.Get("http://" + addr + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run() error = %v, want graceful stop", err)
	}
}

func TestRunErrors(t *testing.T) {
	_, dsn := testdb.New(t)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = busy.Close() }()

	tests := []struct {
		name string
		env  map[string]string
	}{
		{name: "no config", env: map[string]string{}},
		{name: "db unreachable", env: map[string]string{"DATABASE_URL": "postgres://%zz"}},
		{name: "port busy", env: map[string]string{"DATABASE_URL": dsn, "LISTEN_ADDR": busy.Addr().String()}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := run(context.Background(), nil, envOf(tt.env), nil); err == nil {
				t.Fatal("run() error = nil")
			}
		})
	}
}

func TestRunMigrateError(t *testing.T) {
	db, dsn := testdb.New(t)
	if _, err := db.Exec("CREATE TABLE visits (id int)"); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), nil, envOf(map[string]string{"DATABASE_URL": dsn}), nil); err == nil {
		t.Fatal("run() error = nil with an incompatible schema")
	}
}

func TestCreateAdmin(t *testing.T) {
	_, dsn := testdb.New(t)
	env := envOf(map[string]string{"DATABASE_URL": dsn})

	tests := []struct {
		name    string
		args    []string
		stdin   io.Reader
		wantErr bool
	}{
		{name: "ok", args: []string{"create-admin", "admin"}, stdin: strings.NewReader("long-enough-secret\n")},
		{name: "no trailing newline", args: []string{"create-admin", "admin"}, stdin: strings.NewReader("long-enough-secret")},
		{name: "missing username", args: []string{"create-admin"}, stdin: strings.NewReader("x\n"), wantErr: true},
		{name: "short password", args: []string{"create-admin", "admin"}, stdin: strings.NewReader("short\n"), wantErr: true},
		{name: "password too long", args: []string{"create-admin", "admin"}, stdin: strings.NewReader(strings.Repeat("a", 100)), wantErr: true},
		{name: "broken stdin", args: []string{"create-admin", "admin"}, stdin: errReader{}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := run(context.Background(), tt.args, env, tt.stdin)
			if (err != nil) != tt.wantErr {
				t.Errorf("run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
