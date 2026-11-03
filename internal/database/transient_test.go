package database

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"testing"

	"github.com/lib/pq"
)

func TestIsTransient(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "server starting", err: &pq.Error{Code: codeCannotConnectNow}, want: true},
		{name: "connection failure class", err: &pq.Error{Code: "08006"}, want: true},
		{name: "too many connections", err: &pq.Error{Code: codeTooManyConnections}, want: true},
		{name: "unknown host", err: &net.OpError{Op: "dial", Err: &net.DNSError{IsNotFound: true}}},
		{name: "dns server down", err: &net.OpError{Op: "dial", Err: &net.DNSError{IsTemporary: true}}, want: true},
		{name: "wrong password", err: &pq.Error{Code: "28P01"}},
		{name: "unknown database", err: &pq.Error{Code: "3D000"}},
		{name: "connection refused", err: &net.OpError{Op: "dial", Err: errors.New("refused")}, want: true},
		{name: "ping timeout", err: fmt.Errorf("ping: %w", context.DeadlineExceeded), want: true},
		{name: "bad conn", err: driver.ErrBadConn, want: true},
		{name: "server closed connection", err: io.EOF, want: true},
		{name: "malformed dsn", err: &url.Error{Op: "parse", URL: "postgres://%zz", Err: errors.New("invalid escape")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isTransient(tt.err); got != tt.want {
				t.Errorf("isTransient(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
