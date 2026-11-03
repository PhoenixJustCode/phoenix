package clientip

import (
	"net/http/httptest"
	"testing"
)

func TestFromRequest(t *testing.T) {
	tests := []struct {
		name       string
		realIP     string
		remoteAddr string
		want       string
	}{
		{name: "nginx on loopback", realIP: "203.0.113.7", remoteAddr: "127.0.0.1:5000", want: "203.0.113.7"},
		{name: "nginx on ipv6 loopback", realIP: "2001:db8::1", remoteAddr: "[::1]:1", want: "2001:db8::1"},
		{name: "spoofed header from outside", realIP: "1.2.3.4", remoteAddr: "198.51.100.9:443", want: "198.51.100.9"},
		{name: "garbage header falls back", realIP: "not-an-ip", remoteAddr: "127.0.0.1:443", want: "127.0.0.1"},
		{name: "remote addr without port", remoteAddr: "198.51.100.2", want: "198.51.100.2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tt.remoteAddr
			if tt.realIP != "" {
				r.Header.Set("X-Real-IP", tt.realIP)
			}
			if got := FromRequest(r); got != tt.want {
				t.Errorf("FromRequest() = %q, want %q", got, tt.want)
			}
		})
	}
}
