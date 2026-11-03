// Package clientip resolves the visitor address behind the nginx proxy.
package clientip

import (
	"net"
	"net/http"
)

// FromRequest trusts X-Real-IP only from loopback, where nginx is the sole possible sender.
func FromRequest(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if peer := net.ParseIP(host); peer == nil || !peer.IsLoopback() {
		return host
	}
	if ip := net.ParseIP(r.Header.Get("X-Real-IP")); ip != nil {
		return ip.String()
	}
	return host
}
