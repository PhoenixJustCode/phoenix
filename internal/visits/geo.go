// Package visits records site visits and serves the admin statistics.
package visits

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"
)

const (
	geoTimeout  = 5 * time.Second
	maxGeoBody  = 64 << 10
	unknownGeo  = "Unknown"
	localGeo    = "Local"
	geoPathTail = "/json/"
)

// Geo resolves country and city of an IP through an ipapi.co compatible service.
type Geo struct {
	client  *http.Client
	baseURL string
}

// NewGeo returns a Geo querying baseURL.
func NewGeo(baseURL string) *Geo {
	return &Geo{client: &http.Client{Timeout: geoTimeout}, baseURL: baseURL}
}

// Lookup never fails: statistics are optional, so errors degrade to "Unknown".
func (g *Geo) Lookup(ctx context.Context, ip string) (country, city string) {
	addr := net.ParseIP(ip)
	switch {
	case addr == nil:
		return unknownGeo, unknownGeo
	case addr.IsLoopback() || addr.IsPrivate() || addr.IsUnspecified():
		return localGeo, localGeo
	}

	url := g.baseURL + "/" + addr.String() + geoPathTail
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		slog.Warn("failed to build geo request", "err", err)
		return unknownGeo, unknownGeo
	}
	resp, err := g.client.Do(req)
	if err != nil {
		slog.Warn("geo lookup failed", "err", err)
		return unknownGeo, unknownGeo
	}
	// draining lets the keep-alive connection be reused instead of a new TLS handshake
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxGeoBody))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		slog.Warn("geo lookup failed", "status", resp.StatusCode)
		return unknownGeo, unknownGeo
	}
	var body struct {
		Country string `json:"country_name"`
		City    string `json:"city"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxGeoBody)).Decode(&body); err != nil {
		slog.Warn("failed to decode geo response", "err", err)
		return unknownGeo, unknownGeo
	}
	return orUnknown(body.Country), orUnknown(body.City)
}

func orUnknown(s string) string {
	if s == "" {
		return unknownGeo
	}
	return s
}
