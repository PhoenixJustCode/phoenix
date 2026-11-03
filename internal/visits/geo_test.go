package visits

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const publicIP = "203.0.113.10"

func geoStub(t testing.TB, status int, body string) *Geo {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, geoPathTail) {
			t.Errorf("unexpected geo path %q", r.URL.Path)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return NewGeo(srv.URL)
}

func TestGeoLookup(t *testing.T) {
	tests := []struct {
		name        string
		ip          string
		status      int
		body        string
		wantCountry string
		wantCity    string
	}{
		{name: "found", ip: publicIP, status: 200, body: `{"country_name":"Kazakhstan","city":"Almaty"}`, wantCountry: "Kazakhstan", wantCity: "Almaty"},
		{name: "empty fields", ip: publicIP, status: 200, body: `{}`, wantCountry: unknownGeo, wantCity: unknownGeo},
		{name: "rate limited", ip: publicIP, status: 429, wantCountry: unknownGeo, wantCity: unknownGeo},
		{name: "bad json", ip: publicIP, status: 200, body: `{`, wantCountry: unknownGeo, wantCity: unknownGeo},
		{name: "loopback skips lookup", ip: "127.0.0.1", wantCountry: localGeo, wantCity: localGeo},
		{name: "private skips lookup", ip: "10.1.2.3", wantCountry: localGeo, wantCity: localGeo},
		{name: "invalid ip", ip: "nope", wantCountry: unknownGeo, wantCity: unknownGeo},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := geoStub(t, tt.status, tt.body)
			country, city := g.Lookup(context.Background(), tt.ip)
			if country != tt.wantCountry || city != tt.wantCity {
				t.Errorf("Lookup() = (%q, %q), want (%q, %q)", country, city, tt.wantCountry, tt.wantCity)
			}
		})
	}
}

func TestGeoLookupNetworkErrors(t *testing.T) {
	for name, base := range map[string]string{
		"unreachable": "http://127.0.0.1:1",
		"bad url":     "http://bad host",
	} {
		t.Run(name, func(t *testing.T) {
			country, _ := NewGeo(base).Lookup(context.Background(), publicIP)
			if country != unknownGeo {
				t.Errorf("Lookup() country = %q, want %q", country, unknownGeo)
			}
		})
	}
}
