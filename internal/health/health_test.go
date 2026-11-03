package health

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakePinger struct{ err error }

func (f fakePinger) PingContext(context.Context) error { return f.err }

func TestProbes(t *testing.T) {
	tests := []struct {
		name       string
		probe      func(*Handler) http.HandlerFunc
		pingErr    error
		wantCode   int
		wantStatus string
	}{
		{name: "healthz ignores db", probe: func(h *Handler) http.HandlerFunc { return h.Healthz }, pingErr: errors.New("down"), wantCode: 200, wantStatus: "ok"},
		{name: "readyz ok", probe: func(h *Handler) http.HandlerFunc { return h.Readyz }, wantCode: 200, wantStatus: "ready"},
		{name: "readyz db down", probe: func(h *Handler) http.HandlerFunc { return h.Readyz }, pingErr: errors.New("down"), wantCode: 503, wantStatus: "database unavailable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewHandler(fakePinger{tt.pingErr}, "abc123")
			w := httptest.NewRecorder()
			tt.probe(h)(w, httptest.NewRequest(http.MethodGet, "/", nil))

			var got status
			if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
				t.Fatal(err)
			}
			if w.Code != tt.wantCode || got.Status != tt.wantStatus || got.Version != "abc123" {
				t.Errorf("got %d %+v, want %d %q", w.Code, got, tt.wantCode, tt.wantStatus)
			}
		})
	}
}

func BenchmarkHealthz(b *testing.B) {
	h := NewHandler(fakePinger{}, "v")
	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	for b.Loop() {
		h.Healthz(httptest.NewRecorder(), r)
	}
}
