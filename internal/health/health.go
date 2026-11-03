// Package health exposes liveness and readiness probes.
package health

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

const readyTimeout = 2 * time.Second

// Pinger is satisfied by *sql.DB.
type Pinger interface {
	PingContext(ctx context.Context) error
}

// Handler serves /healthz and /readyz.
type Handler struct {
	db      Pinger
	version string
}

// NewHandler returns a Handler reporting version.
func NewHandler(db Pinger, version string) *Handler {
	return &Handler{db: db, version: version}
}

type status struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

// Healthz reports that the process serves requests; deploy checks the version in it.
func (h *Handler) Healthz(w http.ResponseWriter, _ *http.Request) {
	h.write(w, http.StatusOK, "ok")
}

// Readyz additionally checks the database.
func (h *Handler) Readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), readyTimeout)
	defer cancel()
	if err := h.db.PingContext(ctx); err != nil {
		slog.Warn("readiness check failed", "err", err)
		h.write(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	h.write(w, http.StatusOK, "ready")
}

func (h *Handler) write(w http.ResponseWriter, code int, s string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(status{Status: s, Version: h.version})
}
