package visits

import (
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"

	"phoenix/internal/clientip"
)

const (
	defaultLimit = 10
	maxLimit     = 100
	adminPage    = "admin.html"
	loginPage    = "login.html"
)

// SessionChecker tells whether a request belongs to a logged in admin.
type SessionChecker interface {
	LoggedIn(r *http.Request) bool
}

// Handler serves visit tracking and the admin statistics API.
type Handler struct {
	rec      *Recorder
	sessions SessionChecker
	pages    fs.FS
}

// NewHandler returns a Handler rendering admin and login pages from pages.
func NewHandler(rec *Recorder, sessions SessionChecker, pages fs.FS) *Handler {
	return &Handler{rec: rec, sessions: sessions, pages: pages}
}

// Track records a visit; GET also renders the admin panel or the login form.
func (h *Handler) Track(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// the browser must not show a cached login form after a successful login
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		h.rec.RecordAsync(clientip.FromRequest(r), r.UserAgent())
		page := loginPage
		if h.sessions.LoggedIn(r) {
			page = adminPage
		}
		http.ServeFileFS(w, r, h.pages, page)
	case http.MethodPost:
		h.rec.RecordAsync(clientip.FromRequest(r), r.UserAgent())
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// API returns a page of visits as JSON for the admin panel.
func (h *Handler) API(w http.ResponseWriter, r *http.Request) {
	if !h.sessions.LoggedIn(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	q := r.URL.Query()
	limit := intParam(q.Get("limit"), defaultLimit)
	if limit <= 0 || limit > maxLimit {
		limit = defaultLimit
	}
	offset := max(intParam(q.Get("offset"), 0), 0)

	visits, total, err := h.rec.List(r.Context(), q.Get("search"), limit, offset)
	if err != nil {
		slog.Error("failed to list visits", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	// visitor IPs must not stay in browser or proxy caches
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"visits": visits,
		"total":  total,
		"my_ip":  clientip.FromRequest(r),
	})
}

func intParam(s string, fallback int) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return fallback
	}
	return n
}
