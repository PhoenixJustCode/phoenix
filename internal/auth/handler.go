package auth

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"time"

	"phoenix/internal/clientip"
)

const (
	cookieName      = "session_token"
	maxLoginBody    = 4 << 10
	loginAttempts   = 10
	loginPeriod     = 15 * time.Minute
	afterLogoutPath = "/track"
	ipv6PrefixBits  = 64
	ipv6Bits        = 128
)

// Handler serves login and logout and checks sessions for other handlers.
type Handler struct {
	store   *Store
	limiter *Limiter
}

// NewHandler returns a Handler with the default brute force limit.
func NewHandler(store *Store) *Handler {
	return &Handler{store: store, limiter: NewLimiter(loginAttempts, loginPeriod)}
}

type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Login checks credentials and sets the session cookie.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	ip := clientip.FromRequest(r)
	if !h.limiter.Allow(limiterKey(ip)) {
		slog.Warn("login rate limited", "ip", ip)
		http.Error(w, "too many attempts, try later", http.StatusTooManyRequests)
		return
	}

	var creds credentials
	body := http.MaxBytesReader(w, r.Body, maxLoginBody)
	if err := json.NewDecoder(body).Decode(&creds); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	ok, err := h.store.Authenticate(r.Context(), creds.Username, creds.Password)
	if err != nil {
		slog.Error("failed to authenticate", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !ok {
		slog.Info("login failed", "ip", ip)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	token, expires, err := h.store.CreateSession(r.Context(), creds.Username)
	if err != nil {
		slog.Error("failed to create session", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, sessionCookie(token, expires))
	w.WriteHeader(http.StatusOK)
}

// Logout drops the session and the cookie.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		if err := h.store.DeleteSession(r.Context(), c.Value); err != nil {
			slog.Error("failed to delete session", "err", err)
		}
	}
	http.SetCookie(w, sessionCookie("", time.Unix(0, 0)))
	http.Redirect(w, r, afterLogoutPath, http.StatusSeeOther)
}

// LoggedIn reports whether the request carries a valid session cookie.
func (h *Handler) LoggedIn(r *http.Request) bool {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	ok, err := h.store.ValidSession(r.Context(), c.Value)
	if err != nil {
		slog.Error("failed to check session", "err", err)
		return false
	}
	return ok
}

// an IPv6 client usually owns a whole /64, so the limit applies to the prefix
func limiterKey(ip string) string {
	addr := net.ParseIP(ip)
	if addr == nil || addr.To4() != nil {
		return ip
	}
	return addr.Mask(net.CIDRMask(ipv6PrefixBits, ipv6Bits)).String()
}

func sessionCookie(value string, expires time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     cookieName,
		Value:    value,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}
