package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestHandler(t *testing.T) *Handler {
	t.Helper()
	s, _ := newTestStore(t)
	if err := s.UpsertAdmin(context.Background(), "admin", "secret"); err != nil {
		t.Fatal(err)
	}
	return NewHandler(s)
}

func login(h *Handler, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.Login(w, r)
	return w
}

func TestLogin(t *testing.T) {
	h := newTestHandler(t)
	tests := []struct {
		name string
		body string
		want int
	}{
		{name: "valid", body: `{"username":"admin","password":"secret"}`, want: http.StatusOK},
		{name: "wrong password", body: `{"username":"admin","password":"nope"}`, want: http.StatusUnauthorized},
		{name: "bad json", body: `{`, want: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := login(h, tt.body)
			if w.Code != tt.want {
				t.Fatalf("status = %d, want %d", w.Code, tt.want)
			}
			hasCookie := strings.Contains(w.Header().Get("Set-Cookie"), cookieName+"=")
			if hasCookie != (tt.want == http.StatusOK) {
				t.Errorf("Set-Cookie = %q", w.Header().Get("Set-Cookie"))
			}
		})
	}
}

func TestLimiterKey(t *testing.T) {
	tests := map[string]string{
		"203.0.113.7":           "203.0.113.7",
		"2001:db8:1:2:aaaa::1":  "2001:db8:1:2::",
		"2001:db8:1:2:bbbb::99": "2001:db8:1:2::",
		"garbage":               "garbage",
	}
	for ip, want := range tests {
		if got := limiterKey(ip); got != want {
			t.Errorf("limiterKey(%q) = %q, want %q", ip, got, want)
		}
	}
}

func TestLoginRateLimit(t *testing.T) {
	h := newTestHandler(t)
	for range loginAttempts {
		login(h, `{"username":"admin","password":"nope"}`)
	}
	if w := login(h, `{"username":"admin","password":"secret"}`); w.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429 after %d attempts", w.Code, loginAttempts)
	}
}

func TestLoginStoreErrors(t *testing.T) {
	s, db := newTestStore(t)
	h := NewHandler(s)
	_ = db.Close()
	if w := login(h, `{"username":"admin","password":"secret"}`); w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestLoginSessionError(t *testing.T) {
	s, db := newTestStore(t)
	h := NewHandler(s)
	if err := s.UpsertAdmin(context.Background(), "admin", "secret"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("DROP TABLE sessions"); err != nil {
		t.Fatal(err)
	}
	if w := login(h, `{"username":"admin","password":"secret"}`); w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestLoggedInAndLogout(t *testing.T) {
	h := newTestHandler(t)
	cookie := login(h, `{"username":"admin","password":"secret"}`).Result().Cookies()[0]

	r := httptest.NewRequest(http.MethodGet, "/track", nil)
	if h.LoggedIn(r) {
		t.Error("LoggedIn() = true without cookie")
	}
	r.AddCookie(cookie)
	if !h.LoggedIn(r) {
		t.Fatal("LoggedIn() = false with fresh session")
	}

	w := httptest.NewRecorder()
	h.Logout(w, r)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != afterLogoutPath {
		t.Errorf("Logout() = %d to %q", w.Code, w.Header().Get("Location"))
	}
	if h.LoggedIn(r) {
		t.Error("LoggedIn() = true after logout")
	}
}

func TestSessionChecksWithBrokenDB(t *testing.T) {
	s, db := newTestStore(t)
	h := NewHandler(s)
	_ = db.Close()

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: cookieName, Value: "t"})
	if h.LoggedIn(r) {
		t.Error("LoggedIn() = true on db error")
	}
	w := httptest.NewRecorder()
	h.Logout(w, r)
	if w.Code != http.StatusSeeOther {
		t.Errorf("Logout() = %d, must still redirect on db error", w.Code)
	}
}
