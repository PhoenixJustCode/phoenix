package visits

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

type fakeSessions bool

func (f fakeSessions) LoggedIn(*http.Request) bool { return bool(f) }

var testPages = fstest.MapFS{
	adminPage: {Data: []byte("admin panel")},
	loginPage: {Data: []byte("login form")},
}

func TestTrack(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		loggedIn bool
		want     int
		wantBody string
	}{
		{name: "get anonymous", method: http.MethodGet, want: 200, wantBody: "login form"},
		{name: "get logged in", method: http.MethodGet, loggedIn: true, want: 200, wantBody: "admin panel"},
		{name: "post", method: http.MethodPost, want: 204},
		{name: "put", method: http.MethodPut, want: 405},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, _ := newTestRecorder(t)
			h := NewHandler(rec, fakeSessions(tt.loggedIn), testPages)
			w := httptest.NewRecorder()
			h.Track(w, httptest.NewRequest(tt.method, "/track", nil))
			rec.Wait()

			if w.Code != tt.want || !strings.Contains(w.Body.String(), tt.wantBody) {
				t.Errorf("Track() = %d %q, want %d %q", w.Code, w.Body.String(), tt.want, tt.wantBody)
			}
		})
	}
}

func TestTrackPostIgnoresRecordError(t *testing.T) {
	rec, db := newTestRecorder(t)
	_ = db.Close()
	w := httptest.NewRecorder()
	h := NewHandler(rec, fakeSessions(false), testPages)
	h.Track(w, httptest.NewRequest(http.MethodPost, "/track", nil))
	rec.Wait()
	if w.Code != http.StatusNoContent {
		t.Errorf("Track() = %d, tracking errors must not break the page", w.Code)
	}
}

func TestAPI(t *testing.T) {
	rec, db := newTestRecorder(t)
	if _, err := db.Exec("INSERT INTO visits (ip, country, city, user_agent) SELECT '9.9.9.' || g, 'X', 'Y', 'ua' FROM generate_series(1, 150) g"); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		loggedIn bool
		query    string
		want     int
		wantLen  int
	}{
		{name: "unauthorized", query: "", want: 401},
		{name: "default limit", loggedIn: true, query: "", want: 200, wantLen: defaultLimit},
		{name: "custom limit", loggedIn: true, query: "?limit=25&offset=5", want: 200, wantLen: 25},
		{name: "limit capped", loggedIn: true, query: "?limit=1000", want: 200, wantLen: defaultLimit},
		{name: "garbage params", loggedIn: true, query: "?limit=x&offset=-4", want: 200, wantLen: defaultLimit},
		{name: "search", loggedIn: true, query: "?search=9.9.9.150", want: 200, wantLen: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			NewHandler(rec, fakeSessions(tt.loggedIn), testPages).API(w, httptest.NewRequest(http.MethodGet, "/api/visits"+tt.query, nil))
			if w.Code != tt.want {
				t.Fatalf("API() status = %d, want %d", w.Code, tt.want)
			}
			if tt.want != http.StatusOK {
				return
			}
			var resp struct {
				Visits []Visit `json:"visits"`
				Total  int     `json:"total"`
			}
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatal(err)
			}
			if len(resp.Visits) != tt.wantLen {
				t.Errorf("API() returned %d visits, want %d", len(resp.Visits), tt.wantLen)
			}
		})
	}
}

func TestAPIDatabaseError(t *testing.T) {
	rec, db := newTestRecorder(t)
	_ = db.Close()
	w := httptest.NewRecorder()
	NewHandler(rec, fakeSessions(true), testPages).API(w, httptest.NewRequest(http.MethodGet, "/api/visits", nil))
	if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "sql") {
		t.Errorf("API() = %d %q, want 500 without internals", w.Code, w.Body.String())
	}
}
