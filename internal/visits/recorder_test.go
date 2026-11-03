package visits

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"unicode/utf8"

	"phoenix/internal/database"
	"phoenix/internal/testdb"
)

func newTestRecorder(t testing.TB) (*Recorder, *sql.DB) {
	t.Helper()
	db, _ := testdb.New(t)
	if err := database.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	return NewRecorder(db, geoStub(t, 200, `{"country_name":"Kazakhstan","city":"Almaty"}`)), db
}

func countVisits(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow("SELECT count(*) FROM visits").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestRecordDeduplicatesByIP(t *testing.T) {
	r, db := newTestRecorder(t)
	ctx := context.Background()

	for range 3 {
		if err := r.Record(ctx, publicIP, "ua"); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Record(ctx, "127.0.0.1", "ua"); err != nil {
		t.Fatal(err)
	}
	if got := countVisits(t, db); got != 2 {
		t.Errorf("visits = %d, want 2 (one per IP)", got)
	}
}

func TestRecordTruncatesUserAgent(t *testing.T) {
	r, db := newTestRecorder(t)
	long := strings.Repeat("я", maxUserAgentBytes)
	if err := r.Record(context.Background(), publicIP, long); err != nil {
		t.Fatal(err)
	}
	var ua string
	if err := db.QueryRow("SELECT user_agent FROM visits").Scan(&ua); err != nil {
		t.Fatal(err)
	}
	if len(ua) > maxUserAgentBytes || !utf8.ValidString(ua) {
		t.Errorf("stored user agent: %d bytes, valid utf8 = %v", len(ua), utf8.ValidString(ua))
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		in   string
		n    int
		want string
	}{
		{in: "short", n: 10, want: "short"},
		{in: "abcdef", n: 3, want: "abc"},
		{in: "яя", n: 3, want: "я"},
	}
	for _, tt := range tests {
		if got := truncate(tt.in, tt.n); got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.in, tt.n, got, tt.want)
		}
	}
}

func TestRecordAsyncAndWait(t *testing.T) {
	r, db := newTestRecorder(t)
	r.RecordAsync(publicIP, "ua")
	r.Wait()
	if got := countVisits(t, db); got != 1 {
		t.Errorf("visits = %d after Wait(), want 1", got)
	}
}

func TestRecordAsyncDropsWhenSaturated(t *testing.T) {
	r, db := newTestRecorder(t)
	for range maxBackgroundRecords {
		r.slots <- struct{}{}
	}
	r.RecordAsync(publicIP, "ua")
	r.Wait()
	if got := countVisits(t, db); got != 0 {
		t.Errorf("visits = %d, want the overflow visit dropped", got)
	}
}

func TestRecordErrors(t *testing.T) {
	r, db := newTestRecorder(t)
	ctx := context.Background()
	if _, err := db.Exec("ALTER TABLE visits ADD CONSTRAINT no_new_rows CHECK (false) NOT VALID"); err != nil {
		t.Fatal(err)
	}
	if err := r.Record(ctx, publicIP, "ua"); err == nil {
		t.Error("Record() error = nil when insert fails")
	}
	_ = db.Close()
	if err := r.Record(ctx, publicIP, "ua"); err == nil {
		t.Error("Record() error = nil on closed db")
	}
	r.RecordAsync(publicIP, "ua")
	r.Wait()
}

func TestList(t *testing.T) {
	r, db := newTestRecorder(t)
	ctx := context.Background()
	_, err := db.Exec(`INSERT INTO visits (ip, country, city, user_agent) VALUES
		('1.1.1.1', 'Kazakhstan', 'Almaty', 'ua'),
		('2.2.2.2', 'Kazakhstan', 'Astana', 'ua'),
		('3.3.3.3', 'Germany', 'Berlin', NULL)`)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name          string
		search        string
		limit, offset int
		wantLen       int
		wantTotal     int
	}{
		{name: "all", limit: 10, wantLen: 3, wantTotal: 3},
		{name: "paged", limit: 2, offset: 2, wantLen: 1, wantTotal: 3},
		{name: "search country", search: "kazakh", limit: 10, wantLen: 2, wantTotal: 2},
		{name: "search city", search: "berlin", limit: 10, wantLen: 1, wantTotal: 1},
		{name: "no match", search: "mars", limit: 10, wantLen: 0, wantTotal: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, total, err := r.List(ctx, tt.search, tt.limit, tt.offset)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != tt.wantLen || total != tt.wantTotal {
				t.Errorf("List() = %d rows, total %d; want %d, %d", len(got), total, tt.wantLen, tt.wantTotal)
			}
		})
	}
}

func TestListDatabaseError(t *testing.T) {
	r, db := newTestRecorder(t)
	_ = db.Close()
	if _, _, err := r.List(context.Background(), "", 10, 0); err == nil {
		t.Fatal("List() error = nil on closed db")
	}
}

func BenchmarkRecordDuplicate(b *testing.B) {
	r, _ := newTestRecorder(b)
	ctx := context.Background()
	if err := r.Record(ctx, publicIP, "ua"); err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		if err := r.Record(ctx, publicIP, "ua"); err != nil {
			b.Fatal(err)
		}
	}
}
