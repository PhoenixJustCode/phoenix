package visits

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	// one visit per IP per window, so reloads don't inflate statistics
	dedupWindow   = "50 minutes"
	recordTimeout = 10 * time.Second
	// below the db pool size, so background stats never starve requests of connections
	maxBackgroundRecords = 5
	maxUserAgentBytes    = 512
)

const (
	recentVisitQuery = `
		SELECT EXISTS(SELECT 1 FROM visits WHERE ip = $1 AND visited_at > NOW() - $2::interval)`
	// the repeated check narrows the race between parallel requests from one IP
	insertVisitQuery = `
		INSERT INTO visits (ip, country, city, user_agent)
		SELECT $1::varchar, $2::text, $3::text, $4::text
		WHERE NOT EXISTS (
			SELECT 1 FROM visits WHERE ip = $1::varchar AND visited_at > NOW() - $5::interval)`
	listVisitsQuery = `
		SELECT id, COALESCE(ip, ''), COALESCE(country, ''), COALESCE(city, ''),
		       COALESCE(user_agent, ''), COALESCE(visited_at, 'epoch')
		FROM visits
		WHERE $1 = '' OR ip ILIKE $2 OR country ILIKE $2 OR city ILIKE $2
		ORDER BY visited_at DESC
		LIMIT $3 OFFSET $4`
	countVisitsQuery = `
		SELECT count(*) FROM visits
		WHERE $1 = '' OR ip ILIKE $2 OR country ILIKE $2 OR city ILIKE $2`
)

// Visit is one tracked page view.
type Visit struct {
	ID        int       `json:"id"`
	IP        string    `json:"ip"`
	Country   string    `json:"country"`
	City      string    `json:"city"`
	UA        string    `json:"user_agent"`
	VisitedAt time.Time `json:"visited_at"`
}

// Recorder stores visits in postgres.
type Recorder struct {
	db    *sql.DB
	geo   *Geo
	wg    sync.WaitGroup
	slots chan struct{}
}

// NewRecorder returns a Recorder using db and geo.
func NewRecorder(db *sql.DB, geo *Geo) *Recorder {
	return &Recorder{db: db, geo: geo, slots: make(chan struct{}, maxBackgroundRecords)}
}

// Record saves a visit unless the same IP was seen within the dedup window.
func (r *Recorder) Record(ctx context.Context, ip, userAgent string) error {
	var seen bool
	if err := r.db.QueryRowContext(ctx, recentVisitQuery, ip, dedupWindow).Scan(&seen); err != nil {
		return fmt.Errorf("check recent visit: %w", err)
	}
	if seen {
		return nil
	}
	country, city := r.geo.Lookup(ctx, ip)
	ua := truncate(userAgent, maxUserAgentBytes)
	_, err := r.db.ExecContext(ctx, insertVisitQuery, ip, country, city, ua, dedupWindow)
	if err != nil {
		return fmt.Errorf("insert visit: %w", err)
	}
	return nil
}

// truncate cuts s to at most n bytes without splitting a UTF-8 character.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// RecordAsync records in the background; under overload the visit is dropped, stats are optional.
func (r *Recorder) RecordAsync(ip, userAgent string) {
	select {
	case r.slots <- struct{}{}:
	default:
		return
	}
	r.wg.Add(1)
	go func() {
		defer func() {
			<-r.slots
			r.wg.Done()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), recordTimeout)
		defer cancel()
		if err := r.Record(ctx, ip, userAgent); err != nil {
			slog.Error("failed to record visit", "err", err)
		}
	}()
}

// Wait blocks until background recordings finish; called on shutdown.
func (r *Recorder) Wait() {
	r.wg.Wait()
}

// List returns a page of visits matching search and the total number of matches.
func (r *Recorder) List(
	ctx context.Context, search string, limit, offset int,
) ([]Visit, int, error) {
	pattern := "%" + search + "%"
	rows, err := r.db.QueryContext(ctx, listVisitsQuery, search, pattern, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list visits: %w", err)
	}
	defer func() { _ = rows.Close() }()

	visits := []Visit{}
	for rows.Next() {
		var v Visit
		if err := rows.Scan(&v.ID, &v.IP, &v.Country, &v.City, &v.UA, &v.VisitedAt); err != nil {
			return nil, 0, fmt.Errorf("scan visit: %w", err)
		}
		visits = append(visits, v)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate visits: %w", err)
	}

	var total int
	if err := r.db.QueryRowContext(ctx, countVisitsQuery, search, pattern).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count visits: %w", err)
	}
	return visits, total, nil
}
