package auth

import (
	"sync"
	"time"
)

// hard cap on tracked keys; when full of active keys, new ones are rejected (fail closed)
const limiterMaxKeys = 10000

type window struct {
	start time.Time
	count int
}

// Limiter allows at most max attempts per key within a fixed time window.
type Limiter struct {
	mu        sync.Mutex
	max       int
	period    time.Duration
	now       func() time.Time
	hits      map[string]window
	lastPurge time.Time
}

// NewLimiter returns a Limiter allowing max attempts per period.
func NewLimiter(maxAttempts int, period time.Duration) *Limiter {
	return &Limiter{max: maxAttempts, period: period, now: time.Now, hits: map[string]window{}}
}

// Allow records an attempt for key and reports whether it is within the limit.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	w, known := l.hits[key]
	if !known && len(l.hits) >= limiterMaxKeys {
		// purging scans the whole map, so do it at most once per period
		if now.Sub(l.lastPurge) < l.period {
			return false
		}
		l.purge(now)
		if len(l.hits) >= limiterMaxKeys {
			return false
		}
	}
	if now.Sub(w.start) >= l.period {
		w = window{start: now}
	}
	w.count++
	l.hits[key] = w
	return w.count <= l.max
}

func (l *Limiter) purge(now time.Time) {
	l.lastPurge = now
	for k, w := range l.hits {
		if now.Sub(w.start) >= l.period {
			delete(l.hits, k)
		}
	}
}
