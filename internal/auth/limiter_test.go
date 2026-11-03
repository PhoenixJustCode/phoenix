package auth

import (
	"fmt"
	"testing"
	"time"
)

func newTestLimiter(maxAttempts int, now *time.Time) *Limiter {
	l := NewLimiter(maxAttempts, time.Minute)
	l.now = func() time.Time { return *now }
	return l
}

func TestLimiter(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newTestLimiter(2, &now)

	for i, want := range []bool{true, true, false} {
		if got := l.Allow("a"); got != want {
			t.Fatalf("attempt %d: Allow() = %v, want %v", i+1, got, want)
		}
	}
	if !l.Allow("b") {
		t.Error("other key must have its own window")
	}

	now = now.Add(time.Minute)
	if !l.Allow("a") {
		t.Error("window must reset after the period")
	}
}

func fill(l *Limiter) {
	for i := range limiterMaxKeys {
		l.Allow(fmt.Sprint(i))
	}
}

func TestLimiterPurgesStaleKeys(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newTestLimiter(1, &now)
	fill(l)

	now = now.Add(time.Minute)
	if !l.Allow("fresh") {
		t.Fatal("Allow() = false after stale keys could be purged")
	}
	if len(l.hits) != 1 {
		t.Errorf("len(hits) = %d after purge, want 1", len(l.hits))
	}
}

func TestLimiterFailsClosedWhenFullOfActiveKeys(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newTestLimiter(1, &now)
	l.lastPurge = now.Add(-time.Hour)
	fill(l)

	if l.Allow("new") {
		t.Error("Allow() = true for a new key while the map is full of active keys")
	}
	if l.Allow("another") {
		t.Error("Allow() = true right after a useless purge")
	}
	if len(l.hits) != limiterMaxKeys {
		t.Errorf("len(hits) = %d, map must not grow past the cap", len(l.hits))
	}
	if l.Allow("0") {
		t.Error("known key over its limit must stay limited")
	}
}
