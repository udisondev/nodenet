package transport

import (
	"sync"
	"time"
)

// TokenBucket is a minimal time-based rate limiter: tokens refill continuously up to a
// burst ceiling and each allowed event consumes what it costs. It carries no clock — the
// caller passes now — so it stays deterministic under the fake-clock tests. It has its
// own mutex so charging it never needs an enclosing structure's write lock (a table can
// look a bucket up under its read lock and charge it after releasing, keeping rate
// checks off the contended path). The zero value is a ready, full bucket.
//
// It lives in transport — the bottom of the packages that need it — because the pipe's
// own level-2 self-protections meter with it (the relay volunteer's bandwidth shaper,
// the media receive budget) and the packages above (routing's per-edge limiters, node's
// per-originator limiter) reuse the same type.
type TokenBucket struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

// Allow refills the bucket for the elapsed time, then consumes a token if one is
// available, reporting whether the event is permitted.
func (tb *TokenBucket) Allow(now time.Time, rate, burst float64) bool {
	return tb.AllowN(now, 1, rate, burst)
}

// AllowN refills the bucket for the elapsed time, then consumes n tokens if that many
// are available, reporting whether the event is permitted. It is the byte-budget form
// of Allow: a shaper charges each datagram its length, so rate and burst are in
// bytes per second and bytes. A refused event consumes nothing.
func (tb *TokenBucket) AllowN(now time.Time, n, rate, burst float64) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	if tb.last.IsZero() {
		tb.tokens, tb.last = burst, now
	}
	tb.tokens += now.Sub(tb.last).Seconds() * rate
	if tb.tokens > burst {
		tb.tokens = burst
	}
	tb.last = now
	if tb.tokens < n {
		return false
	}
	tb.tokens -= n
	return true
}

// Tokens reports how many tokens the bucket would hold at now (refilled for the elapsed
// time, capped at burst) WITHOUT consuming any. A caller bounding a table of buckets uses
// it to tell a fully-refilled bucket — one holding no consumed-token state, safe to forget
// — from an actively-throttled one whose state must be kept. The zero value reports a full
// (burst) bucket.
func (tb *TokenBucket) Tokens(now time.Time, rate, burst float64) float64 {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	if tb.last.IsZero() {
		return burst
	}
	t := tb.tokens + now.Sub(tb.last).Seconds()*rate
	if t > burst {
		t = burst
	}
	return t
}
