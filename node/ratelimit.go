package node

import (
	"sync"
	"time"

	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/routing"
)

// maxOriginBuckets bounds the per-originator rate-limit table. Each entry costs the
// attacker a distinct PoW identity, so the table stays small under honest load; the cap
// is a level-2 backstop against an adversary grinding many identities to exhaust memory.
const maxOriginBuckets = 4096

// originLimiter rate-limits work-generating routed messages (a lookup answer, a Connect
// coord-disclosure) by their AUTHENTICATED originator rather than by the edge they
// arrived on. Keying on the originator — sound only because the routing envelope is
// signed — means an attacker cannot dodge the limit by spreading a flood across many
// edges, and a busy relay forwarding others' traffic is not falsely throttled.
//
// The dispatch loop is single-goroutine, so this is effectively uncontended; the mutex
// guards the map for safety and future callers, and each TokenBucket guards itself.
type originLimiter struct {
	mu      sync.Mutex
	buckets map[kad.ID]*routing.TokenBucket
}

func newOriginLimiter() *originLimiter {
	return &originLimiter{buckets: make(map[kad.ID]*routing.TokenBucket)}
}

// allow consumes a token for originator and reports whether the message may be served.
func (l *originLimiter) allow(originator kad.ID, now time.Time) bool {
	l.mu.Lock()
	b := l.buckets[originator]
	if b == nil {
		if len(l.buckets) >= maxOriginBuckets {
			l.evict(now)
		}
		b = &routing.TokenBucket{}
		l.buckets[originator] = b
	}
	l.mu.Unlock()
	return b.Allow(now, routing.ControlRate, routing.ControlBurst)
}

// evict bounds the table when it is full WITHOUT discarding live throttle state. It drops
// every bucket that has fully refilled to its burst ceiling — such a bucket holds no
// consumed-token history, so forgetting it is free and a fresh insert reconstructs the
// same full bucket. Only if a flood keeps every bucket actively throttled (no refilled
// one to drop) does it evict the single fullest, losing the least state. A whole-map wipe
// would instead reset EVERY currently-throttled originator to a fresh full burst — exactly
// the relief an attacker grinding identities to fill the table wants, plus a collateral
// reset of honest busy originators. Caller holds l.mu.
func (l *originLimiter) evict(now time.Time) {
	var victim kad.ID
	fullest := -1.0
	for id, b := range l.buckets {
		t := b.Tokens(now, routing.ControlRate, routing.ControlBurst)
		if t >= routing.ControlBurst {
			delete(l.buckets, id) // fully refilled: no throttle state to lose
			continue
		}
		if t > fullest {
			fullest, victim = t, id
		}
	}
	if len(l.buckets) >= maxOriginBuckets {
		delete(l.buckets, victim) // every bucket still active; drop the fullest
	}
}
