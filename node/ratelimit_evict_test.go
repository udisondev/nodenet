package node

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/routing"
)

// TestOriginLimiterEvictPreservesThrottleState (M4): when the per-originator table fills,
// it must not WIPE every bucket — that would reset every currently-throttled originator to
// a fresh full burst, exactly the relief a flood of ground identities wants. Eviction drops
// fully-refilled buckets (no state to lose) and keeps actively-throttled ones, so a drained
// victim stays drained across the table churn.
func TestOriginLimiterEvictPreservesThrottleState(t *testing.T) {
	l := newOriginLimiter()
	now := time.Unix(1_700_000_000, 0)
	past := now.Add(-time.Hour) // buckets last touched here are fully refilled by now

	// Fill to one short of capacity with buckets touched in the far past, so they are all
	// refilled at `now` and become the natural eviction targets.
	for i := uint64(1); len(l.buckets) < maxOriginBuckets-1; i++ {
		var id kad.ID
		binary.BigEndian.PutUint64(id[:], i)
		l.allow(id, past)
	}

	// The victim: an originator actively throttled right now (its burst drained at `now`).
	victim := kad.ID{0xAA, 0xBB, 0xCC}
	for range routing.ControlBurst {
		l.allow(victim, now)
	}
	if l.allow(victim, now) {
		t.Fatal("setup: victim should be throttled after draining its burst")
	}
	if len(l.buckets) != maxOriginBuckets {
		t.Fatalf("setup: table holds %d, want it full at %d", len(l.buckets), maxOriginBuckets)
	}

	// A brand-new originator at the same instant triggers eviction. The refilled past
	// buckets are dropped; the victim's live throttle state must survive.
	var fresh kad.ID
	fresh[0], fresh[kad.IDLen-1] = 0xFF, 0xFF
	l.allow(fresh, now)

	if l.allow(victim, now) {
		t.Fatal("victim's throttle was reset by table eviction (whole-map wipe regression)")
	}
}
