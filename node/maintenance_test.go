package node

import (
	"testing"
	"time"

	"github.com/udisondev/nodenet/kad"
)

// TestBumpBackoffExhaustion: bumpBackoff reports the ladder exhausted — the purge
// signal — only when the peer has failed at least markDeadFails times AND was already
// waiting at the BackoffMax ceiling when it failed again. A short failure streak that
// never climbs to the ceiling (a transient outage) must not purge.
func TestBumpBackoffExhaustion(t *testing.T) {
	m := Maintenance{BackoffBase: time.Second, BackoffMax: 2 * time.Second}.withDefaults()
	now := time.Unix(1_000_000, 0)
	backoff := map[kad.ID]backoffState{}
	id := kad.ID{1}

	// Ladder 1s → 2s(=max) → purge on the next failure at the ceiling.
	for i, want := range []bool{false, false, true} {
		if got := bumpBackoff(backoff, id, m, now); got != want {
			t.Fatalf("failure #%d: exhausted = %v, want %v", i+1, got, want)
		}
	}

	// With base == max the ceiling is hit at once, but the fail floor still holds:
	// fewer than markDeadFails failures never purge.
	m2 := Maintenance{BackoffBase: time.Hour, BackoffMax: time.Hour}.withDefaults()
	id2 := kad.ID{2}
	for i, want := range []bool{false, false, true} {
		if got := bumpBackoff(backoff, id2, m2, now); got != want {
			t.Fatalf("base==max failure #%d: exhausted = %v, want %v", i+1, got, want)
		}
	}
}

// TestPruneBackoff: a backoff entry whose window elapsed long ago without a re-dial is
// dropped (the peer left the knowledge table and is no longer a fill candidate), while a
// still-pending entry is kept. Without this the map grows without bound under churn of
// permanently-dead contacts.
func TestPruneBackoff(t *testing.T) {
	m := DefaultMaintenance()
	now := time.Unix(1_000_000, 0)
	backoff := map[kad.ID]backoffState{
		{1}: {delay: m.BackoffBase, nextAt: now.Add(time.Second)},      // still pending → keep
		{2}: {delay: m.BackoffMax, nextAt: now.Add(-2 * m.BackoffMax)}, // long stale → prune
	}

	pruneBackoff(backoff, now, m)

	if _, ok := backoff[kad.ID{1}]; !ok {
		t.Fatal("pruned a still-pending backoff entry")
	}
	if _, ok := backoff[kad.ID{2}]; ok {
		t.Fatal("did not prune a long-stale backoff entry")
	}
}
