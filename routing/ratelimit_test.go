package routing

import (
	"testing"
	"time"

	"github.com/udisondev/nodenet/kad"
)

// TestAllowControlBurstThenRefill checks the per-edge token bucket: it permits an
// initial burst, denies once drained within the same instant, and replenishes over
// time at the configured rate.
func TestAllowControlBurstThenRefill(t *testing.T) {
	e := NewEdges(kad.ID{}, nil)
	id := kad.ID{1}
	if err := e.AddEdge(fakeConn{id: id}, true, 0, t0); err != nil {
		t.Fatalf("AddEdge: %v", err)
	}

	// At a single instant the bucket allows exactly ControlBurst events, then denies.
	now := t0
	allowed := 0
	for range ControlBurst + 10 {
		if e.AllowControl(id, now) {
			allowed++
		}
	}
	if allowed != ControlBurst {
		t.Fatalf("initial burst allowed %d, want ControlBurst %d", allowed, ControlBurst)
	}
	if e.AllowControl(id, now) {
		t.Fatal("bucket allowed an event past the drained burst at the same instant")
	}

	// After one second the bucket has refilled ControlRate tokens.
	now = now.Add(time.Second)
	refilled := 0
	for range ControlBurst + 10 {
		if e.AllowControl(id, now) {
			refilled++
		}
	}
	if refilled != ControlRate {
		t.Fatalf("after 1s refill allowed %d, want ControlRate %d", refilled, ControlRate)
	}
}

// TestAllowDeniesUnregisteredPeer: a peer whose edge registration was refused — the
// inbound cap is the reachable case — must not fall through to an unlimited budget.
// Once the inbound table is full, every further peer would otherwise get unthrottled
// service of amplifying frames (sibling requests, routed transit), defeating the
// level-2 per-edge throttle exactly for the population past the cap. Only the zero
// id (a self-originated frame, which has no edge by construction) passes uncharged.
func TestAllowDeniesUnregisteredPeer(t *testing.T) {
	var self kad.ID
	e := NewEdges(self, nil)
	for i := range InboundCap {
		if err := e.AddEdge(fakeConn{id: idInBucket(self, 10, i+1)}, false, 0, t0); err != nil {
			t.Fatalf("inbound AddEdge %d: %v", i, err)
		}
	}
	over := idInBucket(self, 10, InboundCap+1)
	if err := e.AddEdge(fakeConn{id: over}, false, 0, t0); err != ErrInboundFull {
		t.Fatalf("over-cap AddEdge err = %v, want ErrInboundFull", err)
	}
	if e.AllowControl(over, t0) {
		t.Fatal("AllowControl granted unlimited budget to a peer refused by InboundCap")
	}
	if e.AllowForward(over, t0) {
		t.Fatal("AllowForward granted unlimited budget to a peer refused by InboundCap")
	}
	// A self-originated frame (zero id, no edge to charge) is never throttled.
	if !e.AllowControl(kad.ID{}, t0) {
		t.Fatal("AllowControl denied a self-originated (zero-id) frame")
	}
	if !e.AllowForward(kad.ID{}, t0) {
		t.Fatal("AllowForward denied a self-originated (zero-id) frame")
	}
}

// An untracked non-zero id has no bucket to charge and no registered edge — it is a
// peer the table refused, so it is denied rather than handed an unlimited budget.
func TestAllowControlUntracked(t *testing.T) {
	e := NewEdges(kad.ID{}, nil)
	if e.AllowControl(kad.ID{9}, t0) {
		t.Fatal("AllowControl permitted an untracked peer")
	}
}
