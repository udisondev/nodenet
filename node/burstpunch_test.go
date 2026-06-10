package node

import (
	"context"
	"strconv"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/udisondev/nodenet/transport"
)

type countPuncher struct{ n atomic.Int32 }

func (c *countPuncher) PunchTo(transport.Addr) error { c.n.Add(1); return nil }

// TestBurstPunchStopsOnCancel: a punch burst spawned in response to an inbound frame must
// stop when the node's context is cancelled, rather than sleeping out its full schedule
// and outliving the dispatch loop. With a cancelled context it fires at most the first
// round and returns promptly.
func TestBurstPunchStopsOnCancel(t *testing.T) {
	n := newBareNode(t, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled, as at shutdown

	p := &countPuncher{}
	addrs := []transport.Addr{{Net: "x", Endpoint: "1"}, {Net: "x", Endpoint: "2"}}

	done := make(chan struct{})
	go func() { n.burstPunch(ctx, p, addrs); close(done) }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("burstPunch ignored context cancellation")
	}
	if got := p.n.Load(); got >= int32(punchBurst*len(addrs)) {
		t.Fatalf("burstPunch made %d punches after cancel; expected an early stop (< %d)",
			got, punchBurst*len(addrs))
	}
}

// TestPunchCandidatesDedupCap (#5): punch fan-out is deduplicated and capped, so a
// Connect/RelayBind carrying many or repeated addresses cannot make the node emit an
// unbounded burst.
func TestPunchCandidatesDedupCap(t *testing.T) {
	// Duplicates collapse.
	dup := []transport.Addr{
		{Net: "quic", Endpoint: "203.0.113.1:1"},
		{Net: "quic", Endpoint: "203.0.113.1:1"},
		{Net: "quic", Endpoint: "203.0.113.2:2"},
	}
	if got := punchCandidates(dup); len(got) != 2 {
		t.Fatalf("dedup: got %d, want 2", len(got))
	}
	// Over-long lists are capped.
	var many []transport.Addr
	for i := range maxPunchCandidates + 20 {
		many = append(many, transport.Addr{Net: "quic", Endpoint: "203.0.113.9:" + strconv.Itoa(i)})
	}
	if got := punchCandidates(many); len(got) != maxPunchCandidates {
		t.Fatalf("cap: got %d, want %d", len(got), maxPunchCandidates)
	}
}

// TestBurstPunchNoTrailingSleep: the burst spaces its volleys punchSpacing apart but
// must not sleep after the LAST one — in holePunchRaw the burst runs synchronously
// before the dial, so a trailing sleep is dead latency on the connection-establishment
// path (and in punchAsync it holds a punchSem slot longer than needed).
func TestBurstPunchNoTrailingSleep(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := newBareNode(t, 1)
		p := &countPuncher{}

		start := time.Now()
		n.burstPunch(context.Background(), p, []transport.Addr{{Net: "x", Endpoint: "1"}})
		if got, want := time.Since(start), (punchBurst-1)*punchSpacing; got != want {
			t.Fatalf("burstPunch took %v of fake time; want %v (no sleep after the last volley)", got, want)
		}
		if got := p.n.Load(); got != punchBurst {
			t.Fatalf("burstPunch fired %d datagrams, want %d", got, punchBurst)
		}
	})
}
