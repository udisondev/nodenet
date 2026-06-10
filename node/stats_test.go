package node

import (
	"testing"
	"time"

	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/routing"
	"github.com/udisondev/nodenet/transport"
)

// TestStatsCountDrops (#observability): the defensive checks bump the drop counters, so a
// flood is visibly shed rather than silently absorbed.
func TestStatsCountDrops(t *testing.T) {
	n := newBareNode(t, 1)
	sender := identity.FromSeed(seedFor(42))
	var ed [32]byte
	copy(ed[:], sender.EdPublic())

	deliver := func(m *routing.Msg) {
		p := transport.Get()
		w, _ := routing.EncodeRouteFrame(p.Buf(), m)
		p.SetLen(w)
		n.handle(transport.Delivery{Pkt: p})
	}

	// Stale (fresh-signed but old timestamp) → DroppedStale.
	stale := routing.Msg{Target: n.ID(), TTL: routing.MaxHops, EdPub: ed, Payload: []byte("x")}
	routing.SignMsg(sender, routing.TypeRoute, &stale, time.Now().Add(-time.Hour))
	deliver(&stale)

	// Fresh but unsigned → DroppedBadSig.
	bad := routing.Msg{Target: n.ID(), TTL: routing.MaxHops, EdPub: ed, Sent: time.Now().UnixNano(), Payload: []byte("x")}
	deliver(&bad)

	s := n.Stats()
	if s.DroppedStale != 1 {
		t.Errorf("DroppedStale = %d, want 1", s.DroppedStale)
	}
	if s.DroppedBadSig != 1 {
		t.Errorf("DroppedBadSig = %d, want 1", s.DroppedBadSig)
	}
}
