package node

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/transport/mem"
)

// idForSeed names a spawn-derived NodeID before the node exists, so a policy
// closure can be built ahead of spawning.
func idForSeed(seed uint64) kad.ID { return identity.FromSeed(seedFor(seed)).ID() }

// TestEdgeAdmissionInboundRefused: a peer the application's policy bans dials
// in and sends its first frame; the frame is dropped, no inbound edge is
// registered, and the refusal is counted — while an unbanned peer is admitted
// as usual.
func TestEdgeAdmissionInboundRefused(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))

		banned := idForSeed(2)
		a := spawn(t, ctx, hub, 1, WithEdgeAdmission(func(remote ID) bool { return remote != banned }))
		b := spawn(t, ctx, hub, 2)
		c := spawn(t, ctx, hub, 3)
		link(t, ctx, b, a) // b holds an outgoing edge; a has not seen b yet
		link(t, ctx, c, a)

		if err := b.Send(a.ID(), []byte("from banned")); err != nil {
			t.Fatalf("Send: %v", err)
		}
		if err := c.Send(a.ID(), []byte("from allowed")); err != nil {
			t.Fatalf("Send: %v", err)
		}
		synctest.Wait()

		select {
		case got := <-a.Deliveries():
			if string(got.Payload) != "from allowed" || got.Originator != c.ID() {
				t.Errorf("delivered %q from %v; the banned peer's frame must be the dropped one", got.Payload, got.Originator)
			}
		default:
			t.Fatal("the allowed peer's message was not delivered")
		}
		select {
		case got := <-a.Deliveries():
			t.Fatalf("unexpected extra delivery %q — the banned frame got through", got.Payload)
		default:
		}
		if _, ok := a.e.Conn(banned); ok {
			t.Error("banned peer was registered as an inbound edge")
		}
		if _, ok := a.e.Conn(c.ID()); !ok {
			t.Error("allowed peer was not registered as an inbound edge")
		}
		if got := a.Stats().DroppedEdgeRefused; got != 1 {
			t.Errorf("DroppedEdgeRefused = %d, want 1", got)
		}
	})
}

// TestEdgeAdmissionOutboundRefused: register — the single outbound
// registration site behind Connect, hole-punch, relay and the maintenance
// dialer — closes a dialed connection to a banned peer and reports
// ErrEdgeRefused.
func TestEdgeAdmissionOutboundRefused(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		banned := kad.ID{42}
		n := newBareNode(t, 1, WithEdgeAdmission(func(remote ID) bool { return remote != banned }))

		if _, err := n.register(stubConn{id: banned}, 0, time.Now()); !errors.Is(err, ErrEdgeRefused) {
			t.Fatalf("register(banned) err = %v, want ErrEdgeRefused", err)
		}
		if _, ok := n.e.Conn(banned); ok {
			t.Error("banned peer was registered as an outgoing edge")
		}
		if got := n.Stats().DroppedEdgeRefused; got != 1 {
			t.Errorf("DroppedEdgeRefused = %d, want 1", got)
		}
		if _, err := n.register(stubConn{id: kad.ID{7}}, 0, time.Now()); err != nil {
			t.Fatalf("register(allowed): %v", err)
		}
	})
}
