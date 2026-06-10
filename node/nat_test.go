package node

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/transport/mem"
)

// TestInboundEdgeRegisteredOnFirstSight: a public-style node C learns an inbound edge
// to a NAT node A the first time A's traffic arrives — without C ever dialing A — and
// can then route back to A over that bidirectional channel. This is the mechanism that
// makes a node a full router for the NAT peers that dialed it, and what lets a
// coordinator relay hole-punch signalling to a NAT node. The inbound edge is not
// counted toward C's connectivity floor.
func TestInboundEdgeRegisteredOnFirstSight(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))

		c := spawn(t, ctx, hub, 1)
		a := spawn(t, ctx, hub, 2)

		// A dials C and routes a message to it; C never dials A (the NAT case).
		link(t, ctx, a, c)
		if _, ok := c.e.Conn(a.ID()); ok {
			t.Fatal("C has an edge to A before any traffic")
		}

		if err := a.Send(c.ID(), []byte("hi")); err != nil {
			t.Fatalf("A.Send: %v", err)
		}
		synctest.Wait()

		if got := drainDeliveries(c); got == 0 {
			t.Fatal("C did not receive A's message")
		}
		if _, ok := c.e.Conn(a.ID()); !ok {
			t.Fatal("C did not register an inbound edge to A on first sight")
		}
		if st := c.e.Status(); st.OutEdges != 0 {
			t.Fatalf("C OutEdges = %d, want 0 (an inbound edge is not self-maintained)", st.OutEdges)
		}

		// C can now route back to A over the edge A opened — unreachable before.
		if err := c.Send(a.ID(), []byte("back")); err != nil {
			t.Fatalf("C.Send back to NAT A: %v", err)
		}
		synctest.Wait()
		if got := drainDeliveries(a); got == 0 {
			t.Fatal("A did not receive C's reply over the inbound edge")
		}
	})
}

// TestHolePunchUnsupportedOnMem: HolePunch needs a transport that can punch; the
// in-memory transport cannot, so it reports ErrUnsupported rather than hanging.
func TestHolePunchUnsupportedOnMem(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))

		a := spawn(t, ctx, hub, 1)
		b := spawn(t, ctx, hub, 2)
		link(t, ctx, a, b)

		pctx, pcancel := context.WithTimeout(ctx, time.Second)
		defer pcancel()
		if _, err := a.HolePunch(pctx, b.ID(), nil); err != ErrUnsupported {
			t.Fatalf("HolePunch on mem = %v, want ErrUnsupported", err)
		}
	})
}

// ensure the mem transport indeed does not advertise Puncher (guards the test above).
func TestMemIsNotPuncher(t *testing.T) {
	hub := mem.NewHub()
	id := identity.FromSeed(seedFor(1))
	tr, err := hub.New(id.ID(), transport.Addr{Net: "mem", Endpoint: "x"})
	if err != nil {
		t.Fatalf("hub.New: %v", err)
	}
	defer tr.Close()
	if _, ok := tr.(transport.Puncher); ok {
		t.Fatal("mem transport must not implement Puncher")
	}
}
