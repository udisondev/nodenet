package node

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/transport/mem"
)

// TestConnectReturnsExistingInboundEdge: a peer that connected to us first leaves us
// holding a live inbound edge; our own Connect to that peer must return it instead of
// dialing a duplicate that register would refuse — the simultaneous-Connect collision,
// where one side would otherwise get ErrUnroutable despite a working edge.
func TestConnectReturnsExistingInboundEdge(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))

		a := spawn(t, ctx, hub, 1)
		b := spawn(t, ctx, hub, 2)

		// B connects to A first: B dials, and A registers the inbound edge on B's
		// first frame.
		link(t, ctx, b, a)
		if err := b.Send(a.ID(), []byte("hi")); err != nil {
			t.Fatalf("B.Send: %v", err)
		}
		synctest.Wait()
		existing, ok := a.e.Conn(b.ID())
		if !ok {
			t.Fatal("A did not register the inbound edge from B (precondition)")
		}

		conn, err := a.Connect(ctx, b.ID())
		if err != nil {
			t.Fatalf("Connect with a live edge to target: %v, want the existing edge", err)
		}
		if conn != existing {
			t.Fatal("Connect dialed a duplicate; want the already-registered edge returned")
		}
	})
}

// TestConnectPropagatesCascadeError: when every stage of Connect's cascade fails, the
// caller gets the last meaningful cause, not a blanket ErrUnroutable that masks it.
// Here rendezvous succeeds (routed via m) but the direct dial is partitioned away and
// there is no puncher or relay to fall back on — the dial's own ErrNoRoute must surface,
// the way dialContact already propagates its cascade's cause.
func TestConnectPropagatesCascadeError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))

		a := spawn(t, ctx, hub, 1)
		m := spawn(t, ctx, hub, 2)
		b := spawn(t, ctx, hub, 3)
		dialEdge(t, ctx, a, m)
		dialEdge(t, ctx, m, a)
		dialEdge(t, ctx, m, b)
		dialEdge(t, ctx, b, m)
		hub.Partition(a.ID(), b.ID()) // rendezvous routes via m; a's direct dial to b fails

		_, err := a.Connect(ctx, b.ID())
		if err == nil {
			t.Fatal("Connect succeeded across a partition")
		}
		if !errors.Is(err, transport.ErrNoRoute) {
			t.Fatalf("Connect err = %v, want the direct dial's ErrNoRoute (the cascade's cause, not a masking ErrUnroutable)", err)
		}
	})
}

// TestRegisterReturnsExistingOnDuplicate: registering a second conn to a peer that
// already has a live edge closes the duplicate and returns the existing edge, not an
// error — every register caller wants "an edge to target", not this particular conn.
func TestRegisterReturnsExistingOnDuplicate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))

		a := spawn(t, ctx, hub, 1)
		b := spawn(t, ctx, hub, 2)

		first := dialEdge(t, ctx, a, b)
		dup, err := a.t.Dial(ctx, b.ID(), b.addr)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}

		got, err := a.register(dup, 0, time.Now())
		if err != nil {
			t.Fatalf("register(duplicate) = %v, want the existing edge", err)
		}
		if got != first {
			t.Fatal("register(duplicate) did not return the already-registered edge")
		}
	})
}
