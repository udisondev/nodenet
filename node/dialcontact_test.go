package node

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/nat"
	"github.com/udisondev/nodenet/routing"
	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/transport/mem"
)

// TestStrategyForCaps: a public anchor is dialed directly only (nothing to punch or
// relay), every other contact gets the full escalation ceiling.
func TestStrategyForCaps(t *testing.T) {
	cases := []struct {
		caps routing.Capability
		want nat.Strategy
	}{
		{routing.PublicAnchor, nat.Direct},
		{routing.PublicAnchor | routing.CanRelay, nat.Direct},
		{0, nat.Relay},
		{routing.CanRelay, nat.Relay},
	}
	for _, c := range cases {
		if got := strategyForCaps(c.caps); got != c.want {
			t.Errorf("strategyForCaps(%v) = %v, want %v", c.caps, got, c.want)
		}
	}
}

// TestDialContactReturnsRawEdge: the maintenance cascade returns a raw, unregistered
// edge — the maintenance loop owns the edge-table write — so dialContact itself adds
// nothing to the table; registering it afterwards does.
func TestDialContactReturnsRawEdge(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))

		a := spawn(t, ctx, hub, 1)
		b := spawn(t, ctx, hub, 2)

		// A capless contact gets the full Relay escalation ceiling; on a real NAT that
		// would matter, but on mem the direct dial succeeds at once and the punch/relay
		// stages are never reached.
		conn, err := a.dialContact(ctx, dialTask{id: b.ID(), addr: b.addr})
		if err != nil {
			t.Fatalf("dialContact: %v", err)
		}
		if conn == nil || conn.Remote() != b.ID() {
			t.Fatalf("dialContact returned conn = %v, want an edge to B", conn)
		}
		if _, ok := a.e.Conn(b.ID()); ok {
			t.Fatal("dialContact registered the edge; it must return it raw for the loop to register")
		}

		// register is the step the maintenance loop runs on the outcome: it adds the
		// edge to the table after the admission-PoW check.
		if _, err := a.register(conn, 0, time.Now()); err != nil {
			t.Fatalf("register: %v", err)
		}
		if _, ok := a.e.Conn(b.ID()); !ok {
			t.Fatal("register did not add the outgoing edge to B")
		}
	})
}

// TestDialContactDegradesToDirectError: with no Puncher/Relayer (the in-memory
// transport), the punch and relay stages are no-ops, so an unreachable contact surfaces
// the direct dial's own error (ErrNoRoute) rather than the stages' ErrUnsupported.
func TestDialContactDegradesToDirectError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))

		a := spawn(t, ctx, hub, 1)
		ghost := identity.FromSeed(seedFor(99)).ID()

		conn, err := a.dialContact(ctx, dialTask{
			id:   ghost,
			addr: transport.Addr{Net: "mem", Endpoint: "ghost"},
		})
		if conn != nil {
			t.Fatal("dialContact returned a conn for an unreachable contact")
		}
		if !errors.Is(err, transport.ErrNoRoute) {
			t.Fatalf("dialContact err = %v, want ErrNoRoute (punch/relay must not mask it)", err)
		}
	})
}
