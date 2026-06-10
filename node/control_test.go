package node

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/udisondev/nodenet/nat"
	"github.com/udisondev/nodenet/routing"
	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/transport/mem"
)

// dialEdge dials from->to and registers the outgoing edge, returning the dialer's
// Conn so a test can inject control frames over it.
func dialEdge(t *testing.T, ctx context.Context, from, to *testNode) transport.Conn {
	t.Helper()
	conn, err := from.t.Dial(ctx, to.ID(), to.addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if err := from.e.AddEdge(conn, true, 0, time.Now()); err != nil {
		t.Fatalf("AddEdge: %v", err)
	}
	return conn
}

// sendControl encodes a frame with enc into a pooled packet and sends it on conn
// (borrow-Send, so the caller Releases). It is how a test injects a control frame.
func sendControl(t *testing.T, conn transport.Conn, enc func([]byte) (int, error)) {
	t.Helper()
	p := transport.Get()
	defer p.Release()
	w, err := enc(p.Buf())
	if err != nil {
		t.Fatalf("encode control frame: %v", err)
	}
	p.SetLen(w)
	if err := conn.Send(p); err != nil {
		t.Fatalf("Send control frame: %v", err)
	}
}

// TestControlPingPongReflexive: A pings neighbours over live edges; each answers with a
// pong echoing the address it saw A at. Fewer than a quorum of corroborating reports is
// not trusted; once a quorum of distinct neighbours agree on the same address A confirms
// it as its reflexive address. (Over the in-memory transport the reports carry no subnet,
// so confirmation falls back to a plain distinct-reporter quorum.)
func TestControlPingPongReflexive(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))

		a := spawn(t, ctx, hub, 1)
		neighbours := []*testNode{spawn(t, ctx, hub, 2), spawn(t, ctx, hub, 3), spawn(t, ctx, hub, 4)}

		// Ping the first quorum-1 neighbours: still short of confirmation.
		for _, nb := range neighbours[:nat.Quorum-1] {
			sendControl(t, dialEdge(t, ctx, a, nb), routing.EncodePingFrame)
		}
		synctest.Wait()
		if got := a.Reflexive(); got != (transport.Addr{}) {
			t.Fatalf("reflexive = %v below quorum, want unconfirmed", got)
		}

		// The quorum-th corroborating report confirms.
		sendControl(t, dialEdge(t, ctx, a, neighbours[nat.Quorum-1]), routing.EncodePingFrame)
		synctest.Wait()
		if got := a.Reflexive(); got != a.addr {
			t.Fatalf("reflexive = %v, want %v (what the neighbours saw A at)", got, a.addr)
		}
	})
}

// TestControlSiblingsExchange: A asks B for its sibling set over a NAT edge (only A
// dialed); B answers straight back over that bidirectional edge, and A learns B —
// with B's address — into its knowledge table.
func TestControlSiblingsExchange(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))

		a := spawn(t, ctx, hub, 1)
		b := spawn(t, ctx, hub, 2)
		conn := dialEdge(t, ctx, a, b)

		// A's request carries a correlation nonce it remembers; B echoes it in the answer,
		// so A's solicitation gate accepts the contacts. (The real siblingExchange registers
		// the nonce; here we register it by hand since the request is injected directly.)
		nonce := [routing.LookupNonceLen]byte{0x5e, 0x71}
		solicit(a.Node, nonce)
		sendControl(t, conn, func(buf []byte) (int, error) { return routing.EncodeSiblingsFrame(buf, nonce) })
		synctest.Wait()

		c, ok := a.Knowledge().Get(b.ID())
		if !ok {
			t.Fatal("A did not learn B from the sibling-set exchange")
		}
		if len(c.Addrs) == 0 || c.Addrs[0] != b.addr {
			t.Fatalf("learned B without its address: %+v", c)
		}
	})
}

// TestControlLookupRouted: A looks up an ID nearest B; B is the greedy terminal and
// answers with the neighbours it knows near that ID (including a contact C), routed
// back to A. A learns C. Edges are mutual so B can route the response home.
func TestControlLookupRouted(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))

		a := spawn(t, ctx, hub, 1)
		b := spawn(t, ctx, hub, 2)
		dialEdge(t, ctx, a, b) // a -> b
		dialEdge(t, ctx, b, a) // b -> a, so b can route the response back

		// C sits one bit from B, so B (not A) is the greedy terminal for a lookup of C.
		cID := b.ID()
		cID[len(cID)-1] ^= 1
		cAddr := transport.Addr{Net: "mem", Endpoint: "c-node"}
		b.Knowledge().Observe(routing.Contact{ID: cID, Addrs: []transport.Addr{cAddr}}, time.Now())

		conn, _ := a.e.Conn(b.ID())
		// The lookup carries a correlation nonce A remembers, so A accepts the routed
		// neighbours answer B sends back (the real lookupTowards registers it; here we both
		// build the request by hand and register the nonce).
		nonce := [routing.LookupNonceLen]byte{0x4c}
		solicit(a.Node, nonce)
		msg := routing.Msg{Target: cID, TTL: routing.MaxHops, EdPub: a.edPub, Payload: nonce[:]}
		routing.SignMsg(a.id, routing.TypeLookup, &msg, time.Now())
		sendControl(t, conn, func(buf []byte) (int, error) { return routing.EncodeLookupFrame(buf, &msg) })
		synctest.Wait()

		if _, ok := a.Knowledge().Get(cID); !ok {
			t.Fatal("A did not learn C through the routed lookup response")
		}
	})
}

// TestControlLeaveRemovesEdge: B announces a graceful leave over its edge to A, and
// A proactively drops the edge instead of waiting for a timeout.
func TestControlLeaveRemovesEdge(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))

		a := spawn(t, ctx, hub, 1)
		b := spawn(t, ctx, hub, 2)
		dialEdge(t, ctx, a, b)           // a -> b: A holds an edge to B
		connBA := dialEdge(t, ctx, b, a) // b -> a: the edge B leaves over

		if _, ok := a.e.Conn(b.ID()); !ok {
			t.Fatal("A is missing its edge to B before the leave")
		}
		sendControl(t, connBA, routing.EncodeLeaveFrame)
		synctest.Wait()

		if _, ok := a.e.Conn(b.ID()); ok {
			t.Fatal("A kept the edge after B's graceful leave")
		}
	})
}
