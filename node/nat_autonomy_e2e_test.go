//go:build e2e_nat

// These tests cover the maintenance dialer reaching NAT peers on its own,
// under churn, by escalating Direct → Punch → Relay — not just the on-demand
// node.Connect path. They run over the production QUIC transport on the in-process NAT
// emulator, under real time, gated behind the e2e_nat build tag:
//
//	go test -tags e2e_nat ./node
package node

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/routing"
	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/transport/quic"
	"github.com/udisondev/nodenet/transport/quic/nattest"
)

// waitEdge blocks until from has an outgoing live edge to id, or fails at the deadline.
// It is how an autonomy test waits for the maintenance dialer to raise an edge on its
// own — no Connect/HolePunch call in the test.
func waitEdge(t *testing.T, from *natNode, id kad.ID, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if _, ok := from.e.Conn(id); ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("node %v never opened an edge to %v autonomously", from.ID(), id)
}

// TestMaintenanceAutoPunch: a node behind a restricted-cone NAT, given only a contact
// for a peer behind another cone NAT, opens a direct edge to it on its own — the
// maintenance dialer's direct dial fails (the peer's NAT drops it), so it escalates to a
// hole-punch, all without any explicit Connect/HolePunch call. This is the autonomy that
// makes NAT nodes fill their live set with NAT peers under churn.
func TestMaintenanceAutoPunch(t *testing.T) {
	f := nattest.NewFabric()

	mk := func(addr string) net.PacketConn {
		pc, err := f.Public(addr)
		if err != nil {
			t.Fatalf("Public %s: %v", addr, err)
		}
		return pc
	}
	mkNAT := func(internal, extIP string) net.PacketConn {
		pc, err := f.BehindNAT(internal, nattest.RestrictedConeNAT(extIP))
		if err != nil {
			t.Fatalf("BehindNAT %s: %v", internal, err)
		}
		return pc
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c1 := spawnQUIC(t, ctx, 11, mk("100.0.1.1:9000"))
	c2 := spawnQUIC(t, ctx, 12, mk("101.0.1.1:9000"))
	c3 := spawnQUIC(t, ctx, 150, mk("102.0.1.1:9000"))
	a := spawnQUIC(t, ctx, 110, mkNAT("10.1.1.2:1111", "201.0.0.1"), WithMaintenance(fastMaintenance()), WithSubnetFunc(routing.SubnetFromHostPort))
	b := spawnQUIC(t, ctx, 120, mkNAT("10.1.2.2:2222", "201.0.0.2"), WithMaintenance(fastMaintenance()), WithSubnetFunc(routing.SubnetFromHostPort))

	// Both NAT nodes anchor to the coordinators (distinct /24s): routing both ways + a
	// subnet-diverse reflexive consensus.
	for _, c := range []*natNode{c1, c2, c3} {
		dialReg(t, ctx, a, c)
		dialReg(t, ctx, b, c)
	}

	// Let keepalive settle: reflexive confirmed, and the coordinators register inbound
	// edges to A and B so they can relay the punch signalling.
	bRefl := waitReflexive(t, b, 3*time.Second)
	waitReflexive(t, a, 3*time.Second)
	time.Sleep(300 * time.Millisecond)

	// Now A learns B as a contact (a neighbours exchange would carry this). A direct dial
	// to B's reflexive address fails — B's cone NAT drops a sender it never sent to — so
	// the maintenance dialer must hole-punch. Nothing in the test calls Connect/HolePunch.
	a.Bootstrap([]routing.Contact{{ID: b.ID(), Addrs: []transport.Addr{bRefl}}})

	waitEdge(t, a, b.ID(), 10*time.Second)
	if got := a.e.Status().OutEdges; got < routing.KMin {
		t.Fatalf("A OutEdges = %d, want >= K_min %d", got, routing.KMin)
	}

	// The autonomously-punched edge carries traffic end-to-end.
	sctx, scancel := context.WithTimeout(ctx, 4*time.Second)
	defer scancel()
	if err := a.Send(b.ID(), []byte("auto-punch")); err != nil {
		t.Fatalf("Send over autonomously-punched edge: %v", err)
	}
	select {
	case got := <-b.Deliveries():
		if string(got.Payload) != "auto-punch" {
			t.Fatalf("B delivered %q, want auto-punch", got.Payload)
		}
	case <-sctx.Done():
		t.Fatal("B delivered nothing over the autonomously-punched edge")
	}
}

// TestMaintenanceAutoRelay: two nodes behind symmetric NATs — unpunchable — given a
// contact for each other and a relay volunteer, open an edge through the relay on their
// own. The maintenance dialer's direct dial fails, the punch is skipped (symmetric NAT),
// and it falls through to the relay autonomously. No explicit Connect call.
func TestMaintenanceAutoRelay(t *testing.T) {
	f := nattest.NewFabric()

	mk := func(addr string) net.PacketConn {
		pc, err := f.Public(addr)
		if err != nil {
			t.Fatalf("Public %s: %v", addr, err)
		}
		return pc
	}
	mkSym := func(internal, extIP string) net.PacketConn {
		pc, err := f.BehindNAT(internal, nattest.SymmetricNAT(extIP))
		if err != nil {
			t.Fatalf("BehindNAT %s: %v", internal, err)
		}
		return pc
	}

	var allocN int32
	relayFactory := func() (net.PacketConn, error) {
		n := atomic.AddInt32(&allocN, 1)
		return f.Public(fmt.Sprintf("151.0.0.1:%d", 50000+n))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c1 := spawnQUIC(t, ctx, 15, mk("100.0.2.1:9000"))
	c2 := spawnQUIC(t, ctx, 16, mk("100.0.2.2:9000"))
	r := spawnQUICTr(t, ctx, 17, mk("100.0.2.7:9000"), []quic.Option{quic.WithRelaySocketFactory(relayFactory)}, WithRelay())
	a := spawnQUIC(t, ctx, 150, mkSym("10.2.1.2:1111", "201.0.1.1"), WithMaintenance(fastMaintenance()))
	b := spawnQUIC(t, ctx, 160, mkSym("10.2.2.2:2222", "201.0.1.2"), WithMaintenance(fastMaintenance()))

	// A and B anchor to the coordinators and the relay.
	for _, peer := range []*natNode{c1, c2, r} {
		dialReg(t, ctx, a, peer)
		dialReg(t, ctx, b, peer)
	}
	// A and B learn the relay's CanRelay capability (a neighbours exchange would carry it).
	a.Bootstrap([]routing.Contact{{ID: r.ID(), Caps: routing.CanRelay, Addrs: []transport.Addr{r.addr}}})
	b.Bootstrap([]routing.Contact{{ID: r.ID(), Caps: routing.CanRelay, Addrs: []transport.Addr{r.addr}}})

	// Let keepalive flow so inbound edges register and both learn they are symmetric.
	bRefl := waitReflexiveSymmetric(t, b, 3*time.Second)
	waitReflexiveSymmetric(t, a, 3*time.Second)

	// A learns B as a contact. Direct dial fails (symmetric NAT), punch is skipped, so the
	// dialer falls through to the relay on its own.
	a.Bootstrap([]routing.Contact{{ID: b.ID(), Addrs: []transport.Addr{bRefl}}})

	waitEdge(t, a, b.ID(), 12*time.Second)
	if got := a.e.Status().OutEdges; got < routing.KMin {
		t.Fatalf("A OutEdges = %d, want >= K_min %d", got, routing.KMin)
	}

	sctx, scancel := context.WithTimeout(ctx, 4*time.Second)
	defer scancel()
	if err := a.Send(b.ID(), []byte("auto-relay")); err != nil {
		t.Fatalf("Send over autonomously-relayed edge: %v", err)
	}
	select {
	case got := <-b.Deliveries():
		if string(got.Payload) != "auto-relay" {
			t.Fatalf("B delivered %q, want auto-relay", got.Payload)
		}
	case <-sctx.Done():
		t.Fatal("B delivered nothing over the autonomously-relayed edge")
	}
}

// waitReflexiveSymmetric waits until a symmetric-NAT node has gathered enough reports to
// know it is symmetric, and returns one reported (per-destination) external address —
// good enough to seed a contact, since the actual relay path does not depend on it.
func waitReflexiveSymmetric(t *testing.T, n *natNode, within time.Duration) transport.Addr {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if n.reflexive.Symmetric() {
			return n.addr
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("node %v never detected its symmetric NAT", n.ID())
	return transport.Addr{}
}
