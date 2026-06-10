//go:build e2e_nat

// These tests run the full node over the production QUIC transport on the in-process
// NAT emulator (transport/quic/nattest), under real time. They are gated behind the
// e2e_nat build tag and excluded from the default `go test ./...`. Run them with:
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

	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/routing"
	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/transport/quic"
	"github.com/udisondev/nodenet/transport/quic/nattest"
)

// natNode is a running node over a QUIC transport on the fabric, with the address a
// peer would dial it at (a public address, or the internal one for a NAT node).
type natNode struct {
	*Node
	addr transport.Addr
}

// fastMaintenance settles the cluster quickly in real time: keepalive within tens of
// ms so reflexive learning and inbound-edge registration happen fast, with reaping far
// enough out that edges are not torn down during the test.
func fastMaintenance() Maintenance {
	return Maintenance{
		Tick:             10 * time.Millisecond,
		KeepaliveSibling: 15 * time.Millisecond,
		KeepaliveFinger:  15 * time.Millisecond,
		DeadSibling:      10 * time.Second,
		DeadFinger:       10 * time.Second,
		SelfLookup:       5 * time.Second,
		SiblingExchange:  5 * time.Second,
		DialTimeout:      2 * time.Second,
		BackoffBase:      50 * time.Millisecond,
		BackoffMax:       1 * time.Second,
		Dialers:          4,
	}
}

func spawnQUIC(t *testing.T, ctx context.Context, seed byte, pc net.PacketConn, opts ...Option) *natNode {
	t.Helper()
	return spawnQUICTr(t, ctx, seed, pc, nil, opts...)
}

// spawnQUICTr is spawnQUIC with optional extra QUIC transport options (e.g. a relay
// socket factory for a relay volunteer).
func spawnQUICTr(t *testing.T, ctx context.Context, seed byte, pc net.PacketConn, qopts []quic.Option, opts ...Option) *natNode {
	t.Helper()
	id := identity.FromSeed(seedFor(uint64(seed)))
	qopts = append([]quic.Option{quic.WithHandshakeTimeout(2 * time.Second)}, qopts...)
	tr, err := quic.ListenPacketConn(id, pc, qopts...)
	if err != nil {
		t.Fatalf("ListenPacketConn(seed %d): %v", seed, err)
	}
	n := New(id, tr, opts...)
	nctx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	go n.Run(nctx)
	return &natNode{Node: n, addr: tr.LocalAddr()}
}

// dialReg opens an outgoing edge from->to and registers it, the way the maintenance
// dialer would once it had the contact.
func dialReg(t *testing.T, ctx context.Context, from, to *natNode) {
	t.Helper()
	conn, err := from.t.Dial(ctx, to.ID(), to.addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if err := from.e.AddEdge(conn, true, 0, time.Now()); err != nil {
		t.Fatalf("AddEdge: %v", err)
	}
}

// waitReflexive blocks until n has a confirmed reflexive address or the deadline, so a
// hole-punch test does not start before the node knows where peers can reach it.
func waitReflexive(t *testing.T, n *natNode, within time.Duration) transport.Addr {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if r := n.Reflexive(); r != (transport.Addr{}) {
			return r
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("node %v never confirmed a reflexive address", n.ID())
	return transport.Addr{}
}

// TestHolePunchAcrossRestrictedCones is the milestone e2e: two nodes behind separate
// restricted-cone NATs, each with live edges to two public coordinators, open a DIRECT
// edge by hole-punching — the Connect/Ack signalling routed through a coordinator (over
// the inbound edges the NAT nodes opened to it), then a simultaneous punch and dial. A
// frame then flows over the direct edge, never touching a coordinator.
func TestHolePunchAcrossRestrictedCones(t *testing.T) {
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

	// Three public coordinators in distinct /24s; two NAT nodes behind separate cone
	// NATs. The NAT nodes derive subnets from real addresses, so reflexive confirmation
	// requires a subnet-diverse quorum of reports — three coordinators across three /24s.
	c1 := spawnQUIC(t, ctx, 1, mk("100.0.0.1:9000"))
	c2 := spawnQUIC(t, ctx, 2, mk("101.0.0.1:9000"))
	c3 := spawnQUIC(t, ctx, 130, mk("102.0.0.1:9000"))
	a := spawnQUIC(t, ctx, 10, mkNAT("10.0.1.2:1111", "200.0.0.1"), WithMaintenance(fastMaintenance()), WithSubnetFunc(routing.SubnetFromHostPort))
	b := spawnQUIC(t, ctx, 20, mkNAT("10.0.2.2:2222", "200.0.0.2"), WithMaintenance(fastMaintenance()), WithSubnetFunc(routing.SubnetFromHostPort))

	// Each NAT node holds edges to all three coordinators: enough for routing both ways
	// and for a subnet-diverse reflexive quorum.
	for _, c := range []*natNode{c1, c2, c3} {
		dialReg(t, ctx, a, c)
		dialReg(t, ctx, b, c)
	}

	// Let keepalive flow so reflexive is confirmed and the coordinators register their
	// inbound edges to A and B (so they can relay the Connect/Ack).
	waitReflexive(t, a, 3*time.Second)
	waitReflexive(t, b, 3*time.Second)
	time.Sleep(200 * time.Millisecond)

	pctx, pcancel := context.WithTimeout(ctx, 8*time.Second)
	defer pcancel()
	conn, err := a.HolePunch(pctx, b.ID(), nil)
	if err != nil {
		t.Fatalf("HolePunch A->B across restricted cones: %v", err)
	}
	if conn.Remote() != b.ID() {
		t.Fatalf("punched edge Remote = %v, want B %v", conn.Remote(), b.ID())
	}
	if _, ok := a.e.Conn(b.ID()); !ok {
		t.Fatal("A did not register the punched edge to B")
	}

	// With a direct edge to B, an overlay message to B routes straight over it (B is
	// the closest live edge to itself) and B delivers it — end-to-end over the punch.
	if err := a.Send(b.ID(), []byte("direct")); err != nil {
		t.Fatalf("Send to B over the punched edge: %v", err)
	}
	select {
	case got := <-b.Deliveries():
		if string(got.Payload) != "direct" {
			t.Fatalf("B delivered %q, want direct", got.Payload)
		}
	case <-pctx.Done():
		t.Fatal("B delivered nothing over the punched edge")
	}
}

// TestConnectRendezvousThenPunch exercises the full rendezvous → direct-channel handoff:
// A.Connect(B) discovers and verifies B's coordinates via rendezvous, then — B being
// behind NAT — hole-punches a direct edge. A then routes a message to B over it.
func TestConnectRendezvousThenPunch(t *testing.T) {
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

	c1 := spawnQUIC(t, ctx, 3, mk("100.0.0.3:9000"))
	c2 := spawnQUIC(t, ctx, 4, mk("101.0.0.3:9000"))
	c3 := spawnQUIC(t, ctx, 140, mk("102.0.0.3:9000"))
	a := spawnQUIC(t, ctx, 30, mkNAT("10.0.3.2:1111", "200.0.0.3"), WithMaintenance(fastMaintenance()), WithSubnetFunc(routing.SubnetFromHostPort))
	b := spawnQUIC(t, ctx, 40, mkNAT("10.0.4.2:2222", "200.0.0.4"), WithMaintenance(fastMaintenance()), WithSubnetFunc(routing.SubnetFromHostPort))

	for _, c := range []*natNode{c1, c2, c3} {
		dialReg(t, ctx, a, c)
		dialReg(t, ctx, b, c)
	}

	waitReflexive(t, a, 3*time.Second)
	waitReflexive(t, b, 3*time.Second)
	time.Sleep(200 * time.Millisecond)

	cctx, ccancel := context.WithTimeout(ctx, 10*time.Second)
	defer ccancel()
	conn, err := a.Connect(cctx, b.ID())
	if err != nil {
		t.Fatalf("Connect A->B: %v", err)
	}
	if conn.Remote() != b.ID() {
		t.Fatalf("connected edge Remote = %v, want B %v", conn.Remote(), b.ID())
	}

	if err := a.Send(b.ID(), []byte("hello-b")); err != nil {
		t.Fatalf("Send to B after Connect: %v", err)
	}
	select {
	case got := <-b.Deliveries():
		if string(got.Payload) != "hello-b" {
			t.Fatalf("B delivered %q, want hello-b", got.Payload)
		}
	case <-cctx.Done():
		t.Fatal("B delivered nothing after Connect")
	}
}

// coneTTL is a cone NAT whose mapping idles out after ttl — short, so a keepalive test
// can show a mapping dying (or being kept alive) within a second.
func coneTTL(ttl time.Duration, extIP string) nattest.NAT {
	n := nattest.RestrictedConeNAT(extIP)
	n.TTL = ttl
	return n
}

// registerBack makes c learn an inbound edge to a by routing one message a->c, so c can
// later send back to the NAT node a.
func registerBack(t *testing.T, ctx context.Context, a, c *natNode) {
	t.Helper()
	if err := a.Send(c.ID(), []byte("reg")); err != nil {
		t.Fatalf("register Send: %v", err)
	}
	select {
	case <-c.Deliveries():
	case <-time.After(2 * time.Second):
		t.Fatal("coordinator did not receive the registration message")
	}
}

// TestNATMappingExpiresWithoutKeepalive: with no keepalive, a NAT node's mapping idles
// out, and the coordinator can no longer reach it over the edge it opened. This is the
// failure the keepalive in the next test prevents.
func TestNATMappingExpiresWithoutKeepalive(t *testing.T) {
	f := nattest.NewFabric()
	cPC, err := f.Public("100.0.0.8:9000")
	if err != nil {
		t.Fatalf("Public: %v", err)
	}
	aPC, err := f.BehindNAT("10.0.7.2:1111", coneTTL(300*time.Millisecond, "200.0.0.7"))
	if err != nil {
		t.Fatalf("BehindNAT: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := spawnQUIC(t, ctx, 8, cPC)                        // coordinator, no maintenance
	a := spawnQUIC(t, ctx, 70, aPC, WithoutMaintenance()) // NAT node, NO keepalive
	dialReg(t, ctx, a, c)
	registerBack(t, ctx, a, c)

	time.Sleep(600 * time.Millisecond) // let A's mapping idle out

	if err := c.Send(a.ID(), []byte("after-expiry")); err != nil {
		t.Fatalf("c.Send: %v", err)
	}
	select {
	case <-a.Deliveries():
		t.Fatal("A received traffic after its NAT mapping should have expired")
	case <-time.After(500 * time.Millisecond):
		// expected: the mapping is gone, the datagram is dropped
	}
}

// TestNATKeepaliveHoldsMapping: with the maintenance keepalive pinging faster than the
// NAT mapping's idle timeout, the mapping stays open and the coordinator keeps reaching
// the NAT node well past when an unkept mapping would have died.
func TestNATKeepaliveHoldsMapping(t *testing.T) {
	f := nattest.NewFabric()
	cPC, err := f.Public("100.0.0.9:9000")
	if err != nil {
		t.Fatalf("Public: %v", err)
	}
	aPC, err := f.BehindNAT("10.0.8.2:1111", coneTTL(300*time.Millisecond, "200.0.0.8"))
	if err != nil {
		t.Fatalf("BehindNAT: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := spawnQUIC(t, ctx, 9, cPC)
	a := spawnQUIC(t, ctx, 80, aPC, WithMaintenance(fastMaintenance())) // keepalive ON
	dialReg(t, ctx, a, c)
	registerBack(t, ctx, a, c)

	time.Sleep(800 * time.Millisecond) // longer than the mapping TTL; keepalive keeps it open

	if err := c.Send(a.ID(), []byte("still-here")); err != nil {
		t.Fatalf("c.Send: %v", err)
	}
	select {
	case got := <-a.Deliveries():
		if string(got.Payload) != "still-here" {
			t.Fatalf("A delivered %q, want still-here", got.Payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("A unreachable despite keepalive keeping its NAT mapping open")
	}
}

// TestRelayConnectsSymmetricNATs is the relay e2e: two nodes behind symmetric NATs —
// which no hole-punch can open — connect through a public volunteer relay. A.Connect(B)
// rendezvous-verifies B, skips the punch (its own NAT is symmetric), and tunnels a QUIC
// connection through the relay, which forwards only ciphertext. A message then flows.
func TestRelayConnectsSymmetricNATs(t *testing.T) {
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

	// The relay's allocation sockets are fresh public fabric endpoints.
	var allocN int32
	relayFactory := func() (net.PacketConn, error) {
		n := atomic.AddInt32(&allocN, 1)
		return f.Public(fmt.Sprintf("150.0.0.1:%d", 50000+n))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c1 := spawnQUIC(t, ctx, 5, mk("100.0.0.5:9000"))
	c2 := spawnQUIC(t, ctx, 6, mk("100.0.0.6:9000"))
	r := spawnQUICTr(t, ctx, 7, mk("100.0.0.7:9000"), []quic.Option{quic.WithRelaySocketFactory(relayFactory)}, WithRelay())
	a := spawnQUIC(t, ctx, 50, mkSym("10.0.5.2:1111", "200.0.0.5"), WithMaintenance(fastMaintenance()))
	b := spawnQUIC(t, ctx, 60, mkSym("10.0.6.2:2222", "200.0.0.6"), WithMaintenance(fastMaintenance()))

	// A and B hold edges to the coordinators (for routing/rendezvous) and to the relay.
	for _, peer := range []*natNode{c1, c2, r} {
		dialReg(t, ctx, a, peer)
		dialReg(t, ctx, b, peer)
	}
	// A and B learn the relay's CanRelay capability (a neighbours exchange would carry
	// this; the test seeds it directly).
	relayContact := routing.Contact{ID: r.ID(), Caps: routing.CanRelay, Addrs: []transport.Addr{r.addr}}
	a.Bootstrap([]routing.Contact{relayContact})
	b.Bootstrap([]routing.Contact{relayContact})

	// Let keepalive flow so the coordinators and relay register inbound edges to A and B
	// (needed to route rendezvous and to bind the callee) and both learn they are
	// symmetric — polled with a deadline rather than slept for, so a slow machine waits
	// instead of flaking.
	waitReflexiveSymmetric(t, a, 3*time.Second)
	waitReflexiveSymmetric(t, b, 3*time.Second)

	cctx, ccancel := context.WithTimeout(ctx, 12*time.Second)
	defer ccancel()
	conn, err := a.Connect(cctx, b.ID())
	if err != nil {
		t.Fatalf("Connect A->B via relay: %v", err)
	}
	if conn.Remote() != b.ID() {
		t.Fatalf("relayed edge Remote = %v, want B %v", conn.Remote(), b.ID())
	}

	if err := a.Send(b.ID(), []byte("relayed")); err != nil {
		t.Fatalf("Send to B over relay: %v", err)
	}
	select {
	case got := <-b.Deliveries():
		if string(got.Payload) != "relayed" {
			t.Fatalf("B delivered %q, want relayed", got.Payload)
		}
	case <-cctx.Done():
		t.Fatal("B delivered nothing over the relay")
	}
}
