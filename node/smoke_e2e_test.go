//go:build e2e_real

// This is a smoke test of the whole stack over the production QUIC transport on real
// loopback UDP sockets, under real time. Two things are exercised:
//
//   - TestSmokeTopologies stands up small overlays in a range of bootstrap shapes (an
//     interconnected core, a single hub, a ring, a chain, two clusters joined by one
//     bridge, a larger mesh), lets the maintenance loop dial and converge, then checks
//     that every node can ROUTE a message to every other node. Convergence from a
//     merely-connected seed graph (not a pre-wired clique) is the property under test:
//     the overlay must gossip itself complete, and most deliveries are multi-hop.
//
//   - TestSmokeDirectChannel exercises the other communication mode: a DIRECT
//     peer-to-peer channel. Two nodes that are not directly linked discover each other
//     through the overlay (rendezvous) and then open a direct QUIC edge straight to each
//     other's socket — no relay, no intermediate hop — and exchange data over it.
//
// Both are gated behind the e2e_real build tag and excluded from the default
// `go test ./...`. Run them with:
//
//	go test -tags e2e_real -run TestSmoke ./node -v
package node

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/routing"
	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/transport/quic"
)

// smokeMaintenance settles the cluster within a few seconds of real time: fast keepalive
// and frequent self-lookup / sibling-exchange so routing tables converge quickly, with
// reaping far enough out that healthy edges are never torn down mid-test.
func smokeMaintenance() Maintenance {
	return Maintenance{
		Tick:             20 * time.Millisecond,
		KeepaliveSibling: 200 * time.Millisecond,
		KeepaliveFinger:  200 * time.Millisecond,
		DeadSibling:      30 * time.Second,
		DeadFinger:       30 * time.Second,
		SelfLookup:       400 * time.Millisecond,
		SiblingExchange:  400 * time.Millisecond,
		DialTimeout:      3 * time.Second,
		BackoffBase:      100 * time.Millisecond,
		BackoffMax:       2 * time.Second,
		Dialers:          4,
	}
}

// smokeNode is a running node plus the address peers dial it at and, per originator, the
// last payload it received (filled by its delivery drain goroutine).
type smokeNode struct {
	*Node
	addr transport.Addr

	mu   sync.Mutex
	recv map[kad.ID][]byte
}

// contact is how another node bootstraps to this one: NodeID (the overlay authenticates
// against it) plus the loopback address, tagged as a stable entry point.
func (s *smokeNode) contact() routing.Contact {
	return routing.Contact{
		ID:    s.ID(),
		Caps:  routing.PublicAnchor,
		Addrs: []transport.Addr{s.addr},
	}
}

// spawnSmoke binds a real loopback QUIC socket under a fresh identity and builds a node
// with the given options. It does NOT start the loop yet (the caller seeds bootstrap
// contacts first); start it with start.
func spawnSmoke(t *testing.T, seed uint64, opts ...Option) *smokeNode {
	t.Helper()
	id := identity.FromSeed(seedFor(seed))
	tr, err := quic.Listen(id, "127.0.0.1:0", quic.WithHandshakeTimeout(3*time.Second))
	if err != nil {
		t.Fatalf("listen (seed %d): %v", seed, err)
	}
	t.Cleanup(func() { tr.Close() })
	n := New(id, tr, opts...)
	return &smokeNode{Node: n, addr: tr.LocalAddr(), recv: make(map[kad.ID][]byte)}
}

// wireEdge opens an outgoing edge from->to and registers it, the way the maintenance
// dialer would once it had the contact. Used to hand-wire a static topology with
// maintenance off. The reverse direction is learned by `to` on the first frame `from`
// sends.
func wireEdge(t *testing.T, ctx context.Context, from, to *smokeNode) {
	t.Helper()
	conn, err := from.t.Dial(ctx, to.ID(), to.addr)
	if err != nil {
		t.Fatalf("link %s->%s dial: %v", short(from.ID()), short(to.ID()), err)
	}
	if err := from.e.AddEdge(conn, true, 0, time.Now()); err != nil {
		t.Fatalf("link %s->%s add edge: %v", short(from.ID()), short(to.ID()), err)
	}
}

// start runs the dispatch loop and drains deliveries, recording each message's payload
// keyed by originator so the test can confirm reachability and inspect what arrived.
// The drain selects on ctx so it ends with the node — Deliveries() is never closed, and
// a goroutine parked on it would pile up across the suite's many topologies.
func (s *smokeNode) start(ctx context.Context) {
	go s.Run(ctx)
	go func() {
		for {
			select {
			case msg, ok := <-s.Deliveries():
				if !ok {
					return
				}
				s.mu.Lock()
				s.recv[msg.Originator] = append([]byte(nil), msg.Payload...)
				s.mu.Unlock()
			case <-ctx.Done():
				return
			}
		}
	}()
}

// missing returns which of want it has not yet received a message from.
func (s *smokeNode) missing(want []kad.ID) []kad.ID {
	s.mu.Lock()
	defer s.mu.Unlock()
	var m []kad.ID
	for _, id := range want {
		if s.recv[id] == nil {
			m = append(m, id)
		}
	}
	return m
}

// reset forgets all received messages, so a later wait observes only fresh deliveries.
func (s *smokeNode) reset() {
	s.mu.Lock()
	s.recv = make(map[kad.ID][]byte)
	s.mu.Unlock()
}

// payloadFrom returns the last payload received from id, or nil.
func (s *smokeNode) payloadFrom(id kad.ID) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recv[id]
}

// topology describes one bootstrap shape: how many nodes, and which contacts each node
// is seeded with. wire(i, nodes) returns the bootstrap contacts for node i, given every
// node (so it can reference addresses). The seed graph it induces must be connected, or
// the overlay cannot converge to all-to-all by design.
type topology struct {
	name string
	n    int
	wire func(i int, nodes []*smokeNode) []routing.Contact
}

// meshCore is the interconnected-core topology, reused by both tests: nodes 0..b-1 are
// bootstraps in a full mesh; each regular (i>=b) enters through a DIFFERENT pair of
// bootstraps, so the cluster is not funnelled through one entry point.
func meshCore(n, b int) topology {
	return topology{name: "mesh-core", n: n, wire: func(i int, nodes []*smokeNode) []routing.Contact {
		if i < b {
			var cs []routing.Contact
			for j := 0; j < b; j++ {
				if j != i {
					cs = append(cs, nodes[j].contact())
				}
			}
			return cs
		}
		k := i - b
		return []routing.Contact{nodes[k%b].contact(), nodes[(k+1)%b].contact()}
	}}
}

func TestSmokeTopologies(t *testing.T) {
	topos := []topology{
		meshCore(8, 3),

		// Star: one hub (node 0); every other node knows only the hub. The whole overlay
		// has to grow out of a single shared entry point.
		{name: "star", n: 8, wire: func(i int, nodes []*smokeNode) []routing.Contact {
			if i == 0 {
				return nil
			}
			return []routing.Contact{nodes[0].contact()}
		}},

		// Ring: node i knows only its successor (i+1). Minimal connectivity, no designated
		// bootstrap — every node starts with exactly one outbound contact.
		{name: "ring", n: 8, wire: func(i int, nodes []*smokeNode) []routing.Contact {
			return []routing.Contact{nodes[(i+1)%len(nodes)].contact()}
		}},

		// Chain: node i knows only its predecessor (i-1); node 0 knows no one and must be
		// discovered purely through the inbound edge node 1 opens to it.
		{name: "chain", n: 8, wire: func(i int, nodes []*smokeNode) []routing.Contact {
			if i == 0 {
				return nil
			}
			return []routing.Contact{nodes[i-1].contact()}
		}},

		// Two clusters joined by a single bridge: nodes split into two intra-cluster rings;
		// node 0 additionally knows node 5, the lone link that must merge both halves into
		// one overlay.
		{name: "bridged-clusters", n: 10, wire: func(i int, nodes []*smokeNode) []routing.Contact {
			const sz = 5
			base := (i / sz) * sz
			next := base + (i-base+1)%sz
			cs := []routing.Contact{nodes[next].contact()}
			if i == 0 {
				cs = append(cs, nodes[sz].contact()) // the bridge A->B
			}
			return cs
		}},

		// Larger mesh: 4 bootstraps in a full mesh, 16 regulars each entering through a
		// different pair — the scale check.
		meshCore(20, 4),
	}

	for ti, topo := range topos {
		topo := topo
		seedBase := uint64(1000 * (ti + 1)) // disjoint identities per topology
		t.Run(topo.name, func(t *testing.T) {
			converge(t, topo, seedBase)
		})
	}
}

// converge spawns the topology's nodes, wires their bootstrap contacts, starts them, and
// drives all-to-all delivery until everyone has heard from everyone (failing on a
// deadline). It returns the running nodes so a caller can drive further scenarios on the
// settled overlay.
func converge(t *testing.T, topo topology, seedBase uint64) []*smokeNode {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	nodes := make([]*smokeNode, topo.n)
	for i := range nodes {
		nodes[i] = spawnSmoke(t, seedBase+uint64(i), WithMaintenance(smokeMaintenance()))
	}

	byID := make(map[kad.ID]*smokeNode, topo.n)
	allIDs := make([]kad.ID, topo.n)
	for i, n := range nodes {
		byID[n.ID()] = n
		allIDs[i] = n.ID()
	}

	for i := range nodes {
		nodes[i].Bootstrap(topo.wire(i, nodes))
	}
	for _, n := range nodes {
		n.start(ctx)
	}

	totalPairs := topo.n * (topo.n - 1)
	t.Logf("%s: %d nodes, converging toward %d directed pairs...", topo.name, topo.n, totalPairs)

	// Every node sends to every other node, resending only the pairs not yet delivered,
	// until everyone has heard from everyone or the deadline passes. Greedy delivery
	// during early convergence may drop, so resends are expected.
	started := time.Now()
	deadline := started.Add(90 * time.Second)
	var lastMissing int
	for {
		missingPairs := 0
		for _, dst := range nodes {
			want := make([]kad.ID, 0, len(allIDs)-1)
			for _, id := range allIDs {
				if id != dst.ID() {
					want = append(want, id)
				}
			}
			for _, srcID := range dst.missing(want) {
				missingPairs++
				_ = byID[srcID].Send(dst.ID(), []byte("smoke"))
			}
		}
		if missingPairs == 0 {
			lo, hi := edgeDegrees(nodes)
			t.Logf("%s: converged in %s — all %d pairs delivered; live-edge degree min=%d max=%d of %d peers (degree<%d ⇒ those deliveries were multi-hop)",
				topo.name, time.Since(started).Round(time.Millisecond), totalPairs, lo, hi, topo.n-1, topo.n-1)
			return nodes
		}
		if missingPairs != lastMissing {
			t.Logf("%s: %d/%d pairs still undelivered (%s elapsed)", topo.name, missingPairs, totalPairs, time.Since(started).Round(time.Millisecond))
			lastMissing = missingPairs
		}
		if time.Now().After(deadline) {
			reportMissing(t, nodes, allIDs)
			t.Fatalf("%s: %d directed pairs never delivered within deadline", topo.name, missingPairs)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// TestSmokeDirectChannel verifies the DIRECT peer-to-peer mode (Connect), as opposed to
// the overlay routing TestSmokeTopologies exercises. It hand-wires a static line a — c —
// b with maintenance off: a and b are NOT directly linked and reach each other only
// through the coordinator c. a then Connects to b — which discovers b's coordinates via
// rendezvous routed over c, then dials a direct QUIC edge straight to b's socket — and
// the test confirms the edge is direct (its remote endpoint is b's own address, not a
// relay or a hop) and that data flows both ways over it.
//
// Maintenance is off on purpose: with it on, the fill loop would itself dial a->b for the
// connectivity floor, so by the time Connect ran the edge would already exist (and
// Connect would simply return it instead of opening its own). Off, the topology stays
// static and the direct edge is unambiguously the one Connect opened.
func TestSmokeDirectChannel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a := spawnSmoke(t, 60001, WithoutMaintenance())
	c := spawnSmoke(t, 60002, WithoutMaintenance())
	b := spawnSmoke(t, 60003, WithoutMaintenance())
	for _, n := range []*smokeNode{a, c, b} {
		n.start(ctx)
	}
	// a — c — b. The reverse edges (c learns a, b learns c, b learns a) form on the first
	// frame each receives, which is enough for the rendezvous handshake to route.
	wireEdge(t, ctx, a, c)
	wireEdge(t, ctx, c, b)

	if _, linked := a.Edges().Conn(b.ID()); linked {
		t.Fatal("precondition failed: a is already directly linked to b")
	}
	t.Logf("static line %s — %s — %s; a is NOT directly linked to b (reachable via c)",
		short(a.ID()), short(c.ID()), short(b.ID()))

	cctx, ccancel := context.WithTimeout(ctx, 20*time.Second)
	defer ccancel()

	// Connect: rendezvous to discover+verify b's coordinates (routed a->c->b), then open a
	// direct edge.
	conn, err := a.Connect(cctx, b.ID())
	if err != nil {
		t.Fatalf("Connect(%s): %v", short(b.ID()), err)
	}

	// The edge is authenticated to b and goes straight to b's own socket — proof it is a
	// direct peer-to-peer channel, not a relayed or multi-hop path.
	if conn.Remote() != b.ID() {
		t.Fatalf("direct conn remote = %s, want %s", short(conn.Remote()), short(b.ID()))
	}
	if got, want := conn.RemoteAddr().Endpoint, b.addr.Endpoint; got != want {
		t.Fatalf("direct conn endpoint = %q, want b's own socket %q", got, want)
	}
	if _, linked := a.Edges().Conn(b.ID()); !linked {
		t.Fatalf("after Connect, a has no live edge to b")
	}
	t.Logf("Connect opened a DIRECT edge to %s at %s", short(b.ID()), conn.RemoteAddr().Endpoint)

	// Exchange data over the now-direct link, both directions. Clear prior receipts so we
	// observe only these fresh, single-hop deliveries.
	a.reset()
	b.reset()
	const toB, toA = "ping-over-direct", "pong-over-direct"
	if err := a.Send(b.ID(), []byte(toB)); err != nil {
		t.Fatalf("a.Send over direct edge: %v", err)
	}
	waitPayload(t, b, a.ID(), toB)
	// b learned the inbound edge to a on a's first frame, so its reply is direct too.
	if err := b.Send(a.ID(), []byte(toA)); err != nil {
		t.Fatalf("b.Send over direct edge: %v", err)
	}
	waitPayload(t, a, b.ID(), toA)
	t.Logf("two-way data confirmed over the direct edge")
}

// waitPayload blocks until dst has received want from src, or fails after a short
// deadline.
func waitPayload(t *testing.T, dst *smokeNode, src kad.ID, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got := dst.payloadFrom(src); got != nil {
			if string(got) != want {
				t.Fatalf("payload from %s = %q, want %q", short(src), got, want)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("node %s never received %q from %s", short(dst.ID()), want, short(src))
}

// edgeDegrees returns the min and max number of live edges across the cluster. A degree
// below n-1 proves a node is NOT directly connected to every peer, so its deliveries to
// the unconnected peers necessarily traversed intermediate hops (greedy forwarding).
func edgeDegrees(nodes []*smokeNode) (lo, hi int) {
	lo = -1
	for _, n := range nodes {
		d := len(n.Edges().Conns(nil))
		if lo < 0 || d < lo {
			lo = d
		}
		if d > hi {
			hi = d
		}
	}
	return lo, hi
}

// reportMissing logs, per node, which originators it never heard from — the diagnostic
// when convergence fails.
func reportMissing(t *testing.T, all []*smokeNode, allIDs []kad.ID) {
	t.Helper()
	for _, dst := range all {
		want := make([]kad.ID, 0, len(allIDs)-1)
		for _, id := range allIDs {
			if id != dst.ID() {
				want = append(want, id)
			}
		}
		if m := dst.missing(want); len(m) > 0 {
			s := dst.Stats()
			known := dst.Knowledge().Closest(dst.ID(), 32, nil)
			withAddrs := 0
			for _, c := range known {
				if len(c.Addrs) > 0 {
					withAddrs++
				}
			}
			cands := dst.Edges().ReplacementFor(dst.Knowledge(), dst.ID(), 8, nil)
			candAddrs := ""
			for _, c := range cands {
				if len(c.Addrs) > 0 {
					candAddrs += " " + short(c.ID) + "=" + c.Addrs[0].Endpoint
				} else {
					candAddrs += " " + short(c.ID) + "=∅"
				}
			}
			t.Logf("node %s (%s) missing %d: %s | degree=%d out=%d known=%d(addrs=%d) cands=%d:%s stats=%+v",
				short(dst.ID()), dst.addr.Endpoint, len(m), shortList(m), len(dst.Edges().Conns(nil)),
				dst.Edges().Status().OutEdges, len(known), withAddrs, len(cands), candAddrs, s)
		}
	}
}

func short(id kad.ID) string { return id.String()[:8] }

func shortList(ids []kad.ID) string {
	s := ""
	for i, id := range ids {
		if i > 0 {
			s += ","
		}
		s += short(id)
	}
	return fmt.Sprintf("[%s]", s)
}
