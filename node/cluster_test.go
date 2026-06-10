package node

import (
	"context"
	"sort"
	"testing"
	"testing/synctest"

	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/pow"
	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/transport/mem"
)

// testNode bundles a running Node with the address it registered, so tests can dial
// it to wire edges. cancel stops just this node (its dispatch and maintenance
// loops), so a test can model one node leaving without tearing down the cluster.
type testNode struct {
	*Node
	addr   transport.Addr
	cancel context.CancelFunc
}

// stop cancels this node's loops (triggering its graceful-leave), leaving the rest
// of the cluster running.
func (tn *testNode) stop() { tn.cancel() }

// spawn brings up a node on hub under its own child context and starts its loops.
// Maintenance is OFF by default so a test drives the topology by hand; pass
// WithMaintenance to enable self-upkeep (the churn e2e tests do).
func spawn(t *testing.T, ctx context.Context, hub *mem.Hub, seed uint64, opts ...Option) *testNode {
	t.Helper()
	idn := identity.FromSeed(seedFor(seed))
	a := transport.Addr{Net: "mem", Endpoint: idn.ID().String()}
	tr, err := hub.New(idn.ID(), a)
	if err != nil {
		t.Fatalf("hub.New: %v", err)
	}
	n := New(idn, tr, append([]Option{WithoutMaintenance()}, opts...)...)
	nctx, cancel := context.WithCancel(ctx)
	go n.Run(nctx)
	return &testNode{Node: n, addr: a, cancel: cancel}
}

// link registers an OUTGOING edge a->b (a dials b). Only a learns the edge; b never
// registers an inbound one (there is no Accept) — which is exactly the NAT case the
// overlay relies on: b forwards over a conn it never put in its table. It is dialEdge
// (control_test.go) without the returned conn, kept for call-site brevity.
func link(t *testing.T, ctx context.Context, a, b *testNode) {
	t.Helper()
	dialEdge(t, ctx, a, b)
}

// chainToward links nodes into a greedy-passable line ending at target: it sorts them
// farthest-from-target first and links each to the next, so every hop is strictly
// closer to the target. It returns the source (farthest) node.
func chainToward(t *testing.T, ctx context.Context, target kad.ID, last *testNode, mids []*testNode) *testNode {
	t.Helper()
	sort.Slice(mids, func(i, j int) bool {
		return kad.DistanceCmp(target, mids[i].ID(), mids[j].ID()) > 0
	})
	for i := 0; i+1 < len(mids); i++ {
		link(t, ctx, mids[i], mids[i+1])
	}
	link(t, ctx, mids[len(mids)-1], last)
	return mids[0]
}

// TestClusterDeliversAcrossHops: a packet originated at the farthest node converges
// to R greedily over a multi-hop chain of live edges.
func TestClusterDeliversAcrossHops(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))

		r := spawn(t, ctx, hub, 1)
		mids := make([]*testNode, 0, 5)
		for s := uint64(2); s <= 6; s++ {
			mids = append(mids, spawn(t, ctx, hub, s))
		}
		src := chainToward(t, ctx, r.ID(), r, mids)

		if err := src.Send(r.ID(), []byte("hello R")); err != nil {
			t.Fatalf("Send: %v", err)
		}
		synctest.Wait()

		select {
		case got := <-r.Deliveries():
			if string(got.Payload) != "hello R" {
				t.Errorf("payload = %q, want hello R", got.Payload)
			}
			if got.Originator != src.ID() {
				t.Errorf("Originator = %v, want src %v", got.Originator, src.ID())
			}
		default:
			t.Fatal("R received nothing")
		}
	})
}

// TestClusterNATForward: the middle node b has only an outgoing edge (to R) and never
// registered the inbound edge from a — yet it forwards a's packet to R. This is a NAT
// node acting as a full router over its dialed-out edge.
func TestClusterNATForward(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))

		r := spawn(t, ctx, hub, 1)
		mids := []*testNode{spawn(t, ctx, hub, 2), spawn(t, ctx, hub, 3)}
		a := chainToward(t, ctx, r.ID(), r, mids)
		var b *testNode // the other middle node — the one closer to R
		for _, m := range mids {
			if m != a {
				b = m
			}
		}

		if st := b.e.Status(); st.OutEdges != 1 {
			t.Fatalf("b OutEdges = %d, want 1 (only its dialed-out edge)", st.OutEdges)
		}
		// No traffic has flowed yet, so dialing alone has not created any reverse edge:
		// b registers an inbound edge to a only once a's first frame arrives.
		if _, ok := b.e.Conn(a.ID()); ok {
			t.Fatal("b has an edge to a before any traffic")
		}

		if err := a.Send(r.ID(), []byte("via NAT")); err != nil {
			t.Fatalf("Send: %v", err)
		}
		synctest.Wait()

		select {
		case got := <-r.Deliveries():
			if string(got.Payload) != "via NAT" {
				t.Errorf("payload = %q, want via NAT", got.Payload)
			}
		default:
			t.Fatal("R received nothing — NAT node did not forward")
		}
	})
}

// TestClusterSubPoWDropped: with a non-zero PoW difficulty, an originator whose
// NodeID does not clear the threshold has its packet dropped at the first honest hop,
// so R never receives it.
func TestClusterSubPoWDropped(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))

		// Both middle nodes get sub-threshold identities picked deterministically
		// (seedSatisfying), so whichever chainToward makes the source is guaranteed
		// below dmin — a lucky-seed skip could silently turn this security test off
		// if the ID derivation ever changed.
		const dmin = 8
		rSeed := seedSatisfying(t, dmin, true)
		m1Seed := seedSatisfying(t, dmin, false, rSeed)
		m2Seed := seedSatisfying(t, dmin, false, rSeed, m1Seed)
		r := spawn(t, ctx, hub, rSeed, WithDmin(dmin))
		mids := []*testNode{spawn(t, ctx, hub, m1Seed, WithDmin(dmin)), spawn(t, ctx, hub, m2Seed, WithDmin(dmin))}
		a := chainToward(t, ctx, r.ID(), r, mids)
		if pow.Satisfies(a.ID(), dmin) {
			t.Fatal("precondition broken: the source clears the PoW it must fail")
		}

		if err := a.Send(r.ID(), []byte("sybil")); err != nil {
			t.Fatalf("Send: %v", err)
		}
		synctest.Wait()

		select {
		case <-r.Deliveries():
			t.Fatal("sub-PoW originator was delivered; must be dropped at first hop")
		default:
		}
	})
}

// drainDeliveries counts how many messages are waiting on a node's delivery channel
// (disjoint paths can deliver the same payload more than once).
func drainDeliveries(n *testNode) int {
	count := 0
	for {
		select {
		case <-n.Deliveries():
			count++
		default:
			return count
		}
	}
}

// TestClusterDisjointDelivers: a source fans the request down three disjoint first
// hops; one first hop is killed, yet R still receives via the others — disjoint paths
// as fault tolerance.
func TestClusterDisjointDelivers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))

		r := spawn(t, ctx, hub, 1)
		f := []*testNode{spawn(t, ctx, hub, 2), spawn(t, ctx, hub, 3), spawn(t, ctx, hub, 4)}
		for _, fi := range f {
			link(t, ctx, fi, r) // each first hop has a direct edge to R
		}
		src := spawn(t, ctx, hub, 5)
		for _, fi := range f {
			link(t, ctx, src, fi) // src has 3 edges → 3 disjoint first hops
		}

		f[0].t.Close() // kill one path entirely (src->f0 and f0->r go down)
		synctest.Wait()

		if err := src.Send(r.ID(), []byte("disjoint")); err != nil {
			t.Fatalf("Send: %v", err)
		}
		synctest.Wait()

		if got := drainDeliveries(r); got == 0 {
			t.Fatal("disjoint: R received nothing despite two live paths")
		}
	})
}

// TestClusterLocalRepair: a forwarder's greedy-best edge dies just before it sends;
// it falls back to the next-closest live edge and the packet still reaches R.
func TestClusterLocalRepair(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))

		r := spawn(t, ctx, hub, 1)
		target := r.ID()

		// Three candidates; the farthest from R is the forwarder m, the two closer
		// ones are b0/b1 (both strictly closer than m, so m's greedy picks them).
		cand := []*testNode{spawn(t, ctx, hub, 2), spawn(t, ctx, hub, 3), spawn(t, ctx, hub, 4)}
		sort.Slice(cand, func(i, j int) bool {
			return kad.DistanceCmp(target, cand[i].ID(), cand[j].ID()) > 0
		})
		m := cand[0]
		b := cand[1:]
		for _, bi := range b {
			link(t, ctx, bi, r)
		}
		link(t, ctx, m, b[0])
		link(t, ctx, m, b[1])

		a := spawn(t, ctx, hub, 5)
		link(t, ctx, a, m)

		// Kill m's greedy-best next hop (the b closer to R).
		if kad.DistanceCmp(target, b[0].ID(), b[1].ID()) > 0 {
			b[0], b[1] = b[1], b[0]
		}
		b[0].t.Close()
		synctest.Wait()

		if err := a.Send(target, []byte("repair")); err != nil {
			t.Fatalf("Send: %v", err)
		}
		synctest.Wait()

		if got := drainDeliveries(r); got == 0 {
			t.Fatal("local repair: R got nothing after greedy-best edge died")
		}
		if _, ok := m.e.Conn(b[0].ID()); ok {
			t.Error("forwarder kept the dead edge; local repair should RemoveEdge it")
		}
	})
}
