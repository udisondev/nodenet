package routing

import (
	"fmt"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/transport"
)

// BenchmarkKnowledgeObserveRefresh measures the per-passing-packet path: an
// Observe of an already-known contact, which refreshes last-seen and reorders the
// bucket in place. Target: 0 allocs/op.
func BenchmarkKnowledgeObserveRefresh(b *testing.B) {
	var self kad.ID
	k := NewKnowledge(self, nil, 0)
	c := contactInBucket(self, 10, 1)
	k.Observe(c, t0)
	b.ReportAllocs()
	for b.Loop() {
		k.Observe(c, t0)
	}
}

// BenchmarkKnowledgeObserveRefreshSameAddrs measures the address-carrying refresh
// in its steady state: neighbours-learning and sibling-exchange re-deliver a
// contact's unchanged addresses every round, and the already-owned stored copy
// must not be re-cloned. Target: 0 allocs/op.
func BenchmarkKnowledgeObserveRefreshSameAddrs(b *testing.B) {
	var self kad.ID
	k := NewKnowledge(self, nil, 0)
	c := contactInBucket(self, 10, 1)
	c.Addrs = []transport.Addr{{Net: "quic", Endpoint: "192.0.2.7:443"}}
	k.Observe(c, t0)
	b.ReportAllocs()
	for b.Loop() {
		k.Observe(c, t0)
	}
}

// BenchmarkKnowledgeClosest measures the candidate-selection path that feeds
// greedy routing. With a pre-sized buffer it must not allocate. Target: 0
// allocs/op.
func BenchmarkKnowledgeClosest(b *testing.B) {
	self := kad.ID{0xff}
	k := NewKnowledge(self, nil, 0)
	rng := rand.New(rand.NewPCG(42, 1337))
	for range 1000 {
		k.Observe(Contact{ID: randID(rng)}, t0)
	}
	target := randID(rng)
	buf := make([]Contact, 0, 16)
	b.ReportAllocs()
	for b.Loop() {
		k.Closest(target, 16, buf)
	}
}

// randEdges builds a TargetEdges-sized live-edge set with random NodeIDs, added in
// random order. A real edge table is filled in time-of-connection order, which is
// uncorrelated with the XOR-distance to any later lookup target — so random IDs
// (not sorted-by-bucket) keep the selection's insertion-sort at its representative
// average case rather than an artificial best/worst for one fixed target.
func randEdges(self kad.ID, rng *rand.Rand) *Edges {
	e := NewEdges(self, nil)
	for range TargetEdges {
		e.AddEdge(fakeConn{id: randID(rng)}, true, 0, t0)
	}
	return e
}

// BenchmarkEdgesClosest measures the next-hop selection that greedy forwarding
// runs on every hop. With a pre-sized buffer it must not allocate. Target: 0
// allocs/op.
func BenchmarkEdgesClosest(b *testing.B) {
	var self kad.ID
	rng := rand.New(rand.NewPCG(42, 1337))
	e := randEdges(self, rng)
	target := randID(rng)
	buf := make([]LiveEdge, 0, 8)
	b.ReportAllocs()
	for b.Loop() {
		e.Closest(target, 8, buf)
	}
}

// BenchmarkEdgesClosestScale measures next-hop selection as the live set grows
// toward its bound (out + InboundCap). Before the CPL bucket index Closest scanned
// the whole set, so ns/op rose roughly linearly with N; the index makes it walk only
// the closeness tiers a next-hop can fall in, so the growth flattens. 0 allocs/op in
// every case (pre-sized buffer).
func BenchmarkEdgesClosestScale(b *testing.B) {
	for _, n := range []int{1, 64, 256, 320} {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			var self kad.ID
			rng := rand.New(rand.NewPCG(42, uint64(n)))
			e := NewEdges(self, nil)
			for range n {
				e.AddEdge(fakeConn{id: randID(rng)}, true, 0, t0)
			}
			target := randID(rng)
			buf := make([]LiveEdge, 0, 8)
			b.ReportAllocs()
			for b.Loop() {
				e.Closest(target, 8, buf)
			}
		})
	}
}

// BenchmarkReclassifyAddRemove measures the role reclassification cost on churn at
// growing live-set sizes. The selection is O(n·Siblings) (was O(n²)), so ns/op grows
// far slower than quadratically as N rises.
func BenchmarkReclassifyAddRemove(b *testing.B) {
	for _, n := range []int{64, 256} {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			var self kad.ID
			rng := rand.New(rand.NewPCG(7, uint64(n)))
			e := NewEdges(self, nil)
			for range n {
				e.AddEdge(fakeConn{id: randID(rng)}, true, 0, t0)
			}
			churn := fakeConn{id: randID(rng)}
			b.ReportAllocs()
			for b.Loop() {
				e.AddEdge(churn, true, 0, t0)
				e.RemoveEdge(churn.Remote())
			}
		})
	}
}

// BenchmarkEncodeMsg / BenchmarkDecodeMsg cover the origination and forwarding
// codec paths. Decode is the hotter one (every received packet); both target 0
// allocs/op — Decode must not let the wire.Reader escape to the heap.
func BenchmarkEncodeMsg(b *testing.B) {
	m := &Msg{Target: fill(1), TTL: 16, EdPub: fill32(2), Avoid: avoidOf(fill(3), fill(4)), Payload: make([]byte, 64)}
	buf := make([]byte, 1<<16)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := EncodeMsg(buf, m); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeMsg(b *testing.B) {
	m := &Msg{Target: fill(1), TTL: 16, EdPub: fill32(2), Avoid: avoidOf(fill(3), fill(4)), Payload: make([]byte, 64)}
	enc := make([]byte, 1<<16)
	n, _ := EncodeMsg(enc, m)
	enc = enc[:n]
	b.ReportAllocs()
	for b.Loop() {
		if _, err := DecodeMsg(enc); err != nil {
			b.Fatal(err)
		}
	}
}

// neighborsBench builds a representative contact list for the control-codec
// benchmarks: a sibling-set-sized batch, each contact with one address.
func neighborsBench() []Contact {
	cs := make([]Contact, Siblings)
	for i := range cs {
		cs[i] = Contact{
			ID:    fill(byte(i + 1)),
			EdPub: fill32(byte(i + 2)),
			XPub:  fill32(byte(i + 3)),
			Caps:  PublicAnchor,
			Addrs: []transport.Addr{{Net: "quic", Endpoint: "192.0.2.7:443"}},
		}
	}
	return cs
}

// BenchmarkEncodeNeighbors / BenchmarkDecodeNeighbors cover the control-traffic
// codec (lookup and sibling-exchange responses). Encode runs into a caller buffer
// and targets 0 allocs/op; Decode necessarily allocates (it owns the contacts'
// strings and slices so a learned contact outlives the buffer) — this measures and
// caps that off-hot-path cost.
func BenchmarkEncodeNeighbors(b *testing.B) {
	cs := neighborsBench()
	buf := make([]byte, neighborsLen(cs))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := EncodeNeighbors(buf, cs); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeNeighbors(b *testing.B) {
	cs := neighborsBench()
	enc := make([]byte, neighborsLen(cs))
	n, _ := EncodeNeighbors(enc, cs)
	enc = enc[:n]
	b.ReportAllocs()
	for b.Loop() {
		if _, err := DecodeNeighbors(enc); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSignMsg / BenchmarkVerifySig cover the envelope-authentication primitives.
// Neither runs on the forwarding hot path — signing happens once per origination,
// verification once at a terminal/amplifying hop — so they do not target 0 allocs/op
// (Ed25519 and the hasher allocate); the benches measure and bound that off-hot-path
// cost. The 64-byte payload is representative of a small control message.
func BenchmarkSignMsg(b *testing.B) {
	id := identity.FromSeed([identity.SeedLen]byte{1, 2, 3})
	var edPub [32]byte
	copy(edPub[:], id.EdPublic())
	m := &Msg{Target: fill(1), TTL: 16, EdPub: edPub, Payload: make([]byte, 64)}
	b.ReportAllocs()
	for b.Loop() {
		SignMsg(id, TypeRoute, m, t0)
	}
}

func BenchmarkVerifySig(b *testing.B) {
	id := identity.FromSeed([identity.SeedLen]byte{1, 2, 3})
	var edPub [32]byte
	copy(edPub[:], id.EdPublic())
	m := &Msg{Target: fill(1), TTL: 16, EdPub: edPub, Payload: make([]byte, 64)}
	SignMsg(id, TypeRoute, m, t0)
	b.ReportAllocs()
	for b.Loop() {
		m.VerifySig(TypeRoute)
	}
}

// BenchmarkAllowControl measures the per-control-frame rate-limit check (a bucket
// refill + token consume under the edge lock). It runs on the control path, not the
// forwarding hot path; with an always-replenished bucket it allocates nothing.
func BenchmarkAllowControl(b *testing.B) {
	var self kad.ID
	e := NewEdges(self, nil)
	id := kad.ID{1}
	e.AddEdge(fakeConn{id: id}, true, 0, t0)
	now := t0
	b.ReportAllocs()
	for b.Loop() {
		now = now.Add(time.Second) // keep the bucket full so the bench measures the steady path
		e.AllowControl(id, now)
	}
}

// BenchmarkAllowForward measures the per-routed-frame rate-limit check charged on the
// forwarding hot path (a bucket refill + token consume under the edge read lock). With an
// always-replenished bucket it must allocate nothing.
func BenchmarkAllowForward(b *testing.B) {
	var self kad.ID
	e := NewEdges(self, nil)
	id := kad.ID{1}
	e.AddEdge(fakeConn{id: id}, true, 0, t0)
	now := t0
	b.ReportAllocs()
	for b.Loop() {
		now = now.Add(time.Second) // keep the bucket full so the bench measures the steady path
		e.AllowForward(id, now)
	}
}

// BenchmarkDecide is the greedy decision run on every forwarded packet: query the
// closest live edges and filter by avoid-set and progress. Target: 0 allocs/op.
func BenchmarkDecide(b *testing.B) {
	var self kad.ID
	rng := rand.New(rand.NewPCG(42, 1337))
	e := randEdges(self, rng)
	m := &Msg{Target: randID(rng), TTL: 16}
	buf := make([]LiveEdge, 0, 8)
	b.ReportAllocs()
	for b.Loop() {
		Decide(self, m, e, buf)
	}
}
