package routing

import (
	"encoding/binary"
	"math/rand/v2"
	"sync"
	"testing"
	"time"

	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/transport"
)

// fakeConn is a minimal transport.Conn for table tests: it carries an identity and
// an address and does no I/O.
type fakeConn struct {
	id   kad.ID
	addr transport.Addr
}

func (c fakeConn) Remote() kad.ID               { return c.id }
func (c fakeConn) RemoteAddr() transport.Addr   { return c.addr }
func (c fakeConn) Send(*transport.Packet) error { return nil }
func (c fakeConn) Close() error                 { return nil }

func add(t *testing.T, e *Edges, id kad.ID, outgoing bool, caps Capability, endpoint string) {
	t.Helper()
	conn := fakeConn{id: id, addr: transport.Addr{Net: "quic", Endpoint: endpoint}}
	if err := e.AddEdge(conn, outgoing, caps, t0); err != nil {
		t.Fatalf("AddEdge: %v", err)
	}
}

// isSibling reports (white-box) whether the live edge to id is classified into the
// sibling role — the tests' window into reclassify.
func isSibling(e *Edges, id kad.ID) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	ed, ok := e.byID[id]
	return ok && ed.role == roleSibling
}

func TestInboundEdgeCap(t *testing.T) {
	var self kad.ID
	e := NewEdges(self, nil)

	// Fill the inbound cap with peer-initiated edges.
	for i := range InboundCap {
		conn := fakeConn{id: idInBucket(self, 10, i+1)}
		if err := e.AddEdge(conn, false, 0, t0); err != nil {
			t.Fatalf("inbound AddEdge %d: %v", i, err)
		}
	}
	if s := e.Status(); s.OutEdges != 0 {
		t.Fatalf("OutEdges = %d, want 0 (inbound edges are not self-maintained)", s.OutEdges)
	}

	// One more inbound edge is refused.
	over := fakeConn{id: idInBucket(self, 10, InboundCap+1)}
	if err := e.AddEdge(over, false, 0, t0); err != ErrInboundFull {
		t.Fatalf("over-cap inbound err = %v, want ErrInboundFull", err)
	}

	// An outgoing edge is never subject to the inbound cap.
	out := fakeConn{id: idInBucket(self, 11, 1)}
	if err := e.AddEdge(out, true, 0, t0); err != nil {
		t.Fatalf("outgoing AddEdge under inbound cap: %v", err)
	}

	// Dropping an inbound edge frees a slot.
	e.RemoveEdge(idInBucket(self, 10, 1))
	if err := e.AddEdge(over, false, 0, t0); err != nil {
		t.Fatalf("inbound AddEdge after freeing a slot: %v", err)
	}
}

func TestAddRemoveEdge(t *testing.T) {
	var self kad.ID
	e := NewEdges(self, nil)

	// self-edge rejected.
	if err := e.AddEdge(fakeConn{id: self}, true, 0, t0); err != ErrSelfEdge {
		t.Fatalf("self-edge err = %v, want ErrSelfEdge", err)
	}

	a := idInBucket(self, 10, 1)
	add(t, e, a, true, 0, "")
	if _, ok := e.Conn(a); !ok {
		t.Fatal("Conn missing after AddEdge")
	}
	if s := e.Status(); s.OutEdges != 1 {
		t.Fatalf("OutEdges = %d, want 1", s.OutEdges)
	}
	// duplicate rejected.
	if err := e.AddEdge(fakeConn{id: a}, true, 0, t0); err != ErrEdgeExists {
		t.Fatalf("dup err = %v, want ErrEdgeExists", err)
	}

	// inbound edge is tracked but not counted toward the floor.
	b := idInBucket(self, 11, 1)
	add(t, e, b, false, 0, "")
	if _, ok := e.Conn(b); !ok {
		t.Fatal("inbound Conn missing")
	}
	if s := e.Status(); s.OutEdges != 1 {
		t.Fatalf("OutEdges = %d after inbound, want 1", s.OutEdges)
	}

	e.RemoveEdge(a)
	if _, ok := e.Conn(a); ok {
		t.Fatal("Conn present after RemoveEdge")
	}
	if s := e.Status(); s.OutEdges != 0 {
		t.Fatalf("OutEdges = %d after remove, want 0", s.OutEdges)
	}
}

func TestSiblingClassification(t *testing.T) {
	var self kad.ID
	e := NewEdges(self, nil)
	// Add Siblings+4 edges in distinct buckets. Closeness to self grows with the
	// bucket index (longer shared prefix = smaller XOR), so the highest buckets are
	// the siblings.
	const extra = 4
	n := Siblings + extra
	ids := make([]kad.ID, n)
	for i := range n {
		ids[i] = idInBucket(self, 200-i, 0) // bucket 200 (closest) down to 200-(n-1)
		add(t, e, ids[i], true, 0, "")
	}
	// ids[0..Siblings-1] are the closest → siblings; the rest are fingers.
	for i := range Siblings {
		if !isSibling(e, ids[i]) {
			t.Fatalf("ids[%d] (bucket %d) should be a sibling", i, 200-i)
		}
	}
	for i := Siblings; i < n; i++ {
		if isSibling(e, ids[i]) {
			t.Fatalf("ids[%d] (bucket %d) should be a finger", i, 200-i)
		}
	}
}

func TestEdgesClosest(t *testing.T) {
	var self kad.ID
	e := NewEdges(self, nil)
	var ids []kad.ID
	for b := 1; b <= 30; b++ {
		id := idInBucket(self, b, 0)
		add(t, e, id, true, 0, "")
		ids = append(ids, id)
	}
	target := idInBucket(self, 5, 99)
	const n = 6
	got := e.Closest(target, n, make([]LiveEdge, 0, n))
	if len(got) != n {
		t.Fatalf("Closest = %d, want %d", len(got), n)
	}
	for i := 1; i < len(got); i++ {
		if kad.DistanceCmp(target, got[i-1].ID, got[i].ID) > 0 {
			t.Fatalf("not sorted at %d", i)
		}
	}
	inGot := map[kad.ID]bool{}
	for _, le := range got {
		inGot[le.ID] = true
	}
	worst := got[len(got)-1].ID
	for _, id := range ids {
		if inGot[id] {
			continue
		}
		if kad.DistanceCmp(target, id, worst) < 0 {
			t.Fatalf("closer edge %x excluded", id)
		}
	}
}

// TestReclassifyMatchesBruteForce: the O(n·Siblings) sibling selection must mark
// exactly the same edges as the original all-pairs O(n²) rule — the Siblings edges
// closest to self — for any live set. It cross-checks against a brute-force count.
func TestReclassifyMatchesBruteForce(t *testing.T) {
	var self kad.ID
	e := NewEdges(self, nil)
	const n = 40 // > Siblings, spread across buckets
	var ids []kad.ID
	for i := range n {
		id := idInBucket(self, 1+i%30, i+1)
		add(t, e, id, true, 0, "")
		ids = append(ids, id)
	}

	gotSiblings := 0
	for _, id := range ids {
		// Brute force: id is a sibling iff fewer than Siblings other edges are closer
		// to self.
		closer := 0
		for _, other := range ids {
			if other != id && kad.DistanceCmp(self, other, id) < 0 {
				closer++
			}
		}
		wantSibling := closer < Siblings
		if got := isSibling(e, id); got != wantSibling {
			t.Fatalf("edge %x: isSibling=%v, brute-force want %v", id[:4], got, wantSibling)
		}
		if wantSibling {
			gotSiblings++
		}
	}
	if gotSiblings != Siblings {
		t.Fatalf("classified %d siblings, want exactly %d", gotSiblings, Siblings)
	}
}

// TestTouchUnderConcurrentReaders: Touch now runs under a read lock plus an atomic
// store, so it must be race-free against the concurrent RLock readers (Idle,
// Closest, Siblings). Run under -race to catch a regression.
func TestTouchUnderConcurrentReaders(t *testing.T) {
	var self kad.ID
	e := NewEdges(self, nil)
	ids := edgeIDs(t, e, self, 4)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		wg.Go(func() {
			now := t0
			for {
				select {
				case <-stop:
					return
				default:
				}
				for _, id := range ids {
					e.Touch(id, now)
				}
				now = now.Add(time.Second)
			}
		})
	}
	for range 4 {
		wg.Go(func() {
			buf := make([]LiveEdge, 0, len(ids))
			tgt := idInBucket(self, 5, 1)
			for {
				select {
				case <-stop:
					return
				default:
				}
				e.Idle(t0.Add(30*time.Second), 10*time.Second, 60*time.Second, buf)
				e.Closest(tgt, 3, buf)
				e.Siblings(buf)
			}
		})
	}
	time.Sleep(20 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// TestEdgesClosestMatchesFullScan: the CPL-indexed Closest must return exactly what
// a brute-force full scan would, element-by-element, for many random edge sets and
// targets — guarding the bucket-skip early-stop against ever dropping a closer edge.
func TestEdgesClosestMatchesFullScan(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	randID := func() kad.ID {
		var id kad.ID
		for o := 0; o < kad.IDLen; o += 8 {
			binary.BigEndian.PutUint64(id[o:], rng.Uint64())
		}
		return id
	}
	for trial := range 200 {
		self := randID()
		e := NewEdges(self, nil)
		ids := make([]kad.ID, 0, 64)
		for range 1 + trial%64 {
			id := randID()
			if id == self {
				continue
			}
			if err := e.AddEdge(fakeConn{id: id}, true, 0, t0); err != nil {
				continue // dup
			}
			ids = append(ids, id)
		}
		// Drop a few at random so the bucket index exercises removal too.
		for i := 0; i < len(ids)/4; i++ {
			e.RemoveEdge(ids[i])
		}

		for _, n := range []int{1, 3, 8} {
			target := randID()
			got := e.Closest(target, n, make([]LiveEdge, 0, n))
			want := bruteClosest(e, target, n)
			if len(got) != len(want) {
				t.Fatalf("trial %d n=%d: len(got)=%d want %d", trial, n, len(got), len(want))
			}
			for i := range got {
				if got[i].ID != want[i].ID {
					t.Fatalf("trial %d n=%d pos %d: got %x want %x", trial, n, i, got[i].ID[:4], want[i].ID[:4])
				}
			}
		}
	}
}

// bruteClosest is the reference: a flat scan of every live edge, kept n-closest.
func bruteClosest(e *Edges, target kad.ID, n int) []LiveEdge {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var buf []LiveEdge
	for _, ed := range e.list {
		buf = insertClosestEdge(buf, LiveEdge{ID: ed.id, Conn: ed.conn}, target, n)
	}
	return buf
}

func TestStatusBands(t *testing.T) {
	var self kad.ID
	e := NewEdges(self, nil)
	if e.Status().Phase != PhaseBootstrap {
		t.Fatalf("empty phase = %v, want Bootstrap", e.Status().Phase)
	}

	ids := make([]kad.ID, 0, 70)
	addN := func(target int) {
		for len(ids) < target {
			id := idInBucket(self, 1+len(ids), 0)
			add(t, e, id, true, 0, "")
			ids = append(ids, id)
		}
	}

	addN(3)
	if p := e.Status().Phase; p != PhaseCritical {
		t.Fatalf("out=3 phase = %v, want Critical", p)
	}
	addN(8)
	if p := e.Status().Phase; p != PhaseUrgent {
		t.Fatalf("out=8 phase = %v, want Urgent", p)
	}
	addN(30)
	if p := e.Status().Phase; p != PhaseNeedsFill {
		t.Fatalf("out=30 phase = %v, want NeedsFill", p)
	}
	addN(TargetEdges)
	if p := e.Status().Phase; p != PhaseNormal {
		t.Fatalf("out=%d phase = %v, want Normal", TargetEdges, p)
	}

	// Hysteresis: dropping a few below target keeps Normal until the margin.
	for len(ids) > TargetEdges-FillHysteresis {
		last := ids[len(ids)-1]
		ids = ids[:len(ids)-1]
		e.RemoveEdge(last)
	}
	if p := e.Status().Phase; p != PhaseNormal {
		t.Fatalf("out=%d phase = %v, want Normal (hysteresis)", e.Status().OutEdges, p)
	}
	// One more drop crosses the margin → NeedsFill.
	last := ids[len(ids)-1]
	ids = ids[:len(ids)-1]
	e.RemoveEdge(last)
	if p := e.Status().Phase; p != PhaseNeedsFill {
		t.Fatalf("out=%d phase = %v, want NeedsFill", e.Status().OutEdges, p)
	}
}

func TestReplacementFor(t *testing.T) {
	var self kad.ID
	k := NewKnowledge(self, subnetByEndpoint, 0)
	e := NewEdges(self, subnetByEndpoint)

	// Knowledge holds candidates near self (high buckets).
	live := idInBucket(self, 210, 1)
	satur := idInBucket(self, 211, 1)
	good := idInBucket(self, 212, 1)
	k.Observe(Contact{ID: live, Addrs: ep("subnet-X")}, t0)
	k.Observe(Contact{ID: satur, Addrs: ep("subnet-X")}, t0)
	k.Observe(Contact{ID: good, Addrs: ep("subnet-Y")}, t0)

	// `live` is already an edge; subnet-X is saturated by two live edges.
	add(t, e, live, true, 0, "subnet-X")
	add(t, e, idInBucket(self, 5, 7), true, 0, "subnet-X") // second live X edge → cap=2
	if e.subnets[mustSubnet("subnet-X")] < LiveSubnetCap {
		t.Fatal("subnet-X not saturated; test setup wrong")
	}

	got := e.ReplacementFor(k, self, 5, nil)
	gotIDs := map[kad.ID]bool{}
	for _, c := range got {
		gotIDs[c.ID] = true
	}
	if gotIDs[live] {
		t.Fatal("ReplacementFor returned an already-live peer")
	}
	if gotIDs[satur] {
		t.Fatal("ReplacementFor returned a peer in a saturated subnet")
	}
	if !gotIDs[good] {
		t.Fatal("ReplacementFor omitted a valid diverse candidate")
	}
}

// Address-less contacts (ID-only hints) are undialable, so they are not replacement
// candidates: they must neither be returned nor mask the saturated-subnet fallback —
// otherwise, in a single-subnet world, phantoms with no subnet fill the diverse pass
// and the dialable same-subnet contacts are never offered.
func TestReplacementForSkipsAddressless(t *testing.T) {
	var self kad.ID
	k := NewKnowledge(self, subnetByEndpoint, 0)
	e := NewEdges(self, subnetByEndpoint)

	// Closer phantom without addresses; farther dialable contact in a saturated subnet.
	phantom := idInBucket(self, 220, 1)
	dialable := idInBucket(self, 210, 1)
	k.Observe(Contact{ID: phantom}, t0)
	k.Observe(Contact{ID: dialable, Addrs: ep("subnet-X")}, t0)

	add(t, e, idInBucket(self, 5, 7), true, 0, "subnet-X")
	add(t, e, idInBucket(self, 6, 7), true, 0, "subnet-X") // subnet-X saturated

	got := e.ReplacementFor(k, self, 2, nil)
	if len(got) != 1 || got[0].ID != dialable {
		t.Fatalf("ReplacementFor = %v, want exactly the dialable saturated-subnet contact %v", got, dialable)
	}
}

// In a single-subnet world (loopback clusters, one shared /24) every candidate
// lives in a saturated subnet. The cap is a soft preference: rather than starving
// the connectivity floor, ReplacementFor must fall back to same-subnet candidates.
func TestReplacementForSingleSubnetFallback(t *testing.T) {
	var self kad.ID
	k := NewKnowledge(self, subnetByEndpoint, 0)
	e := NewEdges(self, subnetByEndpoint)

	cand1 := idInBucket(self, 210, 1)
	cand2 := idInBucket(self, 211, 1)
	k.Observe(Contact{ID: cand1, Addrs: ep("subnet-X")}, t0)
	k.Observe(Contact{ID: cand2, Addrs: ep("subnet-X")}, t0)

	// Two live edges saturate subnet-X; knowledge has no other subnet to offer.
	add(t, e, idInBucket(self, 5, 7), true, 0, "subnet-X")
	add(t, e, idInBucket(self, 6, 7), true, 0, "subnet-X")
	if e.subnets[mustSubnet("subnet-X")] < LiveSubnetCap {
		t.Fatal("subnet-X not saturated; test setup wrong")
	}

	got := e.ReplacementFor(k, self, 2, nil)
	if len(got) != 2 {
		t.Fatalf("ReplacementFor returned %d candidates, want 2 (saturated-subnet fallback)", len(got))
	}
	gotIDs := map[kad.ID]bool{}
	for _, c := range got {
		gotIDs[c.ID] = true
	}
	if !gotIDs[cand1] || !gotIDs[cand2] {
		t.Fatalf("ReplacementFor = %v, want both same-subnet candidates", got)
	}
}

func ep(endpoint string) []transport.Addr {
	return []transport.Addr{{Net: "quic", Endpoint: endpoint}}
}

func mustSubnet(endpoint string) Subnet {
	s, _ := subnetByEndpoint(transport.Addr{Net: "quic", Endpoint: endpoint})
	return s
}

// edgeIDs adds Siblings+extra edges in distinct buckets (closest first) at t0 and
// returns their IDs; the first Siblings are siblings, the rest fingers.
func edgeIDs(t *testing.T, e *Edges, self kad.ID, extra int) []kad.ID {
	t.Helper()
	n := Siblings + extra
	ids := make([]kad.ID, n)
	for i := range n {
		ids[i] = idInBucket(self, 200-i, 0)
		add(t, e, ids[i], true, 0, "")
	}
	return ids
}

func TestEdgesSiblingsAndConns(t *testing.T) {
	var self kad.ID
	e := NewEdges(self, nil)
	ids := edgeIDs(t, e, self, 4)

	if got := len(e.Siblings(nil)); got != Siblings {
		t.Fatalf("Siblings = %d, want %d", got, Siblings)
	}
	for _, le := range e.Siblings(nil) {
		if !isSibling(e, le.ID) {
			t.Fatalf("Siblings returned a non-sibling %v", le.ID)
		}
	}
	if got := len(e.Conns(nil)); got != len(ids) {
		t.Fatalf("Conns = %d, want %d", got, len(ids))
	}
}

func TestEdgesTouchAndIdle(t *testing.T) {
	var self kad.ID
	e := NewEdges(self, nil)
	ids := edgeIDs(t, e, self, 4) // all last-seen at t0
	sibTimeout, fingerTimeout := 10*time.Second, 60*time.Second

	// At t0+30s siblings have crossed their short timeout; fingers have not.
	now := t0.Add(30 * time.Second)
	idle := e.Idle(now, sibTimeout, fingerTimeout, nil)
	if len(idle) != Siblings {
		t.Fatalf("idle = %d, want %d (siblings only)", len(idle), Siblings)
	}
	for _, le := range idle {
		if !isSibling(e, le.ID) {
			t.Fatalf("idle edge %v is a finger, should not be idle yet", le.ID)
		}
	}

	// Touch one sibling at t0+30s; at t0+35s it is no longer idle, the rest are.
	// Touch reports a known edge, so the dispatch path needs no separate lookup.
	if !e.Touch(ids[0], now) {
		t.Fatal("Touch of a registered edge reported it unknown")
	}
	idle = e.Idle(t0.Add(35*time.Second), sibTimeout, fingerTimeout, nil)
	if len(idle) != Siblings-1 {
		t.Fatalf("idle after touch = %d, want %d", len(idle), Siblings-1)
	}
	for _, le := range idle {
		if le.ID == ids[0] {
			t.Fatal("touched edge still reported idle")
		}
	}

	// Far later every edge (fingers included, touched one included) is idle.
	idle = e.Idle(t0.Add(120*time.Second), sibTimeout, fingerTimeout, nil)
	if len(idle) != len(ids) {
		t.Fatalf("idle late = %d, want %d (all)", len(idle), len(ids))
	}

	// Touch of an unknown edge is a harmless no-op and reports it untracked.
	if e.Touch(idInBucket(self, 7, 9), now) {
		t.Fatal("Touch of an unknown edge reported it registered")
	}
}
