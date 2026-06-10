package routing

import (
	"testing"

	"github.com/udisondev/nodenet/kad"
)

// idByte0 builds an ID whose first byte is b and the rest zero — enough to control
// XOR ordering against a target in these tests.
func idByte0(b byte) kad.ID {
	var id kad.ID
	id[0] = b
	return id
}

func TestDecideDeliverSelf(t *testing.T) {
	self := fill(0x42)
	e := NewEdges(self, nil)
	m := &Msg{Target: self, TTL: 10}
	d := Decide(self, m, e, make([]LiveEdge, 0, 4))
	if d.Kind != KindDeliver {
		t.Fatalf("Kind = %v, want KindDeliver", d.Kind)
	}
}

func TestDecideDropTTLZero(t *testing.T) {
	var self kad.ID
	target := idByte0(0xff)
	e := NewEdges(self, nil)
	add(t, e, idByte0(0xf0), true, 0, "") // a perfectly good next hop exists
	m := &Msg{Target: target, TTL: 0}
	d := Decide(self, m, e, make([]LiveEdge, 0, 4))
	if d.Kind != KindDrop {
		t.Fatalf("Kind = %v, want KindDrop (TTL exhausted)", d.Kind)
	}
}

func TestDecideForward(t *testing.T) {
	var self kad.ID // 0x00.. , far from target
	target := idByte0(0xff)
	near := idByte0(0xf0) // closer to target than self
	e := NewEdges(self, nil)
	add(t, e, near, true, 0, "")

	m := &Msg{Target: target, TTL: 10}
	d := Decide(self, m, e, make([]LiveEdge, 0, 4))
	if d.Kind != KindForward {
		t.Fatalf("Kind = %v, want KindForward", d.Kind)
	}
	if d.OutTTL != 9 {
		t.Errorf("OutTTL = %d, want 9", d.OutTTL)
	}
	if len(d.NextHops) != 1 || d.NextHops[0].ID != near {
		t.Errorf("NextHops = %v, want [%v]", d.NextHops, near)
	}
}

// TTL above MaxHops is clamped before decrement, so a hostile budget cannot let a
// packet wander.
func TestDecideClampTTL(t *testing.T) {
	var self kad.ID
	target := idByte0(0xff)
	e := NewEdges(self, nil)
	add(t, e, idByte0(0xf0), true, 0, "")
	m := &Msg{Target: target, TTL: 200}
	d := Decide(self, m, e, make([]LiveEdge, 0, 4))
	if d.Kind != KindForward || d.OutTTL != MaxHops-1 {
		t.Fatalf("Kind=%v OutTTL=%d, want KindForward %d", d.Kind, d.OutTTL, MaxHops-1)
	}
}

// A local optimum that is not the target — no live edge is closer to the target
// than self — is a dead end and drops.
func TestDecideDeadEnd(t *testing.T) {
	target := fill(0xff)
	self := target
	self[kad.IDLen-1] ^= 1 // distance 1 from target: nothing can be closer
	e := NewEdges(self, nil)
	add(t, e, fill(0), true, 0, "") // an edge, but far from target
	m := &Msg{Target: target, TTL: 10}
	d := Decide(self, m, e, make([]LiveEdge, 0, 4))
	if d.Kind != KindDrop {
		t.Fatalf("Kind = %v, want KindDrop (dead end)", d.Kind)
	}
}

// The avoid-set steers the choice: the closest live edge is skipped when listed, and
// forwarding falls to the next-closest non-avoided edge.
func TestDecideAvoid(t *testing.T) {
	var self kad.ID
	target := idByte0(0xff)
	near := idByte0(0xf0)  // closest to target
	near2 := idByte0(0xe0) // next closest
	e := NewEdges(self, nil)
	add(t, e, near, true, 0, "")
	add(t, e, near2, true, 0, "")

	// Avoid the closest: must forward to the other.
	m := &Msg{Target: target, TTL: 10, Avoid: avoidOf(near)}
	d := Decide(self, m, e, make([]LiveEdge, 0, 4))
	if d.Kind != KindForward || len(d.NextHops) != 1 || d.NextHops[0].ID != near2 {
		t.Fatalf("avoid closest: got %v %v, want forward to near2", d.Kind, d.NextHops)
	}

	// Avoid both viable hops: dead end.
	m = &Msg{Target: target, TTL: 10, Avoid: avoidOf(near, near2)}
	d = Decide(self, m, e, make([]LiveEdge, 0, 4))
	if d.Kind != KindDrop {
		t.Fatalf("avoid all: Kind = %v, want KindDrop", d.Kind)
	}
}

// NextHops come back closest-first, so the dispatcher's first try is the greedy
// best and the rest are local-repair fallbacks in order.
func TestDecideNextHopsOrdered(t *testing.T) {
	var self kad.ID
	target := idByte0(0xff)
	e := NewEdges(self, nil)
	// Add out of order; closeness to target is by first byte (higher = closer).
	add(t, e, idByte0(0xa0), true, 0, "")
	add(t, e, idByte0(0xf0), true, 0, "")
	add(t, e, idByte0(0xc0), true, 0, "")

	m := &Msg{Target: target, TTL: 10}
	d := Decide(self, m, e, make([]LiveEdge, 0, 4))
	if d.Kind != KindForward {
		t.Fatalf("Kind = %v, want KindForward", d.Kind)
	}
	wantOrder := []byte{0xf0, 0xc0, 0xa0}
	if len(d.NextHops) != len(wantOrder) {
		t.Fatalf("NextHops len = %d, want %d", len(d.NextHops), len(wantOrder))
	}
	for i, w := range wantOrder {
		if d.NextHops[i].ID != idByte0(w) {
			t.Errorf("NextHops[%d].ID first byte = %#x, want %#x", i, d.NextHops[i].ID[0], w)
		}
	}
}
