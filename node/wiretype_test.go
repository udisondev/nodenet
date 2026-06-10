package node

import (
	"testing"

	"github.com/udisondev/nodenet/nat"
	"github.com/udisondev/nodenet/rendezvous"
	"github.com/udisondev/nodenet/routing"
	"github.com/udisondev/nodenet/transport/transporttest"
	"github.com/udisondev/nodenet/wire"
)

// TestWireTypeRegistry: the wire.Type value space is one flat byte shared by every
// owning package, and nothing checks uniqueness at compile time — the allocation lives
// only in the registry doc on wire.Type (wire/wire.go). node is the sole package that
// imports all the owners, so this is the one place a collision can be caught: collect
// every assigned constant, demand pairwise-distinct values, and pin each to the range
// its package claims in that registry.
func TestWireTypeRegistry(t *testing.T) {
	types := []struct {
		name   string
		typ    wire.Type
		lo, hi wire.Type // the owning package's claimed range per the wire.Type registry
	}{
		{"routing.TypeRoute", routing.TypeRoute, 1, 7},
		{"routing.TypePing", routing.TypePing, 1, 7},
		{"routing.TypePong", routing.TypePong, 1, 7},
		{"routing.TypeLookup", routing.TypeLookup, 1, 7},
		{"routing.TypeNeighbors", routing.TypeNeighbors, 1, 7},
		{"routing.TypeSiblings", routing.TypeSiblings, 1, 7},
		{"routing.TypeLeave", routing.TypeLeave, 1, 7},
		{"rendezvous.TypeHello", rendezvous.TypeHello, 8, 9},
		{"rendezvous.TypeReply", rendezvous.TypeReply, 8, 9},
		{"nat.TypeConnect", nat.TypeConnect, 10, 14},
		{"nat.TypeConnectAck", nat.TypeConnectAck, 10, 14},
		{"nat.TypeRelayRequest", nat.TypeRelayRequest, 10, 14},
		{"nat.TypeRelayGrant", nat.TypeRelayGrant, 10, 14},
		{"nat.TypeRelayBind", nat.TypeRelayBind, 10, 14},
		// The contract suite deliberately sits in the unassigned band; it still must
		// not collide with anything real.
		{"transporttest.TestType", transporttest.TestType, 15, 63},
		{"node.TypeApp", TypeApp, 64, 64},
	}

	seen := make(map[wire.Type]string, len(types))
	for _, c := range types {
		if prev, dup := seen[c.typ]; dup {
			t.Errorf("wire.Type %d is assigned to both %s and %s", c.typ, prev, c.name)
		}
		seen[c.typ] = c.name
		if c.typ < c.lo || c.typ > c.hi {
			t.Errorf("%s = %d sits outside its registry range %d–%d (see wire.Type doc)", c.name, c.typ, c.lo, c.hi)
		}
	}
}
