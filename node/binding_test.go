package node

import (
	"testing"
	"time"

	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/routing"
)

// TestKnowledgeRejectsForgedContact: the table a node folds neighbours responses into
// refuses a contact whose Ed25519 key does not hash to its claimed NodeID — the forged
// pair a malicious peer would use to wedge an entry under an arbitrary or a victim's ID.
// A validly-bound contact and a keyless ID-only hint are still learned.
func TestKnowledgeRejectsForgedContact(t *testing.T) {
	n := newBareNode(t, 1)
	now := time.Now()

	good := identity.FromSeed(seedFor(2))
	var goodKey [32]byte
	copy(goodKey[:], good.EdPublic())

	n.k.Observe(routing.Contact{ID: good.ID(), EdPub: goodKey}, now)          // valid
	n.k.Observe(routing.Contact{ID: kad.ID{0x12, 0x34}, EdPub: goodKey}, now) // forged: real key, wrong ID
	n.k.Observe(routing.Contact{ID: kad.ID{0x56, 0x78}}, now)                 // keyless hint

	if _, ok := n.k.Get(good.ID()); !ok {
		t.Fatal("dropped a validly-bound contact")
	}
	if _, ok := n.k.Get(kad.ID{0x12, 0x34}); ok {
		t.Fatal("learned a forged ID/key pair")
	}
	if _, ok := n.k.Get(kad.ID{0x56, 0x78}); !ok {
		t.Fatal("dropped a keyless ID-only hint (these are allowed, PoW-gated)")
	}
}
