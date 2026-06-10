package routing

import (
	"testing"
	"time"

	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/kad"
)

// edPubOf returns the [32]byte Ed25519 public key of the identity seeded by s.
func edPubOf(idn *identity.Identity) [32]byte {
	var ed [32]byte
	copy(ed[:], idn.EdPublic())
	return ed
}

// TestObserveBindsKeyToID: a contact that carries an Ed25519 key is admitted only when
// the key hashes to the claimed NodeID (NodeID = BLAKE2b(ed_pub)). A mismatched pair —
// the heart of routing-table poisoning, where a peer advertises a victim's or an
// arbitrary ID alongside an unrelated key — is rejected outright. A keyless contact (an
// ID-only routing hint) is still admitted on its NodeID alone.
func TestObserveBindsKeyToID(t *testing.T) {
	self := kad.ID{0xff} // far from the seeded identities below
	k := NewKnowledge(self, nil, 0)

	idn := identity.FromSeed([identity.SeedLen]byte{1})
	realID := idn.ID()
	realKey := edPubOf(idn)

	// Matching pair: admitted and retrievable.
	if out, _ := k.Observe(Contact{ID: realID, EdPub: realKey}, t0); out != ObserveInserted {
		t.Fatalf("matching key/ID: outcome %v, want ObserveInserted", out)
	}
	if _, ok := k.Get(realID); !ok {
		t.Fatal("matching key/ID was not stored")
	}

	// Mismatched pair: the same real key paired with a different (arbitrary) ID is a
	// forged contact and must be refused.
	forgedID := idInBucket(self, 10, 7)
	if forgedID == realID {
		t.Fatal("test setup: forgedID collided with realID")
	}
	if out, _ := k.Observe(Contact{ID: forgedID, EdPub: realKey}, t0); out != ObserveRejected {
		t.Fatalf("mismatched key/ID: outcome %v, want ObserveRejected", out)
	}
	if _, ok := k.Get(forgedID); ok {
		t.Fatal("a forged key/ID contact was stored")
	}

	// Keyless hint: admitted on its NodeID alone (no key to bind yet).
	hintID := idInBucket(self, 20, 3)
	if out, _ := k.Observe(Contact{ID: hintID}, t0); out != ObserveInserted {
		t.Fatalf("keyless hint: outcome %v, want ObserveInserted", out)
	}
	if _, ok := k.Get(hintID); !ok {
		t.Fatal("keyless hint was not stored")
	}
}

// TestXPubOnlyFromAuthenticatedChannel: nothing on the wire binds an X25519 key to a
// NodeID (the ID hashes only the Ed25519 key), so Observe must never store or
// overwrite XPub — a third party could otherwise pair a victim's ID and real EdPub
// with its own XPub via a gossiped contact list (key substitution). The key enters
// the table only through BindXPub, whose callers verified an originator-signed
// channel that covers it.
func TestXPubOnlyFromAuthenticatedChannel(t *testing.T) {
	self := kad.ID{0xff}
	k := NewKnowledge(self, nil, 0)

	idn := identity.FromSeed([identity.SeedLen]byte{4})
	id := idn.ID()
	key := edPubOf(idn)
	attackerX := [32]byte{0xee, 0xee}
	realX := [32]byte{0x11, 0x22}

	// A gossiped XPub is ignored even alongside the victim's real, binding EdPub.
	if out, _ := k.Observe(Contact{ID: id, EdPub: key, XPub: attackerX}, t0); out != ObserveInserted {
		t.Fatalf("admit: %v", out)
	}
	if got, _ := k.Get(id); got.XPub != ([32]byte{}) {
		t.Fatal("Observe stored an unauthenticated XPub")
	}

	// An authenticated bind sticks.
	k.BindXPub(id, realX)
	if got, _ := k.Get(id); got.XPub != realX {
		t.Fatal("BindXPub did not store the key")
	}

	// Later gossip cannot overwrite the bound key.
	k.Observe(Contact{ID: id, EdPub: key, XPub: attackerX}, t0.Add(time.Minute))
	if got, _ := k.Get(id); got.XPub != realX {
		t.Fatal("a gossiped refresh overwrote the bound XPub")
	}
}

// TestObserveRejectsMismatchedRefresh: a refresh carrying a key that does not hash to an
// already-admitted contact's ID is refused, so a later forged packet cannot overwrite a
// verified contact's key.
func TestObserveRejectsMismatchedRefresh(t *testing.T) {
	self := kad.ID{0xff}
	k := NewKnowledge(self, nil, 0)

	idn := identity.FromSeed([identity.SeedLen]byte{2})
	id := idn.ID()
	key := edPubOf(idn)
	k.Observe(Contact{ID: id, EdPub: key}, t0)

	other := edPubOf(identity.FromSeed([identity.SeedLen]byte{3}))
	if out, _ := k.Observe(Contact{ID: id, EdPub: other}, t0); out != ObserveRejected {
		t.Fatalf("mismatched refresh: outcome %v, want ObserveRejected", out)
	}
	c, ok := k.Get(id)
	if !ok {
		t.Fatal("contact vanished after a rejected refresh")
	}
	if c.EdPub != key {
		t.Fatal("a rejected refresh overwrote the verified key")
	}
}
