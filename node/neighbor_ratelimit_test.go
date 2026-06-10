package node

import (
	"testing"
	"time"

	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/routing"
	"github.com/udisondev/nodenet/transport"
)

// TestNeighborSolicitationGate (H1): a neighbours response is folded into knowledge ONLY
// if it echoes the correlation nonce of a lookup/sibling request this node actually sent
// and is still awaiting. An unsolicited response — a nonce the node never issued — is
// dropped wholesale (the off-path table-poisoning vector), while a response carrying a
// solicited nonce is learned.
func TestNeighborSolicitationGate(t *testing.T) {
	// makeFrame takes the calling (sub)test's own t: a t.Fatalf must run on the
	// goroutine of the test it belongs to, never on a captured parent's.
	makeFrame := func(t *testing.T, n *Node, originator *identity.Identity, target *identity.Identity, nonce [routing.LookupNonceLen]byte) []byte {
		t.Helper()
		var oEd [32]byte
		copy(oEd[:], originator.EdPublic())
		var tEd [32]byte
		copy(tEd[:], target.EdPublic())
		cs := []routing.Contact{{ID: target.ID(), EdPub: tEd}}
		p := transport.Get()
		defer p.Release()
		w, err := routing.EncodeNeighborsFrame(p.Buf(), originator, oEd, n.ID(), 1, time.Now(), nonce, cs)
		if err != nil {
			t.Fatalf("EncodeNeighborsFrame: %v", err)
		}
		p.SetLen(w)
		return append([]byte(nil), p.Bytes()...)
	}

	// Unsolicited: a nonce the node never issued — the response must be dropped, the
	// advertised contact never learned, and the drop counted.
	t.Run("unsolicited dropped", func(t *testing.T) {
		n := newBareNode(t, 1)
		originator := identity.FromSeed(seedFor(0xC1))
		target := identity.FromSeed(seedFor(0xC2))
		conn := stubConn{id: originator.ID()}

		p := transport.Get()
		p.SetLen(copy(p.Buf(), makeFrame(t, n, originator, target, [routing.LookupNonceLen]byte{0xDE, 0xAD})))
		n.handle(transport.Delivery{Conn: conn, Pkt: p})

		if _, ok := n.Knowledge().Get(target.ID()); ok {
			t.Fatal("an unsolicited neighbours response was folded into knowledge")
		}
		if n.Stats().DroppedRateLimited == 0 {
			t.Fatal("the unsolicited response was not counted as dropped")
		}
	})

	// Solicited: the node registered the nonce (as the maintenance loop would when sending
	// the request), so the matching response is learned.
	t.Run("solicited learned", func(t *testing.T) {
		n := newBareNode(t, 1)
		originator := identity.FromSeed(seedFor(0xC1))
		target := identity.FromSeed(seedFor(0xC2))
		conn := stubConn{id: originator.ID()}

		nonce := [routing.LookupNonceLen]byte{0x01, 0x02, 0x03}
		solicit(n, nonce)

		p := transport.Get()
		p.SetLen(copy(p.Buf(), makeFrame(t, n, originator, target, nonce)))
		n.handle(transport.Delivery{Conn: conn, Pkt: p})

		if _, ok := n.Knowledge().Get(target.ID()); !ok {
			t.Fatal("a solicited neighbours response was not learned")
		}
	})
}
