package node

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/routing"
	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/transport/mem"
)

// TestKnowledgePoisonKeylessAddr (S7): a neighbours response is untrusted. A keyless
// (key-less) contact in it binds to ANY NodeID trivially, so an attacker could pair a
// real peer's NodeID with its own address and have a victim cache "victimID → attacker
// addr". Such keyless hints must be folded in as ID-only (their addresses dropped), so
// the table is not seeded with attacker-chosen addresses for other peers' IDs.
func TestKnowledgePoisonKeylessAddr(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))

		a := spawn(t, ctx, hub, 1)
		b := spawn(t, ctx, hub, 2) // PoW-valid sender of the neighbours response

		victim := kad.ID{0x11, 0x22, 0x33}
		attackerAddr := transport.Addr{Net: "mem", Endpoint: "attacker-box"}
		// Keyless contact (no EdPub) pairing the victim's ID with the attacker's address.
		cs := []routing.Contact{{ID: victim, Addrs: []transport.Addr{attackerAddr}}}

		conn, err := b.t.Dial(ctx, a.ID(), a.addr)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		nonce := [routing.LookupNonceLen]byte{0xB2}
		solicit(a.Node, nonce)
		sendControl(t, conn, func(buf []byte) (int, error) {
			return routing.EncodeNeighborsFrame(buf, b.id, b.edPub, a.ID(), 10, time.Now(), nonce, cs)
		})
		synctest.Wait()

		// The ID-only hint may be kept, but never with the attacker's address.
		if c, ok := a.k.Get(victim); ok && len(c.Addrs) != 0 {
			t.Fatalf("keyless neighbours hint seeded an address for the victim ID: %v", c.Addrs)
		}
	})
}

// TestKnowledgeKeyedAddrKept (S7): a properly-keyed contact in a neighbours response —
// whose key hashes to its ID — keeps its address; only the trivially-bindable keyless
// hints are stripped.
func TestKnowledgeKeyedAddrKept(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))

		a := spawn(t, ctx, hub, 1)
		b := spawn(t, ctx, hub, 2)
		c := spawn(t, ctx, hub, 3) // a real, keyed peer

		cAddr := transport.Addr{Net: "mem", Endpoint: "c-real"}
		var cEd [32]byte
		copy(cEd[:], c.id.EdPublic())
		cs := []routing.Contact{{ID: c.ID(), EdPub: cEd, Addrs: []transport.Addr{cAddr}}}

		conn, err := b.t.Dial(ctx, a.ID(), a.addr)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		nonce := [routing.LookupNonceLen]byte{0xC3}
		solicit(a.Node, nonce)
		sendControl(t, conn, func(buf []byte) (int, error) {
			return routing.EncodeNeighborsFrame(buf, b.id, b.edPub, a.ID(), 10, time.Now(), nonce, cs)
		})
		synctest.Wait()

		got, ok := a.k.Get(c.ID())
		if !ok {
			t.Fatal("keyed contact from neighbours response was not learned")
		}
		if len(got.Addrs) == 0 || got.Addrs[0] != cAddr {
			t.Fatalf("keyed contact lost its address: %+v", got.Addrs)
		}
	})
}
