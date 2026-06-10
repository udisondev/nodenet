package node

import (
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/nat"
	"github.com/udisondev/nodenet/routing"
	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/wire"
)

// TestControlFloodRateLimited (S4): a peer that floods amplifying control frames over one
// edge is throttled — the node answers at most a bounded burst, not one response per
// request. Here a torrent of sibling-set requests (each would otherwise produce a fat
// neighbours response) must yield exactly the burst many responses: inside the synctest
// bubble the clock is frozen while the flood runs, so the bucket gets zero refill and the
// bound is exact.
func TestControlFloodRateLimited(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := newBareNode(t, 1)

		var (
			mu       sync.Mutex
			captured [][]byte
		)
		peer := n.ID()
		peer[1] ^= 0x5a // distinct from self
		conn := recordConn{id: peer, mu: &mu, frames: &captured}
		if err := n.e.AddEdge(conn, true, 0, time.Now()); err != nil {
			t.Fatalf("AddEdge: %v", err)
		}

		const flood = 200
		sibFrame := func() []byte {
			buf := make([]byte, 64)
			w, err := routing.EncodeSiblingsFrame(buf, [routing.LookupNonceLen]byte{})
			if err != nil {
				t.Fatalf("EncodeSiblingsFrame: %v", err)
			}
			return buf[:w]
		}()

		for range flood {
			p := transport.Get()
			p.SetLen(copy(p.Buf(), sibFrame))
			n.handle(transport.Delivery{Conn: conn, Pkt: p})
		}
		synctest.Wait()

		mu.Lock()
		got := len(captured)
		mu.Unlock()

		if got != routing.ControlBurst {
			t.Fatalf("answered %d/%d sibling requests; want exactly the burst %d (zero refill on the fake clock)",
				got, flood, routing.ControlBurst)
		}
	})
}

// TestLookupFloodKeyedByOriginator (#7): a lookup flood from one authenticated originator
// is throttled even when spread across multiple arriving edges — the limit is keyed on
// the originator, not the edge, so it cannot be dodged by alternating edges.
func TestLookupFloodKeyedByOriginator(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := newBareNode(t, 1)

		var (
			mu       sync.Mutex
			captured [][]byte
		)
		// Two edges the lookup can arrive on (and the answer can route back over).
		for i := byte(1); i <= 2; i++ {
			id := n.ID()
			id[2] ^= i
			if err := n.e.AddEdge(recordConn{id: id, mu: &mu, frames: &captured}, true, 0, time.Now()); err != nil {
				t.Fatalf("AddEdge: %v", err)
			}
		}
		edges := n.e.Conns(nil)

		attacker := identity.FromSeed(seedFor(0xA7))
		var attackerEd [32]byte
		copy(attackerEd[:], attacker.EdPublic())

		const flood = 200
		nonce := [routing.LookupNonceLen]byte{0x9c}
		for i := range flood {
			msg := routing.Msg{Target: n.ID(), TTL: routing.MaxHops, EdPub: attackerEd, Payload: nonce[:]}
			routing.SignMsg(attacker, routing.TypeLookup, &msg, time.Now())
			p := transport.Get()
			w, _ := routing.EncodeLookupFrame(p.Buf(), &msg)
			p.SetLen(w)
			// Alternate the arriving edge each iteration.
			n.handle(transport.Delivery{Conn: edges[i%len(edges)].Conn, Pkt: p})
		}
		synctest.Wait()

		mu.Lock()
		answers := 0
		for _, f := range captured {
			if typ, _, _, err := wire.ParseFrame(f); err == nil && typ == routing.TypeNeighbors {
				answers++
			}
		}
		mu.Unlock()

		if answers != routing.ControlBurst {
			t.Fatalf("answered %d lookups across edges; want exactly the per-originator burst %d (zero refill on the fake clock)",
				answers, routing.ControlBurst)
		}
	})
}

// TestRelayBindFloodRateLimited: a relay bind makes this node fire a punch burst at an
// address taken straight from the (untrusted) payload — work-generating like a relay
// request — so it must be charged against the same per-edge control budget instead of
// being served without limit. A flood past the burst is shed and counted.
func TestRelayBindFloodRateLimited(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := newBareNode(t, 1)
		peer := n.ID()
		peer[1] ^= 0x44
		conn := stubConn{id: peer}
		if err := n.e.AddEdge(conn, true, 0, time.Now()); err != nil {
			t.Fatalf("AddEdge: %v", err)
		}

		buf := make([]byte, 128)
		w, err := nat.EncodeRelayBindFrame(buf, transport.Addr{Net: "quic", Endpoint: "203.0.113.7:7"})
		if err != nil {
			t.Fatalf("EncodeRelayBindFrame: %v", err)
		}
		bindFrame := buf[:w]

		const flood = 200
		for range flood {
			p := transport.Get()
			p.SetLen(copy(p.Buf(), bindFrame))
			n.handle(transport.Delivery{Conn: conn, Pkt: p})
		}

		if got, want := n.Stats().DroppedRateLimited, uint64(flood-routing.ControlBurst); got != want {
			t.Fatalf("dropped %d relay binds; want %d (everything past the burst %d, zero refill on the fake clock)",
				got, want, routing.ControlBurst)
		}
	})
}
