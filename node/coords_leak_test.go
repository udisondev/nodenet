package node

import (
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/nat"
	"github.com/udisondev/nodenet/rendezvous"
	"github.com/udisondev/nodenet/routing"
	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/wire"
)

// TestConnectCoordDisclosureThrottled (S8): a Connect makes this node answer with its
// own coordinates (its externally-visible address) — necessary for hole-punching, but a
// vector for cheap mass deanonymization (NodeID → IP) if answered without bound. The
// responder-side disclosure is throttled per authenticated originator, so a flood of
// Connects yields exactly a burst of ConnectAcks, not one per probe: inside the synctest
// bubble the clock is frozen while the flood runs, so the bucket gets zero refill and
// the bound is exact. (Single disclosure to a legitimate initiator is inherent to the
// routed-handshake design and accepted as residual.)
func TestConnectCoordDisclosureThrottled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := newBareNode(t, 1)

		var (
			mu       sync.Mutex
			captured [][]byte
		)
		peer := n.ID()
		peer[1] ^= 0x33
		edge := recordConn{id: peer, mu: &mu, frames: &captured}
		if err := n.e.AddEdge(edge, true, 0, time.Now()); err != nil {
			t.Fatalf("AddEdge: %v", err)
		}

		attacker := identity.FromSeed(seedFor(777))
		var attackerEd [32]byte
		copy(attackerEd[:], attacker.EdPublic())

		connectFrame := func(nonceByte byte) []byte {
			c := nat.Connect{Addrs: []transport.Addr{{Net: "mem", Endpoint: "atk"}}}
			c.Nonce[0] = nonceByte
			payload, err := nat.MarshalConnect(&c)
			if err != nil {
				t.Fatalf("MarshalConnect: %v", err)
			}
			msg := routing.Msg{Target: n.ID(), TTL: routing.MaxHops, EdPub: attackerEd, Payload: payload}
			routing.SignMsg(attacker, nat.TypeConnect, &msg, time.Now())
			buf := make([]byte, 512)
			w, err := routing.EncodeMsgFrame(buf, nat.TypeConnect, &msg)
			if err != nil {
				t.Fatalf("EncodeMsgFrame: %v", err)
			}
			return buf[:w]
		}

		const flood = 200
		for i := range flood {
			p := transport.Get()
			p.SetLen(copy(p.Buf(), connectFrame(byte(i))))
			n.handle(transport.Delivery{Conn: edge, Pkt: p})
		}
		synctest.Wait() // the acks are originated on their own goroutines

		// Count the ConnectAck responses the node emitted (each discloses its coords).
		mu.Lock()
		acks := 0
		for _, f := range captured {
			if typ, _, _, err := wire.ParseFrame(f); err == nil && typ == nat.TypeConnectAck {
				acks++
			}
		}
		mu.Unlock()

		if acks != routing.ControlBurst {
			t.Fatalf("disclosed coords %d/%d times; want exactly the burst %d (zero refill on the fake clock)",
				acks, flood, routing.ControlBurst)
		}
	})
}

// TestHelloDisclosureThrottled: a rendezvous hello that reached its target costs an
// Ed25519 verify, an Ed25519 reply signature and a 3-path routed reply that discloses
// this node's coordinates — at least the work a Connect costs — so it must be throttled
// per authenticated originator exactly like nat.TypeConnect. One validly-signed hello
// replayed within the freshness window must draw a burst of replies, not one per copy.
func TestHelloDisclosureThrottled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := newBareNode(t, 1)

		var (
			mu       sync.Mutex
			captured [][]byte
		)
		peer := n.ID()
		peer[1] ^= 0x21
		edge := recordConn{id: peer, mu: &mu, frames: &captured}
		if err := n.e.AddEdge(edge, true, 0, time.Now()); err != nil {
			t.Fatalf("AddEdge: %v", err)
		}

		attacker := identity.FromSeed(seedFor(778))
		var attackerEd [32]byte
		copy(attackerEd[:], attacker.EdPublic())

		// One genuine hello, replayed: the hello's inner signature stays valid for the
		// whole freshness window, so the replay costs the attacker no new signing work.
		h := rendezvous.Hello{XPub: attacker.KEXPublic(), Addrs: []transport.Addr{{Net: "mem", Endpoint: "atk"}}}
		h.Nonce[0] = 1
		rendezvous.SignHello(attacker, n.ID(), &h)
		payload, err := rendezvous.MarshalHello(&h)
		if err != nil {
			t.Fatalf("MarshalHello: %v", err)
		}
		msg := routing.Msg{Target: n.ID(), TTL: routing.MaxHops, EdPub: attackerEd, Payload: payload}
		routing.SignMsg(attacker, rendezvous.TypeHello, &msg, time.Now())
		buf := make([]byte, 1024)
		w, err := routing.EncodeMsgFrame(buf, rendezvous.TypeHello, &msg)
		if err != nil {
			t.Fatalf("EncodeMsgFrame: %v", err)
		}
		helloFrame := buf[:w]

		const flood = 200
		for range flood {
			p := transport.Get()
			p.SetLen(copy(p.Buf(), helloFrame))
			n.handle(transport.Delivery{Conn: edge, Pkt: p})
		}
		synctest.Wait() // the replies are originated on their own goroutines

		mu.Lock()
		replies := 0
		for _, f := range captured {
			if typ, _, _, err := wire.ParseFrame(f); err == nil && typ == rendezvous.TypeReply {
				replies++
			}
		}
		mu.Unlock()

		if replies != routing.ControlBurst {
			t.Fatalf("disclosed coords in %d/%d hello replies; want exactly the burst %d (zero refill on the fake clock)",
				replies, flood, routing.ControlBurst)
		}
	})
}
