package node

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/routing"
	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/transport/mem"
)

// TestEclipseResistance (#9): the composition of S5 (subnet-diverse reflexive consensus)
// and S7 (keyless neighbours hints kept as ID-only) means a single attacker that holds an
// edge to a victim cannot capture it — neither redirect a known peer's address to itself
// nor poison the victim's reflexive address. A victim that knows an honest peer keeps that
// peer's real address, and reflexive stays unconfirmed, despite a flood of attacker
// hints.
func TestEclipseResistance(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))

		v := spawn(t, ctx, hub, 1, WithSubnetFunc(ipSubnet))
		attacker := spawn(t, ctx, hub, 2)

		// The victim already knows an honest peer H — keyed, with H's real address.
		h := identity.FromSeed(seedFor(100))
		var hEd [32]byte
		copy(hEd[:], h.EdPublic())
		honestAddr := transport.Addr{Net: "quic", Endpoint: "198.51.100.7:9000"}
		v.Bootstrap([]routing.Contact{{ID: h.ID(), EdPub: hEd, Addrs: []transport.Addr{honestAddr}}})

		// The attacker floods the victim with a neighbours response: H's ID paired with
		// the attacker's address (a redirect attempt), plus many keyless junk IDs (a
		// table-flooding attempt).
		attackerAddr := transport.Addr{Net: "quic", Endpoint: "203.0.113.66:9000"}
		cs := []routing.Contact{{ID: h.ID(), Addrs: []transport.Addr{attackerAddr}}}
		for i := byte(1); i <= 30; i++ {
			junk := kad.ID{0x55, i}
			cs = append(cs, routing.Contact{ID: junk, Addrs: []transport.Addr{attackerAddr}})
		}
		conn, err := attacker.t.Dial(ctx, v.ID(), v.addr)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		// Make the response solicited so the keyless-strip path is exercised (an unsolicited
		// response is dropped wholesale by the solicitation gate before the strip).
		nonce := [routing.LookupNonceLen]byte{0xE7}
		solicit(v.Node, nonce)
		sendControl(t, conn, func(buf []byte) (int, error) {
			return routing.EncodeNeighborsFrame(buf, attacker.id, attacker.edPub, v.ID(), 10, time.Now(), nonce, cs)
		})
		synctest.Wait()

		// S7: H's address is still the honest one — the keyless redirect was dropped.
		got, ok := v.Knowledge().Get(h.ID())
		if !ok {
			t.Fatal("victim lost the honest contact H")
		}
		if len(got.Addrs) == 0 || got.Addrs[0] != honestAddr {
			t.Fatalf("H's address was poisoned: got %v, want %v", got.Addrs, honestAddr)
		}

		// S5: the attacker (a single edge, one subnet) cannot confirm a reflexive address.
		// Replay a pong claiming a forged external address from the attacker edge.
		forged := transport.Addr{Net: "quic", Endpoint: "203.0.113.66:7777"}
		// The attacker has no real subnet via the mem transport's ipSubnet (mem addr →
		// no subnet), so even repeated reports cannot reach the subnet-diverse quorum.
		for range 5 {
			p := transport.Get()
			p.SetLen(copy(p.Buf(), pongFrame(t, forged)))
			v.handle(transport.Delivery{Conn: pongConn{id: attacker.ID(), addr: v.addr}, Pkt: p})
		}
		synctest.Wait()
		if r := v.Reflexive(); r != (transport.Addr{}) {
			t.Fatalf("single attacker confirmed a reflexive address: %v", r)
		}
	})
}
