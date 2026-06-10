package node

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/pow"
	"github.com/udisondev/nodenet/routing"
	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/transport/mem"
)

// seedSatisfying scans seeds for one whose NodeID's leading-zero count clears (want=true)
// or fails (want=false) difficulty d, skipping any in avoid so the nodes get distinct
// identities. It makes the admission tests deterministic rather than leaning on a lucky
// default seed.
func seedSatisfying(t *testing.T, d int, want bool, avoid ...uint64) uint64 {
	t.Helper()
outer:
	for s := uint64(1); s < 1_000_000; s++ {
		for _, a := range avoid {
			if s == a {
				continue outer
			}
		}
		if pow.Satisfies(identity.FromSeed(seedFor(s)).ID(), d) == want {
			return s
		}
	}
	t.Fatalf("no seed with Satisfies==%v at d=%d", want, d)
	return 0
}

// TestAdmissionInboundPoW: a node with a non-zero PoW difficulty refuses an inbound edge
// from a sub-threshold peer (no registration, conn closed) but admits a peer that clears
// the threshold. This is the admission-PoW gate on the "first appearance" path.
func TestAdmissionInboundPoW(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))

		const d = 1
		aSeed := seedSatisfying(t, d, true)
		subSeed := seedSatisfying(t, d, false, aSeed)
		okSeed := seedSatisfying(t, d, true, aSeed, subSeed)

		a := spawn(t, ctx, hub, aSeed, WithDmin(d))
		sub := spawn(t, ctx, hub, subSeed, WithDmin(d))
		ok := spawn(t, ctx, hub, okSeed, WithDmin(d))

		// Sub-PoW peer: A registers no edge and closes the conn.
		subConn, err := sub.t.Dial(ctx, a.ID(), a.addr)
		if err != nil {
			t.Fatalf("Dial sub: %v", err)
		}
		sendControl(t, subConn, routing.EncodePingFrame)
		synctest.Wait()
		if _, known := a.e.Conn(sub.ID()); known {
			t.Fatal("A registered an edge to a sub-PoW peer")
		}
		// A closed its end → sub's next send observes the closure.
		p := transport.Get()
		w, _ := routing.EncodePingFrame(p.Buf())
		p.SetLen(w)
		if err := subConn.Send(p); !errors.Is(err, transport.ErrConnClosed) {
			t.Fatalf("sub conn Send err = %v, want ErrConnClosed", err)
		}
		p.Release()

		// PoW-valid peer: A admits the inbound edge.
		okConn, err := ok.t.Dial(ctx, a.ID(), a.addr)
		if err != nil {
			t.Fatalf("Dial ok: %v", err)
		}
		sendControl(t, okConn, routing.EncodePingFrame)
		synctest.Wait()
		if _, known := a.e.Conn(ok.ID()); !known {
			t.Fatal("A did not register an edge to a PoW-valid peer")
		}
	})
}

// TestAdmissionOutboundPoW: a successful dial to a sub-threshold peer is not taken as a
// live edge — dialAny (the shared outbound path for Connect/HolePunch/relay) closes the
// winning conn and returns ErrPoWUnmet.
func TestAdmissionOutboundPoW(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))

		const d = 1
		aSeed := seedSatisfying(t, d, true)
		subSeed := seedSatisfying(t, d, false, aSeed)

		a := spawn(t, ctx, hub, aSeed, WithDmin(d))
		sub := spawn(t, ctx, hub, subSeed, WithDmin(d))

		conn, err := a.dialAny(ctx, sub.ID(), []transport.Addr{sub.addr})
		if !errors.Is(err, ErrPoWUnmet) {
			t.Fatalf("dialAny err = %v, want ErrPoWUnmet", err)
		}
		if conn != nil {
			t.Fatal("dialAny returned a conn for a sub-PoW peer")
		}
		if _, known := a.e.Conn(sub.ID()); known {
			t.Fatal("A registered an outgoing edge to a sub-PoW peer")
		}
	})
}

// TestAdmissionKnowledgePoW: a peer's neighbours response carries a contact list a node
// did not vet. A sub-threshold NodeID in that list must be refused entry to the
// knowledge table, so a flood of cheap Sybil IDs cannot pollute the table or be handed
// back out by Closest; a PoW-valid contact from the same list is learned.
func TestAdmissionKnowledgePoW(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))

		const d = 1
		aSeed := seedSatisfying(t, d, true)
		bSeed := seedSatisfying(t, d, true, aSeed)

		a := spawn(t, ctx, hub, aSeed, WithDmin(d))
		b := spawn(t, ctx, hub, bSeed, WithDmin(d)) // PoW-valid sender, clears admission

		sub := kad.ID{0x80, 0xAB, 0xCD}  // 0 leading zero bits — fails d=1
		good := kad.ID{0x40, 0xAB, 0xCD} // 1 leading zero bit — clears d=1
		cs := []routing.Contact{{ID: sub}, {ID: good}}

		// b sends a, addressed to a itself, a neighbours response listing both contacts.
		// The originator is b (PoW-valid), so the frame clears origination-PoW and is
		// delivered; handling it folds the listed contacts into a's knowledge.
		conn, err := b.t.Dial(ctx, a.ID(), a.addr)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		nonce := [routing.LookupNonceLen]byte{0xA1}
		solicit(a.Node, nonce)
		sendControl(t, conn, func(buf []byte) (int, error) {
			return routing.EncodeNeighborsFrame(buf, b.id, b.edPub, a.ID(), 10, time.Now(), nonce, cs)
		})
		synctest.Wait()

		if _, ok := a.k.Get(sub); ok {
			t.Fatal("sub-PoW contact from a neighbours response entered knowledge")
		}
		if _, ok := a.k.Get(good); !ok {
			t.Fatal("PoW-valid contact from a neighbours response was not learned")
		}
	})
}
