package node

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/rendezvous"
	"github.com/udisondev/nodenet/routing"
	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/transport/mem"
)

// fixedReader yields a constant byte forever — a deterministic nonce source so a test
// knows exactly which nonce a Rendezvous will use and can craft replies that carry it.
type fixedReader byte

func (f fixedReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(f)
	}
	return len(p), nil
}

// linkBoth wires a bidirectional pair of edges a<->b, so a routed reply can find its
// way home the same greedy way the request travelled out.
func linkBoth(t *testing.T, ctx context.Context, a, b *testNode) {
	t.Helper()
	link(t, ctx, a, b)
	link(t, ctx, b, a)
}

// replyFrame builds a complete TypeReply wire frame addressed to target (A), with the
// routing envelope's originator key set from signer (so it clears PoW) and rep as the
// payload. It is how a test injects a reply — genuine or forged — into A's inbound.
func replyFrame(t *testing.T, target kad.ID, signer *identity.Identity, rep *rendezvous.Reply) []byte {
	t.Helper()
	payload, err := rendezvous.MarshalReply(rep)
	if err != nil {
		t.Fatalf("MarshalReply: %v", err)
	}
	var edPub [32]byte
	copy(edPub[:], signer.EdPublic())
	msg := routing.Msg{Target: target, TTL: routing.MaxHops, EdPub: edPub, Payload: payload}
	routing.SignMsg(signer, rendezvous.TypeReply, &msg, time.Now()) // stamps a fresh timestamp
	buf := make([]byte, transport.MaxPacketLen)
	w, err := routing.EncodeMsgFrame(buf, rendezvous.TypeReply, &msg)
	if err != nil {
		t.Fatalf("EncodeMsgFrame: %v", err)
	}
	return buf[:w]
}

// sendFrame delivers raw frame bytes over conn (a dialled edge into the target node).
func sendFrame(t *testing.T, conn transport.Conn, frame []byte) {
	t.Helper()
	p := transport.Get()
	defer p.Release()
	p.SetLen(copy(p.Buf(), frame))
	if err := conn.Send(p); err != nil {
		t.Fatalf("send frame: %v", err)
	}
}

// TestRendezvousDirect: A discovers R by routing a signed hello to R's NodeID and
// verifying R's routed reply — over a bidirectional edge, the smallest end-to-end
// handshake. A ends up with R's authenticated keys and coordinates.
func TestRendezvousDirect(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))

		a := spawn(t, ctx, hub, 5)
		r := spawn(t, ctx, hub, 1)
		linkBoth(t, ctx, a, r)

		rctx, rcancel := context.WithTimeout(ctx, 30*time.Second)
		defer rcancel()
		res, err := a.Rendezvous(rctx, r.ID())
		if err != nil {
			t.Fatalf("Rendezvous: %v", err)
		}

		if res.Target != r.ID() {
			t.Errorf("Target = %v, want %v", res.Target, r.ID())
		}
		if identity.DeriveID(res.EdPub[:]) != r.ID() {
			t.Error("EdPub does not hash to R's NodeID (anti-MITM check would fail)")
		}
		rident := identity.FromSeed(seedFor(1))
		if res.XPub != rident.KEXPublic() {
			t.Error("XPub != R's static X25519 public key")
		}
		// R's keys/coordinates were folded into A's knowledge.
		if c, ok := a.Knowledge().Get(r.ID()); !ok || c.XPub != rident.KEXPublic() {
			t.Error("A did not learn R's contact from the rendezvous")
		}
	})
}

// TestRendezvousForgedReplyRejected: a forwarder that sees the hello learns the nonce
// and forges a reply in R's place, but it cannot produce R's key, so A's VerifyReply
// rejects it (DeriveID(ed_pub) != NodeID_R). The genuine reply, carrying the same
// nonce and R's real key, is accepted. A deterministic nonce (WithRand) lets the test
// craft both replies precisely.
func TestRendezvousForgedReplyRejected(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))

		// A uses a constant nonce source, so we know the handshake nonce is all 0x07.
		a := spawn(t, ctx, hub, 5, WithRand(fixedReader(0x07)))
		var nonce [rendezvous.NonceLen]byte
		for i := range nonce {
			nonce[i] = 0x07
		}
		// A needs one edge to launch the hello from; m drops it (m is not R), so the
		// only replies A ever sees are the ones we inject.
		m := spawn(t, ctx, hub, 8)
		link(t, ctx, a, m)
		conn, err := m.t.Dial(ctx, a.ID(), a.addr)
		if err != nil {
			t.Fatalf("Dial A: %v", err)
		}

		rIdent := identity.FromSeed(seedFor(1)) // the real R (not running; we sign as it)
		target := rIdent.ID()

		type rzvOut struct {
			res RendezvousResult
			err error
		}
		out := make(chan rzvOut, 1)
		rctx, rcancel := context.WithTimeout(ctx, time.Hour)
		defer rcancel()
		go func() {
			res, err := a.Rendezvous(rctx, target)
			out <- rzvOut{res, err}
		}()
		synctest.Wait() // hello originated, pending registered, A blocked on the reply

		// Forged: signed by a different identity, with the stolen nonce.
		forger := identity.FromSeed(seedFor(9))
		forged := rendezvous.Reply{XPub: forger.KEXPublic(), Addrs: []transport.Addr{{Net: "mem", Endpoint: "forger"}}, Nonce: nonce}
		rendezvous.SignReply(forger, &forged)
		sendFrame(t, conn, replyFrame(t, a.ID(), forger, &forged))
		synctest.Wait()
		select {
		case o := <-out:
			t.Fatalf("rendezvous completed on a forged reply: err=%v target=%v", o.err, o.res.Target)
		default:
		}

		// Genuine: signed by R, same nonce.
		genuine := rendezvous.Reply{XPub: rIdent.KEXPublic(), Addrs: []transport.Addr{{Net: "mem", Endpoint: "R"}}, Nonce: nonce}
		rendezvous.SignReply(rIdent, &genuine)
		sendFrame(t, conn, replyFrame(t, a.ID(), rIdent, &genuine))
		synctest.Wait()
		select {
		case o := <-out:
			if o.err != nil {
				t.Fatalf("genuine reply rejected: %v", o.err)
			}
			if o.res.Target != target || identity.DeriveID(o.res.EdPub[:]) != target {
				t.Error("result did not carry R's verified identity")
			}
			if o.res.XPub != rIdent.KEXPublic() {
				t.Error("result XPub != R's key")
			}
		default:
			t.Fatal("rendezvous did not complete on the genuine reply")
		}
	})
}

// TestRendezvousSubPoWHelloDropped: with a non-zero PoW difficulty, A's hello is
// dropped at the first honest hop because A's NodeID does not clear the threshold, so
// R never replies and the rendezvous deadline fires.
func TestRendezvousSubPoWHelloDropped(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))

		// A's identity is picked deterministically below the threshold (seedSatisfying)
		// — a lucky-seed skip could silently turn this security test off if the ID
		// derivation ever changed.
		const dmin = 8
		aSeed := seedSatisfying(t, dmin, false)
		rSeed := seedSatisfying(t, dmin, true, aSeed)
		a := spawn(t, ctx, hub, aSeed, WithDmin(dmin))
		r := spawn(t, ctx, hub, rSeed, WithDmin(dmin))
		linkBoth(t, ctx, a, r)

		rctx, rcancel := context.WithTimeout(ctx, 10*time.Second)
		defer rcancel()
		if _, err := a.Rendezvous(rctx, r.ID()); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Rendezvous err = %v, want DeadlineExceeded (hello dropped at first honest hop)", err)
		}
	})
}

// TestRendezvousUnroutable: with no live edge to launch from, Rendezvous fails fast
// with ErrUnroutable rather than waiting out the deadline.
func TestRendezvousUnroutable(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))

		a := spawn(t, ctx, hub, 5)
		if _, err := a.Rendezvous(ctx, kad.ID{1, 2, 3}); !errors.Is(err, ErrUnroutable) {
			t.Fatalf("Rendezvous err = %v, want ErrUnroutable", err)
		}
	})
}

// TestSealedBoxOverOverlay: the connectionless e2e path. A seals a message to R's
// static X25519 key and routes the opaque box over the multi-hop overlay with an
// ordinary Send; the forwarders carry ciphertext, and only R can Open it, recovering
// the plaintext and A's authenticated identity. The node layer stays out of it — the
// box is just a payload.
func TestSealedBoxOverOverlay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))

		r := spawn(t, ctx, hub, 1)
		mids := make([]*testNode, 0, 4)
		for s := uint64(2); s <= 5; s++ {
			mids = append(mids, spawn(t, ctx, hub, s))
		}
		src := chainToward(t, ctx, r.ID(), r, mids)

		// Sealing/Opening is application work: it holds the identities directly.
		rIdent := identity.FromSeed(seedFor(1))
		plaintext := []byte("direct-channel coordinates")
		box, err := rendezvous.Seal(fixedReader(0x11), src.id, rIdent.KEXPublic(), plaintext, nil, time.Now())
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		// The sealed box must not contain the plaintext (forwarders see only ciphertext).
		if bytes.Contains(box, plaintext) {
			t.Fatal("sealed box leaks plaintext")
		}

		if err := src.Send(r.ID(), box); err != nil {
			t.Fatalf("Send: %v", err)
		}
		synctest.Wait()

		select {
		case got := <-r.Deliveries():
			senderID, pt, err := rendezvous.Open(rIdent, got.Payload, nil, time.Now(), time.Hour)
			if err != nil {
				t.Fatalf("Open at R: %v", err)
			}
			if senderID != src.ID() {
				t.Errorf("sender = %v, want A %v", senderID, src.ID())
			}
			if !bytes.Equal(pt, plaintext) {
				t.Errorf("plaintext = %q, want %q", pt, plaintext)
			}
		default:
			t.Fatal("R received nothing")
		}
	})
}

// TestRendezvousConverged: rendezvous works over a self-organized topology, not just a
// hand-wired one — a maintained cluster bootstraps itself into a connected graph, then
// one member discovers another by NodeID.
func TestRendezvousConverged(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))

		const n = 5
		nodes := make([]*testNode, 0, n)
		for s := uint64(1); s <= n; s++ {
			nodes = append(nodes, spawn(t, ctx, hub, s, WithMaintenance(testMaint())))
		}
		// Bootstrap every node with every other so the maintenance loops dial out and
		// the graph converges (each edge is bidirectional once both ends dial).
		for _, nd := range nodes {
			boot := make([]routing.Contact, 0, n-1)
			for _, other := range nodes {
				if other != nd {
					boot = append(boot, contactOf(other))
				}
			}
			nd.Bootstrap(boot)
		}
		time.Sleep(20 * time.Second)
		synctest.Wait()

		a, r := nodes[0], nodes[n-1]
		rctx, rcancel := context.WithTimeout(ctx, 30*time.Second)
		defer rcancel()
		res, err := a.Rendezvous(rctx, r.ID())
		if err != nil {
			t.Fatalf("Rendezvous over converged cluster: %v", err)
		}
		if identity.DeriveID(res.EdPub[:]) != r.ID() {
			t.Error("converged rendezvous returned an unverified identity")
		}
	})
}
