package node

import (
	"context"
	"encoding/binary"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/rendezvous"
	"github.com/udisondev/nodenet/routing"
	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/transport/mem"
	"github.com/udisondev/nodenet/wire"
)

// closeRecordConn is a transport.Conn that records whether Close was called, for the
// edge-teardown and admission tests below.
type closeRecordConn struct {
	id     kad.ID
	closed atomic.Bool
}

func (c *closeRecordConn) Remote() kad.ID               { return c.id }
func (c *closeRecordConn) RemoteAddr() transport.Addr   { return transport.Addr{} }
func (c *closeRecordConn) Send(*transport.Packet) error { return nil }
func (c *closeRecordConn) Close() error                 { c.closed.Store(true); return nil }

// TestHandleMalformedClosesUnregisteredConn (F1): a peer-initiated conn that is not a
// live edge and sends an unparseable frame bypasses the admission block, so it never
// reaches the PoW gate. handle must close it (counting the drop) instead of leaving it
// open as an untracked zombie that pins an inbound slot.
func TestHandleMalformedClosesUnregisteredConn(t *testing.T) {
	n := newBareNode(t, 1)
	conn := &closeRecordConn{id: identityID(2)}
	p := transport.Get()
	p.SetLen(copy(p.Buf(), []byte{0xFF, 0xFF, 0xFF})) // bad version → ParseFrame fails

	n.handle(transport.Delivery{Conn: conn, Pkt: p})

	if !conn.closed.Load() {
		t.Fatal("unregistered conn with a malformed frame was not closed")
	}
	if got := n.Stats().DroppedMalformed; got != 1 {
		t.Fatalf("DroppedMalformed = %d, want 1", got)
	}
	if _, known := n.e.Conn(conn.id); known {
		t.Fatal("a malformed first frame registered an edge")
	}
}

// TestDropEdgeClosesConn (F13): dropping a live edge must close its transport.Conn —
// otherwise the connection, its read loop and (on the peer) the inbound slot live on
// as a zombie nothing reaps.
func TestDropEdgeClosesConn(t *testing.T) {
	n := newBareNode(t, 1)
	conn := &closeRecordConn{id: identityID(2)}
	if err := n.e.AddEdge(conn, true, 0, time.Now()); err != nil {
		t.Fatalf("AddEdge: %v", err)
	}
	n.dropEdge(conn.id, "test")
	if !conn.closed.Load() {
		t.Fatal("dropEdge did not close the edge's conn")
	}
	if _, known := n.e.Conn(conn.id); known {
		t.Fatal("dropEdge did not remove the edge")
	}
}

// TestHandleLeaveClosesConn (F13): a TypeLeave from a live neighbour reaps the edge,
// which must close the conn (graceful-leave path through dropEdge).
func TestHandleLeaveClosesConn(t *testing.T) {
	n := newBareNode(t, 1)
	conn := &closeRecordConn{id: identityID(2)}
	if err := n.e.AddEdge(conn, false, 0, time.Now()); err != nil {
		t.Fatalf("AddEdge: %v", err)
	}
	p := transport.Get()
	w, err := routing.EncodeLeaveFrame(p.Buf())
	if err != nil {
		t.Fatalf("EncodeLeaveFrame: %v", err)
	}
	p.SetLen(w)
	n.handle(transport.Delivery{Conn: conn, Pkt: p})
	if !conn.closed.Load() {
		t.Fatal("TypeLeave reaped the edge without closing its conn")
	}
}

// TestTypeAppPerEdgeRateLimit (F7): app frames land in the shared delivery channel, so
// they must be throttled per edge like routed deliveries — a flood beyond the per-edge
// forward burst is shed and counted, not allowed to starve the channel unbounded.
func TestTypeAppPerEdgeRateLimit(t *testing.T) {
	n := newBareNode(t, 1)
	conn := stubConn{id: identityID(2)}
	if err := n.e.AddEdge(conn, false, 0, time.Now()); err != nil {
		t.Fatalf("AddEdge: %v", err)
	}
	// Nobody reads Deliveries(); send well past the per-edge forward burst.
	const flood = routing.ForwardBurst + 256
	for range flood {
		p := transport.Get()
		frame, err := wire.EncodeFrame(p.Buf(), TypeApp, []byte("x"))
		if err != nil {
			p.Release()
			t.Fatalf("EncodeFrame: %v", err)
		}
		p.SetLen(len(frame))
		n.handle(transport.Delivery{Conn: conn, Pkt: p})
	}
	if got := n.Stats().DroppedRateLimited; got == 0 {
		t.Fatal("TypeApp flood past the burst was not rate-limited (no per-edge throttle)")
	}
}

// TestHelloForgedEdPubDoesNotPoisonOriginLimit (F6): the per-originator rate-limit
// must be charged only AFTER the envelope signature is verified. A hello carrying a
// forged EdPub (no private key to sign it) must fail verify and create no limiter
// bucket — otherwise an attacker both bypasses the throttle (a fresh forged originator
// each time) and floods the bucket map.
func TestHelloForgedEdPubDoesNotPoisonOriginLimit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := newBareNode(t, 1)
		peer := n.ID()
		peer[1] ^= 0x21
		edge := stubConn{id: peer}
		if err := n.e.AddEdge(edge, true, 0, time.Now()); err != nil {
			t.Fatalf("AddEdge: %v", err)
		}

		const flood = 500
		for i := range flood {
			// A distinct forged originator key each time (dmin=0, so origination-PoW
			// passes), with NO valid envelope signature — verify must reject it.
			var ed [32]byte
			binary.BigEndian.PutUint64(ed[24:], uint64(i+1))
			h := rendezvous.Hello{Nonce: [rendezvous.NonceLen]byte{byte(i)}}
			payload, err := rendezvous.MarshalHello(&h)
			if err != nil {
				t.Fatalf("MarshalHello: %v", err)
			}
			// A fresh timestamp so the envelope passes the freshness check, but NO valid
			// signature — verify must be what rejects it.
			msg := routing.Msg{Target: n.ID(), TTL: routing.MaxHops, EdPub: ed, Sent: time.Now().UnixNano(), Payload: payload}
			buf := make([]byte, 1024)
			w, err := routing.EncodeMsgFrame(buf, rendezvous.TypeHello, &msg)
			if err != nil {
				t.Fatalf("EncodeMsgFrame: %v", err)
			}
			p := transport.Get()
			p.SetLen(copy(p.Buf(), buf[:w]))
			n.handle(transport.Delivery{Conn: edge, Pkt: p})
		}
		synctest.Wait()

		n.originLimit.mu.Lock()
		buckets := len(n.originLimit.buckets)
		n.originLimit.mu.Unlock()
		if buckets != 0 {
			t.Fatalf("forged-EdPub hellos created %d origin-limit buckets; want 0", buckets)
		}
		if got := n.Stats().DroppedBadSig; got < flood {
			t.Fatalf("DroppedBadSig = %d, want >= %d (verify must run before the rate limit)", got, flood)
		}
	})
}

// TestRunReturnsOnGracefulLeaveWithStalledNeighbour (F17): graceful leave fans a
// Leave frame to every neighbour at shutdown. A neighbour whose inbound buffer is full
// and undrained would, with an unbounded send, hang the fan-out's wait forever and Run
// would never return. The bounded forward send caps each leave, so Run returns.
func TestRunReturnsOnGracefulLeaveWithStalledNeighbour(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// No WithSendBound on the hub: without the bounded forward send the leave would
		// block forever (and synctest would flag the deadlock).
		hub := mem.NewHub(mem.WithInboundBuffer(1))
		aIdn := identity.FromSeed(seedFor(1))
		aT, err := hub.New(aIdn.ID(), transport.Addr{Net: "mem", Endpoint: "a"})
		if err != nil {
			t.Fatalf("New a: %v", err)
		}
		a := New(aIdn, aT) // maintenance on by default — graceful leave runs at shutdown
		bIdn := identity.FromSeed(seedFor(2))
		if _, err := hub.New(bIdn.ID(), transport.Addr{Net: "mem", Endpoint: "b"}); err != nil {
			t.Fatalf("New b: %v", err) // B never runs, so its inbound is never drained
		}

		conn, err := aT.Dial(context.Background(), bIdn.ID(), transport.Addr{Net: "mem", Endpoint: "b"})
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		if err := a.e.AddEdge(conn, true, 0, time.Now()); err != nil {
			t.Fatalf("AddEdge: %v", err)
		}
		// Fill B's inbound buffer (cap 1) so the graceful-leave send to B blocks.
		fill := transport.Get()
		fill.SetLen(1)
		_ = conn.Send(fill)
		fill.Release()

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { _ = a.Run(ctx); close(done) }()
		synctest.Wait() // the maintenance loop settles idle before any keepalive tick
		cancel()        // → graceful leave fans a Leave to the stalled B

		select {
		case <-done:
		case <-time.After(time.Minute):
			t.Fatal("Run did not return: graceful leave wedged on a stalled neighbour")
		}
	})
}

// identityID returns the NodeID for test seed s, matching newBareNode's derivation.
func identityID(s uint64) kad.ID {
	return identity.FromSeed(seedFor(s)).ID()
}

// TestDeliveriesClosesOnRun (F25): the delivery channel must close when Run returns, so
// a consumer ranging Deliveries() unblocks on shutdown instead of leaking its goroutine.
func TestDeliveriesClosesOnRun(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := newBareNode(t, 1)
		consumed := make(chan struct{})
		go func() {
			for range n.Deliveries() {
			}
			close(consumed)
		}()

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			_ = n.Run(ctx)
			close(done)
		}()
		synctest.Wait()
		cancel()
		<-done
		synctest.Wait()
		select {
		case <-consumed:
		default:
			t.Fatal("Deliveries() did not close on Run shutdown (consumer leaked)")
		}
	})
}
