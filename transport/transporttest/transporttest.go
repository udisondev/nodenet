// Package transporttest is a shared contract suite for transport.Transport
// implementations. The semantics a transport must provide — authenticated
// bidirectional edges keyed by NodeID, a single Inbound stream, borrow-Send,
// close propagation, and the dial error sentinels — are the same whether the
// pipe is the in-memory hub or production QUIC. RunContract runs those
// assertions against any implementation supplied through a Factory, so both
// transport/mem and transport/quic prove they are drop-in equivalents by passing
// the identical tests.
//
// It is a normal (non _test.go) package so the test files of both mem and quic
// can import it. It depends on transport, wire, identity and kad — none of
// which depend on it, so there is no import cycle.
package transporttest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/wire"
)

// TestType is the wire frame type the suite uses for its payloads. 15 is in the
// unassigned range of the wire.Type registry (see the doc on wire.Type), so suite
// frames can never be mistaken for a real protocol message. Exported so the
// registry-uniqueness test in node can account for it alongside the protocol types.
const TestType wire.Type = 15

// IDFromSeed derives the deterministic NodeID a Factory must bind for a given
// seed, so a test can name the dial target without holding the identity.
func IDFromSeed(seed byte) kad.ID {
	var s [identity.SeedLen]byte
	s[0] = seed
	return identity.FromSeed(s).ID()
}

// Factory builds transports for the suite and controls how a test body is run.
// A fresh Factory is created per subtest (see RunContract), so implementations
// may hold per-subtest state such as a shared in-memory hub.
type Factory interface {
	// New creates a transport whose NodeID is IDFromSeed(seed) and returns it
	// together with the Addr peers dial to reach it. The transport must be closed
	// at test end (register t.Cleanup).
	New(t *testing.T, seed byte) (transport.Transport, transport.Addr)

	// Run executes fn as the test body. The in-memory factory wraps it in
	// testing/synctest (deterministic fake clock); the QUIC factory runs it
	// directly under real time. Suite bodies are therefore written clock-agnostic.
	Run(t *testing.T, fn func(t *testing.T))

	// NoRouteAddr returns an address at which no peer can ever be reached, so a
	// Dial to it must fail with ErrNoRoute (an unregistered hub name for mem; a
	// dead UDP endpoint for quic).
	NoRouteAddr() transport.Addr
}

// RunContract runs the full transport contract suite. newFactory must return a
// fresh Factory each call so subtests do not share identities or sockets.
func RunContract(t *testing.T, newFactory func() Factory) {
	t.Helper()
	cases := []struct {
		name string
		fn   func(t *testing.T, f Factory)
	}{
		{"FrameExchange", frameExchange},
		{"SendBorrowsPacket", sendBorrowsPacket},
		{"Bidirectional", bidirectional},
		{"CloseConnPropagation", closeConnPropagation},
		{"DialIdentityMismatch", dialIdentityMismatch},
		{"DialNoRoute", dialNoRoute},
		{"TransportCloseClosesInbound", transportCloseClosesInbound},
	}
	for _, c := range cases {
		f := newFactory()
		t.Run(c.name, func(t *testing.T) { c.fn(t, f) })
	}
}

// sendFrame encodes payload into a pooled Packet and sends it on conn. Send
// borrows the Packet, so the caller Releases it after Send returns.
func sendFrame(t *testing.T, conn transport.Conn, payload []byte) {
	t.Helper()
	p := transport.Get()
	frame, err := wire.EncodeFrame(p.Buf(), TestType, payload)
	if err != nil {
		p.Release()
		t.Fatalf("EncodeFrame: %v", err)
	}
	p.SetLen(len(frame))
	err = conn.Send(p)
	p.Release()
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
}

// recvPayload reads one delivery, parses the frame, returns the payload (copied)
// and the Conn it arrived on, and Releases the Packet.
func recvPayload(t *testing.T, tr transport.Transport) ([]byte, transport.Conn) {
	t.Helper()
	d, ok := <-tr.Inbound()
	if !ok {
		t.Fatalf("Inbound closed before a delivery arrived; it must stay open until Transport.Close")
	}
	typ, payload, _, err := wire.ParseFrame(d.Pkt.Bytes())
	if err != nil {
		d.Pkt.Release()
		t.Fatalf("ParseFrame: %v", err)
	}
	if typ != TestType {
		t.Errorf("frame type = %d, want %d", typ, TestType)
	}
	out := append([]byte(nil), payload...)
	d.Pkt.Release()
	return out, d.Conn
}

// frameExchange: A dials B and sends one frame; B receives it on its single
// inbound stream, tagged with a Conn whose Remote() is A — proving the edge is
// keyed by NodeID.
func frameExchange(t *testing.T, f Factory) {
	f.Run(t, func(t *testing.T) {
		a, _ := f.New(t, 1)
		b, baddr := f.New(t, 2)
		idA, idB := IDFromSeed(1), IDFromSeed(2)

		conn, err := a.Dial(context.Background(), idB, baddr)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		if conn.Remote() != idB {
			t.Errorf("dialer conn Remote = %v, want B", conn.Remote())
		}

		sendFrame(t, conn, []byte("ping"))

		got, via := recvPayload(t, b)
		if string(got) != "ping" {
			t.Errorf("B received %q, want ping", got)
		}
		if via.Remote() != idA {
			t.Errorf("B's delivery Conn Remote = %v, want A", via.Remote())
		}
	})
}

// sendBorrowsPacket: Send borrows the Packet rather than taking ownership — after
// Send returns the caller still owns the buffer and reuses it for the next frame,
// then Releases it once. Under -tags transportdebug, reusing Buf() after Send
// would panic if Send had wrongly Released it, so this guards the contract.
func sendBorrowsPacket(t *testing.T, f Factory) {
	f.Run(t, func(t *testing.T) {
		a, _ := f.New(t, 1)
		b, baddr := f.New(t, 2)

		conn, err := a.Dial(context.Background(), IDFromSeed(2), baddr)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}

		p := transport.Get()
		frame, _ := wire.EncodeFrame(p.Buf(), TestType, []byte("first"))
		p.SetLen(len(frame))
		if err := conn.Send(p); err != nil {
			t.Fatalf("Send: %v", err)
		}
		// Still ours: reuse the SAME buffer for a second frame.
		frame, _ = wire.EncodeFrame(p.Buf(), TestType, []byte("second"))
		p.SetLen(len(frame))
		if err := conn.Send(p); err != nil {
			t.Fatalf("Send reuse: %v", err)
		}
		p.Release()

		got1, _ := recvPayload(t, b)
		got2, _ := recvPayload(t, b)
		if string(got1) != "first" || string(got2) != "second" {
			t.Errorf("received %q, %q; want first, second", got1, got2)
		}
	})
}

// bidirectional: B replies on the SAME Conn it received on, and A gets the reply
// on its inbound stream — the transport-level basis of a NAT node forwarding back
// over the edge it accepted.
func bidirectional(t *testing.T, f Factory) {
	f.Run(t, func(t *testing.T) {
		a, _ := f.New(t, 1)
		b, baddr := f.New(t, 2)
		idB := IDFromSeed(2)

		conn, err := a.Dial(context.Background(), idB, baddr)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		sendFrame(t, conn, []byte("ping"))

		_, bConn := recvPayload(t, b)
		sendFrame(t, bConn, []byte("pong"))

		got, aConn := recvPayload(t, a)
		if string(got) != "pong" {
			t.Errorf("A received %q, want pong", got)
		}
		if aConn.Remote() != idB {
			t.Errorf("A's reply Conn Remote = %v, want B", aConn.Remote())
		}
	})
}

// closeConnPropagation: closing one end of an edge propagates — the peer end's
// next Send returns ErrConnClosed, and the closing end's own Send does too. Send
// must not touch the packet on error (the caller still owns and Releases it).
func closeConnPropagation(t *testing.T, f Factory) {
	f.Run(t, func(t *testing.T) {
		a, _ := f.New(t, 1)
		b, baddr := f.New(t, 2)

		near, err := a.Dial(context.Background(), IDFromSeed(2), baddr)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		sendFrame(t, near, []byte("hello"))
		_, far := recvPayload(t, b)

		if err := near.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		// The closing end sees its edge down at once; the peer end sees it once the
		// close propagates (instant for mem, a network round-trip for quic), so its
		// Send is retried to ErrConnClosed.
		mustEventuallyClosedSend(t, near, "near")
		mustEventuallyClosedSend(t, far, "far")
	})
}

// mustEventuallyClosedSend sends small packets on conn until one returns
// ErrConnClosed, retrying across the close-propagation delay. Send must never
// touch the packet on error, so the caller Releases it each attempt. Under
// synctest the sleeps advance the fake clock; an end that has already observed
// the close returns ErrConnClosed on the first attempt.
func mustEventuallyClosedSend(t *testing.T, conn transport.Conn, label string) {
	t.Helper()
	for range 200 {
		p := transport.Get()
		p.SetLen(4)
		err := conn.Send(p)
		p.Release()
		if errors.Is(err, transport.ErrConnClosed) {
			return
		}
		if err != nil {
			t.Fatalf("%s.Send: unexpected err = %v, want ErrConnClosed", label, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s.Send never returned ErrConnClosed", label)
}

// dialIdentityMismatch: dialing the address of a peer that authenticates as a
// different NodeID than asked for returns ErrIdentityMismatch.
func dialIdentityMismatch(t *testing.T, f Factory) {
	f.Run(t, func(t *testing.T) {
		a, _ := f.New(t, 1)
		_, baddr := f.New(t, 2)

		_, err := a.Dial(context.Background(), IDFromSeed(99), baddr)
		if !errors.Is(err, transport.ErrIdentityMismatch) {
			t.Errorf("Dial wrong id: err = %v, want ErrIdentityMismatch", err)
		}
	})
}

// dialNoRoute: dialing an address where no peer can be reached returns
// ErrNoRoute.
func dialNoRoute(t *testing.T, f Factory) {
	f.Run(t, func(t *testing.T) {
		a, _ := f.New(t, 1)
		_, err := a.Dial(context.Background(), IDFromSeed(2), f.NoRouteAddr())
		if !errors.Is(err, transport.ErrNoRoute) {
			t.Errorf("Dial unreachable addr: err = %v, want ErrNoRoute", err)
		}
	})
}

// transportCloseClosesInbound: closing a transport closes its inbound stream so a
// ranging receiver drains and exits; Close is idempotent.
func transportCloseClosesInbound(t *testing.T, f Factory) {
	f.Run(t, func(t *testing.T) {
		a, _ := f.New(t, 1)
		if err := a.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if _, ok := <-a.Inbound(); ok {
			t.Error("Inbound delivered after Close, want closed channel")
		}
		if err := a.Close(); err != nil {
			t.Errorf("second Close: %v", err)
		}
	})
}
