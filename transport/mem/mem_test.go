package mem

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/wire"
)

const testType wire.Type = 7

// nodeID derives a deterministic NodeID from a one-byte seed, so tests get
// stable, distinct identities without touching randomness.
func nodeID(seed byte) kad.ID {
	var s [identity.SeedLen]byte
	s[0] = seed
	return identity.FromSeed(s).ID()
}

func addr(name string) transport.Addr {
	return transport.Addr{Net: "mem", Endpoint: name}
}

// sendFrame encodes payload as a wire frame into a pooled Packet and sends it on
// conn. Send borrows the Packet, so the caller Releases it after Send returns.
func sendFrame(t *testing.T, conn transport.Conn, payload []byte) {
	t.Helper()
	p := transport.Get()
	frame, err := wire.EncodeFrame(p.Buf(), testType, payload)
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
	d := <-tr.Inbound()
	typ, payload, _, err := wire.ParseFrame(d.Pkt.Bytes())
	if err != nil {
		d.Pkt.Release()
		t.Fatalf("ParseFrame: %v", err)
	}
	if typ != testType {
		t.Errorf("frame type = %d, want %d", typ, testType)
	}
	out := append([]byte(nil), payload...)
	d.Pkt.Release()
	return out, d.Conn
}

func TestPartitionBlackholesAndHeals(t *testing.T) {
	h := NewHub()
	idA, idB := nodeID(1), nodeID(2)
	a, err := h.New(idA, addr("a"))
	if err != nil {
		t.Fatalf("New a: %v", err)
	}
	bt, err := h.New(idB, addr("b"))
	if err != nil {
		t.Fatalf("New b: %v", err)
	}
	defer a.Close()
	defer bt.Close()
	conn, err := a.Dial(context.Background(), idB, addr("b"))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	// Baseline: the frame gets through.
	sendFrame(t, conn, []byte("hi"))
	if got, _ := recvPayload(t, bt); string(got) != "hi" {
		t.Fatalf("baseline payload = %q, want hi", got)
	}

	// Partitioned: Send reports no error (the edge is up) but nothing is delivered.
	h.Partition(idA, idB)
	sendFrame(t, conn, []byte("lost"))
	select {
	case d := <-bt.Inbound():
		d.Pkt.Release()
		t.Fatal("frame delivered during partition; it should be blackholed")
	default:
	}

	// Healed: delivery resumes.
	h.Heal(idA, idB)
	sendFrame(t, conn, []byte("back"))
	if got, _ := recvPayload(t, bt); string(got) != "back" {
		t.Fatalf("post-heal payload = %q, want back", got)
	}
}

// TestRemoveClearsPerNodeState: closing a transport must drop all per-node soft
// state the Hub holds for it — partitions, directed link profiles, the media-support
// flag — so a re-registration of the same identity starts clean instead of inheriting
// a dead node's partition or link model.
func TestRemoveClearsPerNodeState(t *testing.T) {
	h := NewHub()
	idA, idB := nodeID(1), nodeID(2)
	a, err := h.New(idA, addr("a"))
	if err != nil {
		t.Fatalf("New a: %v", err)
	}
	if _, err := h.New(idB, addr("b")); err != nil {
		t.Fatalf("New b: %v", err)
	}

	h.Partition(idA, idB)
	h.SetLinkProfile(idA, idB, LinkProfile{})
	h.SetMediaSupport(idA, false)

	h.mu.Lock()
	pre := len(h.blocked) == 1 && len(h.links) == 1 && h.noMedia[idA]
	h.mu.Unlock()
	if !pre {
		t.Fatal("setup: per-node state not installed")
	}

	if err := a.Close(); err != nil {
		t.Fatalf("Close a: %v", err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.blocked) != 0 {
		t.Errorf("blocked not cleared: %d entries", len(h.blocked))
	}
	if len(h.links) != 0 {
		t.Errorf("links not cleared: %d entries", len(h.links))
	}
	if len(h.noMedia) != 0 {
		t.Errorf("noMedia not cleared: %d entries", len(h.noMedia))
	}
}

// TestMemConnsBounded: closing an edge must deregister both ends from their owning
// transports, so a long-lived transport that dials and closes many edges does not
// accumulate dead conns until its own Close. Before the fix each end stayed in its
// owner's conns slice forever.
func TestMemConnsBounded(t *testing.T) {
	h := NewHub()
	at, err := h.New(nodeID(1), addr("a"))
	if err != nil {
		t.Fatalf("New a: %v", err)
	}
	bt, err := h.New(nodeID(2), addr("b"))
	if err != nil {
		t.Fatalf("New b: %v", err)
	}
	a := at.(*memTransport)
	b := bt.(*memTransport)

	for range 100 {
		conn, err := a.Dial(context.Background(), b.id, b.addr)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		conn.Close()
	}

	a.connsMu.Lock()
	na := len(a.conns)
	a.connsMu.Unlock()
	b.connsMu.Lock()
	nb := len(b.conns)
	b.connsMu.Unlock()
	if na != 0 || nb != 0 {
		t.Fatalf("conns not reclaimed: a=%d b=%d, want 0,0", na, nb)
	}
}

func TestHubRegister(t *testing.T) {
	h := NewHub()
	idA, idB := nodeID(1), nodeID(2)

	if _, err := h.New(idA, addr("a")); err != nil {
		t.Fatalf("New a: %v", err)
	}
	if _, err := h.New(idB, addr("b")); err != nil {
		t.Fatalf("New b: %v", err)
	}
	if _, err := h.New(nodeID(3), addr("a")); err == nil {
		t.Error("duplicate addr accepted, want error")
	}
	if _, err := h.New(idA, addr("c")); err == nil {
		t.Error("duplicate id accepted, want error")
	}
}

// TestCloseNotBlockedByParkedDeliver: a deliver parked on a full inbound channel
// holds the receiving transport's read lock for the whole channel send; closing an
// UNRELATED edge of the same transport must not wait behind it. Before the fix
// removeConn took the same mutex's write lock, so one undrained receiver plus one
// Conn.Close wedged forever — and since the node's dispatch loop is both the only
// Inbound consumer and the goroutine that closes edges, the whole transport
// deadlocked (the pending writer also blocks every new read lock, so all further
// Sends to the transport froze too). Real time, not synctest: blocking on a mutex
// is not a durably-blocking operation, so the fake clock cannot drive this repro;
// the timeout below is protective only — the green path returns at once.
func TestCloseNotBlockedByParkedDeliver(t *testing.T) {
	h := NewHub(WithInboundBuffer(0))
	xt, err := h.New(nodeID(1), addr("x"))
	if err != nil {
		t.Fatalf("New x: %v", err)
	}
	at, err := h.New(nodeID(2), addr("a"))
	if err != nil {
		t.Fatalf("New a: %v", err)
	}
	bt, err := h.New(nodeID(3), addr("b"))
	if err != nil {
		t.Fatalf("New b: %v", err)
	}
	defer xt.Close()
	defer at.Close()
	defer bt.Close()

	connA, err := at.Dial(context.Background(), nodeID(1), addr("x"))
	if err != nil {
		t.Fatalf("Dial a->x: %v", err)
	}
	connB, err := bt.Dial(context.Background(), nodeID(1), addr("x"))
	if err != nil {
		t.Fatalf("Dial b->x: %v", err)
	}

	// Park a sender on edge A: x's inbound is unbuffered and nobody reads it, so
	// the deliver blocks inside the channel send holding x's read lock.
	sent := make(chan error, 1)
	go func() {
		p := transport.Get()
		p.SetLen(4)
		err := connA.Send(p)
		p.Release()
		sent <- err
	}()
	// Wait until the parked deliver actually holds the read lock: TryLock fails
	// only while a reader is inside, and the parked deliver is the only one.
	x := xt.(*memTransport)
	for x.mu.TryLock() {
		x.mu.Unlock()
		time.Sleep(time.Millisecond)
	}

	// Closing the unrelated edge B must return promptly.
	closed := make(chan struct{})
	go func() {
		connB.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close of an unrelated edge blocked behind a deliver parked on a full inbound channel")
	}

	// Unpark the sender and let it finish.
	d := <-xt.Inbound()
	d.Pkt.Release()
	if err := <-sent; err != nil {
		t.Fatalf("parked Send: %v", err)
	}
}

// TestSendBoundedZeroFallsBackToHubBound: SendBounded documents that a
// non-positive budget falls back to the Hub send bound, exactly as the QUIC conn
// falls back to its transport's send deadline. Before the fix d<=0 was passed
// through to deliverBounded, which treats it as UNBOUNDED — so the send parked
// forever on the very stalled receiver the Hub bound was configured to guard
// against, strictly worse than a plain Send.
func TestSendBoundedZeroFallsBackToHubBound(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const bound = 5 * time.Second
		h := NewHub(WithInboundBuffer(0), WithSendBound(bound))
		xt, err := h.New(nodeID(1), addr("x"))
		if err != nil {
			t.Fatalf("New x: %v", err)
		}
		at, err := h.New(nodeID(2), addr("a"))
		if err != nil {
			t.Fatalf("New a: %v", err)
		}
		defer xt.Close()
		defer at.Close()
		conn, err := at.Dial(context.Background(), nodeID(1), addr("x"))
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}

		// x's inbound is unbuffered and never drained, so the send can only
		// return through the fallback bound.
		mc := conn.(*memConn)
		done := make(chan error, 1)
		go func() {
			p := transport.Get()
			p.SetLen(4)
			err := mc.SendBounded(p, 0)
			p.Release()
			done <- err
		}()

		// Sleep past the Hub bound on the fake clock; a sender that armed the
		// fallback timer has returned by now.
		time.Sleep(bound + time.Second)
		select {
		case err := <-done:
			if !errors.Is(err, transport.ErrConnClosed) {
				t.Fatalf("SendBounded(p, 0) err = %v, want ErrConnClosed", err)
			}
		default:
			// Unpark the sender so the bubble drains, then fail.
			d := <-xt.Inbound()
			d.Pkt.Release()
			<-done
			t.Fatal("SendBounded(p, 0) ignored the Hub send bound and parked past it")
		}
	})
}

// TestSendBoundTimeoutClosesEdge: a Send that trips the Hub send bound reports
// ErrConnClosed — and the edge must actually BE down for both ends afterwards,
// mirroring the QUIC conn tearing the connection down on a tripped send deadline.
// Before the fix the edge stayed open: the sender had just been told the edge is
// dead while the peer kept using it successfully, a split state unreachable on
// the real transport.
func TestSendBoundTimeoutClosesEdge(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := NewHub(WithInboundBuffer(0), WithSendBound(time.Second))
		xt, err := h.New(nodeID(1), addr("x"))
		if err != nil {
			t.Fatalf("New x: %v", err)
		}
		at, err := h.New(nodeID(2), addr("a"))
		if err != nil {
			t.Fatalf("New a: %v", err)
		}
		defer xt.Close()
		defer at.Close()
		conn, err := at.Dial(context.Background(), nodeID(1), addr("x"))
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}

		// x's inbound is unbuffered and never drained: the send trips the bound.
		p := transport.Get()
		p.SetLen(4)
		err = conn.Send(p)
		p.Release()
		if !errors.Is(err, transport.ErrConnClosed) {
			t.Fatalf("bounded Send err = %v, want ErrConnClosed", err)
		}

		// The tripped bound killed the edge for both ends, not just this Send.
		mc := conn.(*memConn)
		select {
		case <-mc.edge.closed:
		default:
			t.Fatal("send-bound timeout left the edge open; the QUIC mirror closes it")
		}
		// The peer end observes the close on its next Send.
		q := transport.Get()
		q.SetLen(4)
		err = mc.peerConn.Send(q)
		q.Release()
		if !errors.Is(err, transport.ErrConnClosed) {
			t.Fatalf("peer Send after the tripped bound: err = %v, want ErrConnClosed", err)
		}
	})
}

// After Close, Dial to the closed transport's address fails (it is deregistered).
// This exercises hub deregistration specifically; the generic ErrNoRoute sentinel
// is covered by the shared contract suite (see contract_test.go).
func TestDialAfterPeerClose(t *testing.T) {
	h := NewHub()
	a, _ := h.New(nodeID(1), addr("a"))
	b, _ := h.New(nodeID(2), addr("b"))
	defer a.Close()
	b.Close()

	_, err := a.Dial(context.Background(), nodeID(2), addr("b"))
	if !errors.Is(err, transport.ErrNoRoute) {
		t.Errorf("Dial to closed peer: err = %v, want ErrNoRoute", err)
	}
}
