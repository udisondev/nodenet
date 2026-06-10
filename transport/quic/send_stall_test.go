//go:build e2e_real

package quic

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/transport/transporttest"
)

// TestSendDeadlineTearsDownStuckEdge: a peer that stops reading (its Inbound is never
// drained, so its read loop back-pressures the stream) must not be able to block the
// sender's Send indefinitely. With a short send deadline the write trips, the edge is
// torn down, and Send reports ErrConnClosed — the signal the dispatch loop turns into a
// disjoint-path fallback and re-dial, instead of a node-wide stall.
func TestSendDeadlineTearsDownStuckEdge(t *testing.T) {
	const deadline = 300 * time.Millisecond
	a, err := Listen(idFromSeed(1), "127.0.0.1:0", WithSendDeadline(deadline), WithHandshakeTimeout(2*time.Second))
	if err != nil {
		t.Fatalf("Listen a: %v", err)
	}
	defer a.Close()
	// b never drains its Inbound(), so once its buffer fills its read loop blocks and the
	// QUIC flow-control window backs up to a's writes.
	b, err := Listen(idFromSeed(2), "127.0.0.1:0", WithHandshakeTimeout(2*time.Second))
	if err != nil {
		t.Fatalf("Listen b: %v", err)
	}
	defer b.Close()

	conn, err := a.Dial(context.Background(), transporttest.IDFromSeed(2), b.LocalAddr())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	// Flood large frames until a write trips the deadline. A healthy bound means this
	// terminates well before the (generous) cap and reports the edge closed.
	payload := make([]byte, transport.MaxPacketLen-8)
	start := time.Now()
	var sendErr error
	for i := 0; i < 100_000; i++ {
		p := transport.Get()
		copy(p.Buf(), payload)
		p.SetLen(len(payload))
		sendErr = conn.Send(p)
		p.Release()
		if sendErr != nil {
			break
		}
		if time.Since(start) > 10*time.Second {
			t.Fatal("Send never tripped the deadline; it would have stalled the dispatch loop")
		}
	}
	if !errors.Is(sendErr, transport.ErrConnClosed) {
		t.Fatalf("Send err = %v, want ErrConnClosed", sendErr)
	}
	// The edge is torn down: a further Send fails fast.
	p := transport.Get()
	p.SetLen(1)
	if err := conn.Send(p); !errors.Is(err, transport.ErrConnClosed) {
		t.Fatalf("post-teardown Send err = %v, want ErrConnClosed", err)
	}
	p.Release()
}
