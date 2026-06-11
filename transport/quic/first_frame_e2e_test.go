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

// TestFirstFrameTimeoutReapsSilentInbound: a peer that completes the cheap (non-PoW)
// handshake and opens the bidi stream but never sends a first frame must be reaped
// after the first-frame timeout, freeing its admission slot. Otherwise it is a free
// slowloris pinning inbound capacity until the (long) idle timeout.
func TestFirstFrameTimeoutReapsSilentInbound(t *testing.T) {
	const budget = 300 * time.Millisecond
	b, err := Listen(idFromSeed(2), "127.0.0.1:0",
		WithFirstFrameTimeout(budget), WithHandshakeTimeout(2*time.Second))
	if err != nil {
		t.Fatalf("Listen b: %v", err)
	}
	defer b.Close()
	a, err := Listen(idFromSeed(1), "127.0.0.1:0", WithHandshakeTimeout(2*time.Second))
	if err != nil {
		t.Fatalf("Listen a: %v", err)
	}
	defer a.Close()

	conn, err := a.Dial(context.Background(), transporttest.IDFromSeed(2), b.LocalAddr())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	// a deliberately sends nothing. b's read loop arms the first-frame deadline; once it
	// expires b reaps the connection, which propagates back to a. Wait past the budget,
	// then a single Send must observe the edge closed.
	time.Sleep(budget + time.Second)
	p := transport.Get()
	p.SetLen(1)
	err = conn.Send(p)
	p.Release()
	if !errors.Is(err, transport.ErrConnClosed) {
		t.Fatalf("Send after first-frame timeout = %v, want ErrConnClosed (slot was pinned)", err)
	}
}

// TestFirstFrameTimeoutSparesActiveEdge: an edge that delivers its first frame must
// NOT be reaped by the first-frame bound, even if it then goes quiet far longer than
// the budget — liveness is the overlay keepalive's job from the first frame on.
func TestFirstFrameTimeoutSparesActiveEdge(t *testing.T) {
	const budget = 300 * time.Millisecond
	b, err := Listen(idFromSeed(4), "127.0.0.1:0",
		WithFirstFrameTimeout(budget), WithHandshakeTimeout(2*time.Second))
	if err != nil {
		t.Fatalf("Listen b: %v", err)
	}
	defer b.Close()
	a, err := Listen(idFromSeed(3), "127.0.0.1:0", WithHandshakeTimeout(2*time.Second))
	if err != nil {
		t.Fatalf("Listen a: %v", err)
	}
	defer a.Close()

	conn, err := a.Dial(context.Background(), transporttest.IDFromSeed(4), b.LocalAddr())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	// First frame arrives, clearing the bound on b's side.
	first := transport.Get()
	first.SetLen(1)
	if err := conn.Send(first); err != nil {
		t.Fatalf("first Send: %v", err)
	}
	first.Release()
	d := <-b.Inbound()
	d.Pkt.Release()

	// Stay quiet well past the budget; the edge must remain usable.
	time.Sleep(budget * 3)
	second := transport.Get()
	second.SetLen(1)
	err = conn.Send(second)
	second.Release()
	if err != nil {
		t.Fatalf("Send on a quiet-but-established edge = %v, want nil (must not be reaped)", err)
	}
}
