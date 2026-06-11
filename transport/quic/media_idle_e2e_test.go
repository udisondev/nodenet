//go:build e2e_real

package quic

import (
	"context"
	"testing"
	"time"

	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/transport/transporttest"
)

// TestMediaIdleReaperClosesParkedInbound: an accepted media session whose peer goes
// silent must be reaped within ~mediaIdleTimeout by the session's own idle reaper,
// independent of the dialer's advertised QUIC idle. The dialer here keeps the QUIC
// connection alive with keepalive PINGs (the standard media config) but sends no
// app frames, so only the app-frame reaper — not QUIC's idle — can close it.
func TestMediaIdleReaperClosesParkedInbound(t *testing.T) {
	b, err := Listen(idFromSeed(2), "127.0.0.1:0", WithHandshakeTimeout(2*time.Second))
	if err != nil {
		t.Fatalf("Listen b: %v", err)
	}
	defer b.Close()
	a, err := Listen(idFromSeed(1), "127.0.0.1:0", WithHandshakeTimeout(2*time.Second))
	if err != nil {
		t.Fatalf("Listen a: %v", err)
	}
	defer a.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sess, err := a.(transport.Media).OpenMedia(ctx, transporttest.IDFromSeed(2), b.LocalAddr())
	if err != nil {
		t.Fatalf("OpenMedia: %v", err)
	}
	defer sess.Close()

	var accepted transport.MediaSession
	select {
	case accepted = <-b.(transport.Media).InboundMedia():
	case <-ctx.Done():
		t.Fatal("no inbound media session surfaced")
	}

	// a sends nothing. b's accepted session must be reaped by its idle reaper.
	select {
	case <-accepted.Closed():
		// reaped within the idle window, as required
	case <-time.After(mediaIdleTimeout + 5*time.Second):
		t.Fatal("parked inbound media session was not reaped (peer-advertised idle would pin it)")
	}
}

// TestMediaIdleReaperSparesActiveCall: a session that keeps receiving frames must
// NOT be reaped — the reaper only closes a peer gone silent, never a live call.
func TestMediaIdleReaperSparesActiveCall(t *testing.T) {
	b, err := Listen(idFromSeed(4), "127.0.0.1:0", WithHandshakeTimeout(2*time.Second))
	if err != nil {
		t.Fatalf("Listen b: %v", err)
	}
	defer b.Close()
	a, err := Listen(idFromSeed(3), "127.0.0.1:0", WithHandshakeTimeout(2*time.Second))
	if err != nil {
		t.Fatalf("Listen a: %v", err)
	}
	defer a.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sess, err := a.(transport.Media).OpenMedia(ctx, transporttest.IDFromSeed(4), b.LocalAddr())
	if err != nil {
		t.Fatalf("OpenMedia: %v", err)
	}
	defer sess.Close()
	accepted := <-b.(transport.Media).InboundMedia()

	// Keep sending frames across more than one idle window; the session must stay open.
	stop := time.After(mediaIdleTimeout * 3 / 2)
	tick := time.NewTicker(mediaKeepAlive)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			p := transport.GetMedia()
			p.SetLen(copy(p.Buf(), []byte("x")))
			_ = sess.SendDatagram(17, p)
			p.Release()
		case <-accepted.Closed():
			t.Fatal("active call was reaped despite continuous frames")
		case <-stop:
			return // survived as required
		}
	}
}
