//go:build e2e_real

package quic

import (
	"context"
	"errors"
	"testing"
	"time"

	quicgo "github.com/quic-go/quic-go"
	"github.com/udisondev/nodenet/transport"
)

// mediaPairE2E opens a media session between two loopback transports and
// returns both ends as their concrete type, so a test can misbehave on the raw
// QUIC connection underneath.
func mediaPairE2E(t *testing.T) (near, far *mediaSession) {
	t.Helper()
	srv := listenLoopback(t, idFromByte(2), WithHandshakeTimeout(2*time.Second))
	cli := listenLoopback(t, idFromByte(1), WithHandshakeTimeout(2*time.Second))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sess, err := cli.(transport.Media).OpenMedia(ctx, idFromByte(2).ID(), srv.LocalAddr())
	if err != nil {
		t.Fatalf("OpenMedia: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	var accepted transport.MediaSession
	select {
	case accepted = <-srv.(transport.Media).InboundMedia():
	case <-ctx.Done():
		t.Fatal("no inbound media session surfaced")
	}
	return sess.(*mediaSession), accepted.(*mediaSession)
}

// TestMediaExtraBidiStreamsAreDrained: the media subprotocol uses datagrams and
// uni message streams only — never a bidirectional stream — so an ACCEPTED media
// session must reset any bidi stream its peer opens. quic-go would otherwise
// buffer the unread stream's bytes up to the connection flow-control window:
// data that never passes the session's level-2 receive budget (which is charged
// only on the datagram and uni-stream paths). The session's drain resets every
// bidi stream, so a write into one is stopped (STOP_SENDING) instead of
// silently absorbed — the media mirror of the overlay edge's extra-stream drain.
func TestMediaExtraBidiStreamsAreDrained(t *testing.T) {
	near, _ := mediaPairE2E(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	bidi, err := near.qconn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("open bidi on media connection: %v", err)
	}
	_ = bidi.SetWriteDeadline(time.Now().Add(4 * time.Second))
	blob := make([]byte, 2<<20) // 2 MiB, well past one connection FC window
	_, werr := bidi.Write(blob)
	if werr == nil {
		t.Fatal("write into a media bidi stream succeeded fully; acceptor absorbed it past the rx budget")
	}
	// The error must be an acceptor-initiated stream reset (STOP_SENDING), not our
	// own write deadline — that would mean the acceptor silently buffered the data.
	var serr *quicgo.StreamError
	if !asStreamError(werr, &serr) {
		t.Fatalf("media bidi write err = %v, want a stream reset from the acceptor", werr)
	}
}

// TestMediaDialedSessionDeniesPeerBidi: a DIALED media session controls its own
// QUIC config (unlike the acceptor, whose shared listener config must keep bidi
// open for overlay edges), so it denies the peer bidirectional streams outright:
// the open fails at the stream limit instead of a stream quietly buffering
// toward a session that never reads it.
func TestMediaDialedSessionDeniesPeerBidi(t *testing.T) {
	_, far := mediaPairE2E(t)

	_, err := far.qconn.OpenStream()
	var limitErr *quicgo.StreamLimitReachedError
	if !errors.As(err, &limitErr) {
		t.Fatalf("OpenStream toward the dialed session: err = %v, want StreamLimitReachedError", err)
	}
}
