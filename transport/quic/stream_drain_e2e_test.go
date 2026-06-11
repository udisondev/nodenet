//go:build e2e_real

package quic

import (
	"context"
	"crypto/rand"
	"net"
	"testing"
	"time"

	quicgo "github.com/quic-go/quic-go"
)

// TestExtraStreamsAreDrained: on an accepted overlay edge a peer must not be able to
// park data in streams beyond the single overlay bidi. quic-go would otherwise buffer
// an unread stream's bytes up to the connection flow-control window — data that never
// passes the per-frame PoW gate. The accept-path drain resets every extra stream, so a
// write into one is stopped (STOP_SENDING) instead of silently absorbed.
func TestExtraStreamsAreDrained(t *testing.T) {
	srv, err := Listen(idFromByte(2), "127.0.0.1:0", WithHandshakeTimeout(2*time.Second))
	if err != nil {
		t.Fatalf("Listen srv: %v", err)
	}
	defer srv.Close()

	// Raw attacker: a quic-go transport that speaks the overlay ALPN with a valid cert,
	// so the handshake and admission succeed, then misbehaves by opening extra streams.
	cert, err := buildCert(idFromByte(9), rand.Reader)
	if err != nil {
		t.Fatalf("buildCert: %v", err)
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer udp.Close()
	atk := &quicgo.Transport{Conn: udp}
	defer atk.Close()

	tlsConf := tlsConfig(cert)
	tlsConf.NextProtos = []string{alpn}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srvAddr, _ := net.ResolveUDPAddr("udp", srv.LocalAddr().Endpoint)
	conn, err := atk.Dial(ctx, srvAddr, tlsConf, &quicgo.Config{})
	if err != nil {
		t.Fatalf("attacker Dial: %v", err)
	}

	// The legitimate single overlay bidi (handleAccepted takes it; the drain ignores it).
	overlay, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("open overlay bidi: %v", err)
	}
	if _, err := overlay.Write([]byte{0}); err != nil {
		t.Fatalf("overlay first byte: %v", err)
	}

	// An EXTRA uni stream stuffed with data: the server must reset it (STOP_SENDING),
	// so a large write eventually errors instead of being absorbed up to the FC window.
	uni, err := conn.OpenUniStreamSync(ctx)
	if err != nil {
		t.Fatalf("open extra uni: %v", err)
	}
	_ = uni.SetWriteDeadline(time.Now().Add(4 * time.Second))
	blob := make([]byte, 2<<20) // 2 MiB, well past one connection FC window
	_, werr := uni.Write(blob)
	if werr == nil {
		t.Fatal("write into an extra uni stream succeeded fully; server absorbed it past the PoW gate")
	}
	// The error must be a server-initiated stream reset (STOP_SENDING), not our own
	// write deadline — that would mean the server silently absorbed and stalled us.
	var serr *quicgo.StreamError
	if !asStreamError(werr, &serr) {
		t.Fatalf("extra uni write err = %v, want a stream reset from the server", werr)
	}
}

// asStreamError reports whether err is a quic-go StreamError and binds it.
func asStreamError(err error, target **quicgo.StreamError) bool {
	for err != nil {
		if se, ok := err.(*quicgo.StreamError); ok {
			*target = se
			return true
		}
		type unwrap interface{ Unwrap() error }
		u, ok := err.(unwrap)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
