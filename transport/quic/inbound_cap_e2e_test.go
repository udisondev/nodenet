//go:build e2e_real

package quic

import (
	"context"
	"testing"
	"time"

	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/transport/transporttest"
)

// TestInboundCapEndToEnd drives the global inbound cap over real loopback QUIC. With a
// server capped at two concurrent inbound connections, a client opens three; the server
// admits two and tears the third down right after its handshake, before any read loop. We
// assert it server-side — counting the distinct edges that actually deliver a frame —
// rather than on the dialer, because a refused dial can still momentarily look successful
// to the client (the server closes it a beat after the handshake completes). This is the
// end-to-end counterpart to the unit-level cap accounting tests: it proves an adversary
// cannot accumulate unbounded inbound connections on a public node.
func TestInboundCapEndToEnd(t *testing.T) {
	server, err := Listen(idFromSeed(1), "127.0.0.1:0",
		WithHandshakeTimeout(2*time.Second),
		WithMaxInbound(2),
		WithMaxInboundPerIP(0), // isolate the global cap
	)
	if err != nil {
		t.Fatalf("Listen server: %v", err)
	}
	t.Cleanup(func() { server.Close() })
	saddr := server.LocalAddr()
	sid := transporttest.IDFromSeed(1)

	client, err := Listen(idFromSeed(2), "127.0.0.1:0", WithHandshakeTimeout(2*time.Second))
	if err != nil {
		t.Fatalf("Listen client: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	dial := func() (transport.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return client.Dial(ctx, sid, saddr)
	}

	// Open three connections, sequentially so the server admits them in order, and send a
	// frame on each so an admitted edge surfaces a delivery while a refused one stays silent.
	for i := 0; i < 3; i++ {
		c, derr := dial()
		if derr != nil {
			continue // a refused dial may surface as an error here — fine, it delivers nothing
		}
		defer c.Close()
		p := transport.Get()
		p.SetLen(copy(p.Buf(), []byte("ping")))
		_ = c.Send(p)
		p.Release()
		time.Sleep(150 * time.Millisecond)
	}

	// Count the distinct server-side edges that delivered a frame within a short window.
	// The cap allows exactly two; the third connection is torn down and delivers nothing.
	seen := make(map[transport.Conn]bool)
	deadline := time.After(2 * time.Second)
drain:
	for {
		select {
		case d := <-server.Inbound():
			if d.Conn != nil {
				seen[d.Conn] = true
			}
			d.Pkt.Release()
		case <-deadline:
			break drain
		}
	}

	if len(seen) != 2 {
		t.Fatalf("server delivered frames from %d distinct edges; cap is 2 (cap not enforced)", len(seen))
	}
}
