package node

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/routing"
	"github.com/udisondev/nodenet/transport"
)

// closeConn is a no-op Conn that records whether Close was called, for asserting that
// a refused admission really tears the channel down.
type closeConn struct {
	id     kad.ID
	closed *atomic.Bool
}

func (c closeConn) Remote() kad.ID               { return c.id }
func (c closeConn) RemoteAddr() transport.Addr   { return transport.Addr{} }
func (c closeConn) Send(*transport.Packet) error { return nil }
func (c closeConn) Close() error                 { c.closed.Store(true); return nil }

// TestInboundFullConnRefused: a peer-initiated conn arriving when the inbound-edge cap
// is already reached must be refused outright — closed and its frame dropped, like a
// sub-PoW peer — not left open as an untracked zombie. An unregistered conn has no
// rate-limit bucket and is invisible to the keepalive/reap scan, so serving it would
// hand the population past the cap unmetered service that nothing ever reaps.
func TestInboundFullConnRefused(t *testing.T) {
	n := newBareNode(t, 1)
	now := time.Now()

	// Fill the inbound cap with stub edges (distinct IDs, all != self).
	for i := range routing.InboundCap {
		id := n.ID()
		id[10], id[11] = byte(i), byte(i>>8)
		id[12] ^= 0xAA
		if err := n.e.AddEdge(stubConn{id: id}, false, 0, now); err != nil {
			t.Fatalf("AddEdge #%d: %v", i, err)
		}
	}

	over := n.ID()
	over[1] ^= 0x77
	closed := &atomic.Bool{}
	conn := closeConn{id: over, closed: closed}

	p := transport.Get()
	w, err := routing.EncodePingFrame(p.Buf())
	if err != nil {
		t.Fatalf("EncodePingFrame: %v", err)
	}
	p.SetLen(w)
	n.handle(transport.Delivery{Conn: conn, Pkt: p})

	if _, ok := n.e.Conn(over); ok {
		t.Fatal("over-cap conn was registered as an edge")
	}
	if !closed.Load() {
		t.Fatal("over-cap conn was left open; want it closed like a refused admission")
	}
	if n.Stats().DroppedInboundFull == 0 {
		t.Fatal("the refusal was not counted in stats")
	}
}
