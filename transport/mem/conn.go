package mem

import (
	"sync"

	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/transport"
)

var _ transport.Conn = (*memConn)(nil)

// edge is the shared teardown state of one bidirectional link. Both ends of the
// link reference the same edge, so closing either end closes the link for both.
type edge struct {
	closed chan struct{}
	once   sync.Once
}

func (e *edge) close() {
	e.once.Do(func() { close(e.closed) })
}

// memConn is one end of a paired edge. peerOwner is the transport that receives
// what this end sends, and peerConn is the other end, used to tag deliveries so
// the receiver can reply on the same link.
type memConn struct {
	remote     kad.ID
	remoteAddr transport.Addr
	peerOwner  *memTransport
	peerConn   *memConn
	edge       *edge
}

func (c *memConn) Remote() kad.ID             { return c.remote }
func (c *memConn) RemoteAddr() transport.Addr { return c.remoteAddr }

// Send copies the frame into a fresh pooled Packet on the receiving side and
// delivers it — mirroring QUIC, where the peer receives its own copy and the
// sender's buffer is free once the bytes are on the wire. Send BORROWS p: it
// copies out of p synchronously and never Releases it, so the caller keeps
// ownership and Releases p exactly once after Send returns. A closed edge returns
// ErrConnClosed (p untouched). The fresh Packet on the receiving side is owned by
// whoever reads it off Inbound; on a failed deliver Send Releases that one.
func (c *memConn) Send(p *transport.Packet) error {
	select {
	case <-c.edge.closed:
		return transport.ErrConnClosed
	default:
	}

	// A simulated partition blackholes the frame: the edge is up (no error), but the
	// bytes never arrive — the receiver hears nothing, so its keepalive eventually
	// times the edge out, exactly as a real network outage would. c.remote is the
	// receiver; c.peerConn.remote is this end's owner (the sender).
	if c.peerOwner.hub.isBlocked(c.peerConn.remote, c.remote) {
		return nil
	}

	dst := transport.Get()
	dst.SetLen(copy(dst.Buf(), p.Bytes()))

	if err := c.peerOwner.deliver(transport.Delivery{Conn: c.peerConn, Pkt: dst}, c.edge); err != nil {
		dst.Release()
		return err
	}
	return nil
}

// Close tears down the link. It is idempotent and, because both ends share one
// edge, the peer end observes ErrConnClosed on its next Send.
func (c *memConn) Close() error {
	c.edge.close()
	return nil
}
