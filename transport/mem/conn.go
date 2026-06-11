package mem

import (
	"sync"
	"time"

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

// memConn is one end of a paired edge. owner is the transport that HOLDS this end
// (where it is registered for cleanup); peerOwner is the transport that receives what
// this end sends; peerConn is the other end, used to tag deliveries so the receiver
// can reply on the same link.
type memConn struct {
	remote     kad.ID
	remoteAddr transport.Addr
	owner      *memTransport
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

// SendBounded is Send with an explicit per-send budget, mirroring the QUIC conn's
// method so the node's forward path can cap a single send independently of the Hub's
// global send bound — a stalled receiver then cannot freeze the dispatch loop even
// when the Hub has no send bound. A non-positive d falls back to the Hub bound. It
// borrows p exactly like Send.
func (c *memConn) SendBounded(p *transport.Packet, d time.Duration) error {
	select {
	case <-c.edge.closed:
		return transport.ErrConnClosed
	default:
	}
	if c.peerOwner.hub.isBlocked(c.peerConn.remote, c.remote) {
		return nil
	}
	if d <= 0 {
		// Fall back to the Hub bound, as the QUIC conn falls back to its
		// transport's send deadline (sendBound is immutable after NewHub).
		d = c.peerOwner.hub.sendBound
	}
	dst := transport.Get()
	dst.SetLen(copy(dst.Buf(), p.Bytes()))
	if err := c.peerOwner.deliverBounded(transport.Delivery{Conn: c.peerConn, Pkt: dst}, c.edge, d); err != nil {
		dst.Release()
		return err
	}
	return nil
}

// Close tears down the link. It is idempotent and, because both ends share one
// edge, the peer end observes ErrConnClosed on its next Send. It also deregisters
// both ends from their owning transports' conn lists, so a long-lived transport's
// list does not grow without bound as edges come and go (it is reclaimed in full
// only at transport Close otherwise). removeConn is a no-op for an end already gone.
func (c *memConn) Close() error {
	c.edge.close()
	if c.owner != nil {
		c.owner.removeConn(c)
	}
	if c.peerConn != nil && c.peerConn.owner != nil {
		c.peerConn.owner.removeConn(c.peerConn)
	}
	return nil
}
