// Package mem is the in-memory transport: a deterministic, channel-based
// implementation of transport.Transport for tests. It mirrors enough of the QUIC
// transport's semantics — bidirectional edges keyed by NodeID, framed send/recv,
// a single inbound stream, authenticated dial — that code written against the
// transport.Transport interface runs unchanged on both, but it does no crypto, no
// I/O, and spawns no background goroutines, so a cluster of mem transports runs
// fully deterministically under testing/synctest with the fake clock.
//
// A Hub is the shared fabric: every mem transport registers with one Hub, and
// Dial resolves a peer through it and wires a paired edge. Bring up N transports
// on a Hub and you have the fabric the node-level cluster harness in package node
// builds on; the tests here exercise transport-level behaviour (framed exchange,
// the bidirectional-edge router property, edge teardown) on its own. The Hub is
// also where tests inject churn: Partition blackholes all traffic between a pair
// of NodeIDs — established edges stay up but their frames vanish, and fresh dials
// fail — until Heal restores the link, a deterministic stand-in for a network
// outage.
package mem

import (
	"context"
	"sync"

	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/transport"
)

var _ transport.Transport = (*memTransport)(nil)

// memTransport is one node's attachment to a Hub. All frames arriving on all of
// its edges surface on the single in channel returned by Inbound.
type memTransport struct {
	hub  *Hub
	id   kad.ID
	addr transport.Addr

	in   chan transport.Delivery // single inbound stream; closed by Close
	done chan struct{}           // closed first by Close to unblock in-flight delivers

	mu     sync.RWMutex // guards closed/conns; RLock held across a delivery into in
	closed bool
	conns  []*memConn

	closeOnce sync.Once
}

func (t *memTransport) LocalID() kad.ID                    { return t.id }
func (t *memTransport) LocalAddr() transport.Addr          { return t.addr }
func (t *memTransport) Inbound() <-chan transport.Delivery { return t.in }

// Dial opens a paired edge to the peer registered at addr. The peer must have
// authenticated as remoteID (here: be registered under it), else
// ErrIdentityMismatch; an unregistered address is ErrNoRoute.
func (t *memTransport) Dial(
	ctx context.Context,
	remoteID kad.ID,
	addr transport.Addr,
) (transport.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	peer, ok := t.hub.lookup(addr)
	if !ok {
		return nil, transport.ErrNoRoute
	}
	if peer.id != remoteID {
		return nil, transport.ErrIdentityMismatch
	}
	// A partition is a full communication outage, not just dropped data: the
	// handshake itself cannot complete, so the peer is unreachable until Heal.
	if t.hub.isBlocked(t.id, remoteID) {
		return nil, transport.ErrNoRoute
	}

	e := &edge{closed: make(chan struct{})}
	// near is the dialer's handle; far is the peer's view of the same edge.
	near := &memConn{remote: peer.id, remoteAddr: peer.addr, peerOwner: peer, edge: e}
	far := &memConn{remote: t.id, remoteAddr: t.addr, peerOwner: t, edge: e}
	near.peerConn = far
	far.peerConn = near

	if !t.addConn(near) {
		return nil, transport.ErrConnClosed
	}
	if !peer.addConn(far) {
		near.edge.close()
		return nil, transport.ErrNoRoute
	}
	return near, nil
}

// addConn registers a conn for Close cleanup; it reports false if the transport
// is already closed.
func (t *memTransport) addConn(c *memConn) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return false
	}
	t.conns = append(t.conns, c)
	return true
}

// deliver pushes one frame onto this transport's inbound stream. It holds RLock
// for the whole channel operation so Close cannot close in underneath it, and
// selects on done and the edge so a backpressured send is freed when either the
// receiving transport or the edge closes.
func (t *memTransport) deliver(d transport.Delivery, e *edge) error {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.closed {
		return transport.ErrConnClosed
	}
	select {
	case t.in <- d:
		return nil
	case <-t.done:
		return transport.ErrConnClosed
	case <-e.closed:
		return transport.ErrConnClosed
	}
}

// Close stops accepting, tears down every edge, and closes the inbound stream.
// It closes done first to unblock any in-flight delivery, then takes the write
// lock (which drains RLock-holding delivers) before closing in, so in is never
// closed with a sender still writing to it. Idempotent.
func (t *memTransport) Close() error {
	t.closeOnce.Do(func() {
		close(t.done)
		t.mu.Lock()
		t.closed = true
		conns := t.conns
		t.conns = nil
		t.mu.Unlock()

		for _, c := range conns {
			c.edge.close()
		}
		t.hub.remove(t)
		close(t.in)
	})
	return nil
}
