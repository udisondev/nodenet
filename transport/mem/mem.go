// Package mem is the in-memory transport: a deterministic, channel-based
// implementation of transport.Transport for tests. It mirrors enough of the QUIC
// transport's semantics — bidirectional edges keyed by NodeID, framed send/recv,
// a single inbound stream, authenticated dial — that code written against the
// transport.Transport interface runs unchanged on both, but it does no crypto and
// no I/O, so a cluster of mem transports runs fully deterministically under
// testing/synctest with the fake clock. The overlay plane spawns no goroutines
// at all; the media plane (transport.Media, see media.go) runs a pump and a
// watchdog per session — they exit when the session or its transport closes, so
// tests that close what they open keep the synctest bubble drainable.
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
	"time"

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

	in      chan transport.Delivery     // single inbound stream; closed by Close
	inMedia chan transport.MediaSession // inbound media sessions; closed by Close
	done    chan struct{}               // closed first by Close to unblock in-flight delivers

	mu     sync.RWMutex // guards closed; RLock held across a delivery into in so Close cannot close the channel underneath
	closed bool

	// connsMu guards the registration lists alone and is never held across a
	// blocking send, so deregistering one edge cannot wait behind a deliver
	// parked on another edge's frame under mu. That matters because the node's
	// dispatch loop — the only Inbound consumer — closes edges synchronously:
	// a removeConn waiting for a parked deliver would deadlock the transport
	// against its own consumer (the QUIC transport's deliver avoids the same
	// trap by releasing its lock before the channel send).
	connsMu sync.Mutex
	conns   []*memConn
	media   []*memMediaSession

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
	// near is the dialer's handle; far is the peer's view of the same edge. owner is the
	// transport that holds each end (where it is registered for cleanup): near lives in
	// the dialer t, far in the peer.
	near := &memConn{remote: peer.id, remoteAddr: peer.addr, owner: t, peerOwner: peer, edge: e}
	far := &memConn{remote: t.id, remoteAddr: t.addr, owner: peer, peerOwner: t, edge: e}
	near.peerConn = far
	far.peerConn = near

	if !t.addConn(near) {
		return nil, transport.ErrConnClosed
	}
	if !peer.addConn(far) {
		// Second registration failed: deregister near so a failed dial leaves no
		// dangling conn in the dialer's list.
		t.removeConn(near)
		near.edge.close()
		return nil, transport.ErrNoRoute
	}
	return near, nil
}

// removeConn deregisters c from this transport's conn list (swap-removal). It is a
// no-op if c is absent (already removed, or Close took the whole list — the scan of
// the nil snapshot finds nothing). It takes only connsMu, so Conn.Close stays a
// light operation that never waits behind a parked deliver.
func (t *memTransport) removeConn(c *memConn) {
	t.connsMu.Lock()
	defer t.connsMu.Unlock()
	for i, x := range t.conns {
		if x == c {
			last := len(t.conns) - 1
			t.conns[i] = t.conns[last]
			t.conns[last] = nil
			t.conns = t.conns[:last]
			return
		}
	}
}

// addConn registers a conn for Close cleanup; it reports false if the transport
// is already closed. Holding mu's read lock across the append pairs the add with
// Close: a conn either lands before Close's write lock — and is then in the
// snapshot Close tears down — or the add observes closed and is refused. The
// nesting order is always mu before connsMu, and connsMu is never held across
// anything blocking, so the pair cannot deadlock.
func (t *memTransport) addConn(c *memConn) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.closed {
		return false
	}
	t.connsMu.Lock()
	t.conns = append(t.conns, c)
	t.connsMu.Unlock()
	return true
}

// deliver pushes one frame onto this transport's inbound stream. It holds RLock
// for the whole channel operation so Close cannot close in underneath it, and
// selects on done and the edge so a backpressured send is freed when either the
// receiving transport or the edge closes. With a Hub send bound set, a deliver that
// cannot make progress within the bound closes the edge and returns ErrConnClosed —
// mirroring the QUIC send deadline so a stalled receiver cannot wedge the sender
// forever.
func (t *memTransport) deliver(d transport.Delivery, e *edge) error {
	return t.deliverBounded(d, e, t.hub.sendBound)
}

// deliverBounded is deliver with an explicit per-send bound: a non-positive bound is
// unbounded (the historical default), a positive one closes the edge and returns
// ErrConnClosed if the send cannot make progress within it. The node's forward path
// passes a positive bound so a stalled receiver cannot wedge the single dispatch loop
// even when the Hub has no global send bound. Under testing/synctest the bound runs
// on the fake clock.
func (t *memTransport) deliverBounded(d transport.Delivery, e *edge, bound time.Duration) error {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.closed {
		return transport.ErrConnClosed
	}
	if bound <= 0 {
		select {
		case t.in <- d:
			return nil
		case <-t.done:
			return transport.ErrConnClosed
		case <-e.closed:
			return transport.ErrConnClosed
		}
	}
	// Fast path: deliver without arming a timer when the channel has room.
	select {
	case t.in <- d:
		return nil
	case <-t.done:
		return transport.ErrConnClosed
	case <-e.closed:
		return transport.ErrConnClosed
	default:
	}
	timer := time.NewTimer(bound)
	defer timer.Stop()
	select {
	case t.in <- d:
		return nil
	case <-t.done:
		return transport.ErrConnClosed
	case <-e.closed:
		return transport.ErrConnClosed
	case <-timer.C:
		// A tripped bound means the receiver stalled past its budget: declare the
		// edge dead and tear it down for BOTH ends, exactly like the QUIC conn
		// closing itself on a tripped send deadline. ErrConnClosed must never be
		// reported for an edge that is still alive — the peer would keep sending
		// on a link this side has already written off.
		e.close()
		return transport.ErrConnClosed
	}
}

// Close stops accepting, tears down every edge and media session, and closes
// the inbound streams. It closes done first to unblock any in-flight delivery,
// then takes the write lock (which drains RLock-holding delivers) before
// closing in and inMedia, so neither is ever closed with a sender still
// writing to it. The registration lists are snapshotted under connsMu after
// closed is set: a registration racing Close either landed before the write
// lock (and is in the snapshot) or observes closed and is refused, so no edge
// escapes the teardown. Media sessions finish asynchronously: closing their
// shared edges makes each pump unwind and drain its own channels. Idempotent.
func (t *memTransport) Close() error {
	t.closeOnce.Do(func() {
		close(t.done)
		t.mu.Lock()
		t.closed = true
		t.mu.Unlock()

		t.connsMu.Lock()
		conns := t.conns
		t.conns = nil
		media := t.media
		t.media = nil
		t.connsMu.Unlock()

		for _, c := range conns {
			c.edge.close()
		}
		for _, s := range media {
			s.edge.close()
		}
		t.hub.remove(t)
		close(t.in)
		close(t.inMedia)
	})
	return nil
}
