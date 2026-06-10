package transport

import "github.com/udisondev/nodenet/kad"

// Conn is one live, authenticated, bidirectional edge to a peer, keyed by the
// peer's NodeID. It is the unit recursive routing forwards over: a frame sent on
// a Conn arrives in order at the peer, and the peer can send frames back on the
// SAME Conn — which is why a NAT node that dialed out can still receive requests
// and forward them.
//
// Conn is frame-oriented: each Send moves one whole wire frame over a reliable,
// ordered channel; received frames surface on Transport.Inbound, tagged with the
// Conn they came in on, not via a per-Conn read method. Bulk traffic does not go
// here — only small control and rendezvous frames — so a framed edge, not a byte
// stream, is the right shape.
type Conn interface {
	// Remote returns the authenticated NodeID of the peer. For QUIC it is the
	// identity proven by the peer's certificate; for the in-memory transport it
	// is fixed when the edge is wired. This is the routing key.
	Remote() kad.ID

	// RemoteAddr returns the peer's endpoint as observed on this edge: the
	// dialed address for an outbound edge, the peer's source address for an
	// accepted one. Upper layers echo it in pong replies — that echo is how a
	// peer learns its reflexive (NAT-mapped) address — and feed it to
	// subnet-diversity accounting.
	RemoteAddr() Addr

	// Send transmits one frame to the peer. It BORROWS p for the duration of the
	// call: it copies whatever it needs synchronously and does not touch p after
	// returning — on success or error — so the CALLER keeps ownership and must
	// Release p exactly once. Borrowing rather than taking ownership is what makes
	// zero-copy forwarding work: a transit frame is sent on in the same buffer it
	// arrived in, the forwarder can retry the next neighbour with that same buffer
	// on a failed Send (local repair), and an originator can reuse one buffer for
	// several disjoint copies — all with no re-allocation. Send returns
	// ErrConnClosed if the edge is down (p is untouched, still the caller's).
	Send(p *Packet) error

	// Close tears the edge down. It is idempotent, and closing one end propagates
	// to the peer end (the peer observes ErrConnClosed on its next Send and stops
	// receiving on this edge).
	Close() error
}
