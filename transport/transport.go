// Package transport is the pipe of nodenet: it delivers bytes between nodes,
// authenticated to a NodeID, and nothing else. It is the one polymorphic boundary
// of the system — a QUIC implementation for production and an in-memory
// implementation for deterministic tests — behind a single Transport interface,
// so everything above it (routing, node) is written once and runs on both.
//
// # What a Transport provides
//
// A Transport authenticates each peer to its kad.ID, dials outbound edges, and
// accepts inbound ones. Every edge is a Conn: a live, authenticated, bidirectional
// channel keyed by the peer's NodeID. "Bidirectional" is load-bearing — a node
// that dialed out can still receive on that same Conn, which is exactly what lets
// a NAT node forward overlay traffic and become a full router rather than a
// leaf.
//
// Edges are frame-oriented, not stream-oriented: each send and receive moves one
// whole wire frame. The overlay carries only small control and rendezvous frames;
// bulk traffic goes directly between endpoints, never over the overlay, so a
// framed channel is the right granularity and keeps the in-memory mirror faithful
// to QUIC.
//
// # How frames arrive
//
// All frames from all of a Transport's edges arrive on a single channel,
// Inbound, each wrapped in a Delivery that carries the Conn it came in on. The
// routing layer runs one select-loop over Inbound and replies or forwards on
// Delivery.Conn — the basis of recursive forwarding. There is no separate Accept:
// a newly accepted edge surfaces as the first Delivery carrying a Conn the router
// has not seen, and the router registers it as a live edge on first sight.
//
// # Layering
//
// transport sits one notch above kad and imports only it (for kad.ID). It does
// NOT import wire: a Packet is an opaque pooled buffer, and building a frame into
// it — wire.EncodeFrame(p.Buf(), …) then p.SetLen(…) — is the job of node, which
// composes wire (codec) with transport (pipe). transport moves bytes without
// interpreting them.
package transport

import (
	"context"
	"errors"

	"github.com/udisondev/nodenet/kad"
)

// Delivery is one item from a Transport's inbound stream: a frame that arrived,
// together with the edge it arrived on. The receiver owns Pkt and must Release it
// once it has parsed (and copied out anything it needs to keep). To reply or
// forward, send on Conn.
type Delivery struct {
	Conn Conn    // the live edge the frame arrived on; reply via Conn.Send
	Pkt  *Packet // the received frame; the receiver Releases it after use
}

// Transport is the sole polymorphic boundary of nodenet (a QUIC implementation
// for production, an in-memory one for tests). It authenticates peers to their
// NodeID, dials and accepts bidirectional edges, and surfaces all inbound frames
// on a single channel.
type Transport interface {
	// LocalID returns this transport's own NodeID.
	LocalID() kad.ID

	// LocalAddr returns the endpoint peers dial to reach this transport.
	LocalAddr() Addr

	// Dial opens an authenticated bidirectional edge to remoteID at addr. It
	// blocks until the edge is established, ctx is cancelled, or it fails. On
	// success Conn.Remote() == remoteID; an implementation that finds the peer
	// authenticated as a different identity returns ErrIdentityMismatch, and a
	// peer that cannot be located returns ErrNoRoute.
	Dial(ctx context.Context, remoteID kad.ID, addr Addr) (Conn, error)

	// Inbound returns the stream of frames arriving on every edge this transport
	// dialed or accepted. There is exactly one Inbound channel per Transport;
	// routing runs a single select-loop over it. It is closed when the Transport
	// is closed, which a ranging receiver observes as the channel draining shut.
	Inbound() <-chan Delivery

	// Close shuts the transport down: it stops accepting, closes every Conn, and
	// closes the Inbound channel. It is idempotent.
	Close() error
}

// Puncher is an optional capability a Transport may implement: sending a raw
// NAT-punch datagram toward addr on the shared socket, without a Conn. It opens the
// local NAT mapping (and, for a restricted NAT, the inbound permission for addr)
// ahead of a coordinated simultaneous dial. A caller discovers it by type-asserting a
// Transport to Puncher; the in-memory transport does not implement it (it has no NAT
// to punch), so hole-punch orchestration is a no-op there.
//
// PunchTo is best-effort and connectionless: it neither blocks for nor confirms a
// reply. Confirmation is the QUIC handshake that follows on the punched path, which
// authenticates the peer to its NodeID — so a punch sent to a wrong address only
// wastes a datagram, it cannot misdirect a connection.
type Puncher interface {
	PunchTo(addr Addr) error
}

// IPAddressed is an optional capability a Transport may implement to report that its
// endpoint addresses are real IP host:port pairs. The node layer uses it to default to
// IP subnet-diversity accounting (reflexive consensus across independent /24s or /64s,
// live-edge failure-domain diversification) when the caller did not set a SubnetFunc —
// so a deployer cannot silently lose that protection by forgetting the option. A
// transport whose addresses carry no IP (the in-memory one) does not implement it, and
// the diversity caps stay inert there. It is queried by type-asserting a Transport.
type IPAddressed interface {
	IPAddressed() bool
}

// Relayer is an optional capability a Transport may implement: opening a relay session
// for two peers that cannot hole-punch (e.g. symmetric↔symmetric NAT). It splices raw
// datagrams between two allocation endpoints so a QUIC connection tunnels between the
// peers without this node terminating it — the relay sees only ciphertext. A caller
// discovers it by type-asserting a Transport to Relayer; the in-memory transport does
// not implement it.
//
// AllocateRelay returns the address the caller (A) dials and the address the callee (B)
// registers and accepts on, plus a cancel func to tear the session down. It is
// capability-gated by policy: only a volunteer advertising CanRelay should offer it.
type Relayer interface {
	AllocateRelay() (callerAddr Addr, calleeAddr Addr, cancel func(), err error)
}

// Sentinel errors. Callers match them with errors.Is.
var (
	// ErrConnClosed means the edge is down: a Send on a closed Conn, or a Conn
	// closed underneath an in-flight operation.
	ErrConnClosed = errors.New("transport: conn closed")
	// ErrNoRoute means Dial could not locate the peer at the given address.
	ErrNoRoute = errors.New("transport: no route to peer")
	// ErrIdentityMismatch means the peer reached at the dialed address
	// authenticated as a NodeID other than the one Dial asked for.
	ErrIdentityMismatch = errors.New("transport: peer identity mismatch")
	// ErrRelayBusy means AllocateRelay was refused because the volunteer is at its
	// concurrent-session limit. The transport is alive — the caller should try
	// another volunteer or retry later, not treat the node as down.
	ErrRelayBusy = errors.New("transport: relay sessions limit reached")
)
