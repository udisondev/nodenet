package transport

// This file is the media plane's vocabulary: the optional Media capability a
// Transport may implement, the MediaSession it hands out, the datagram/message
// types received on one, the per-session counters, the media frame codec
// (ChannelID byte | opaque payload) and the plane's constants and sentinels.
//
// A media session is a real-time channel to one peer — the foundation a calling
// application builds audio/video on. It is deliberately NOT an overlay edge: it
// lives on its own connection (its own congestion controller, flow control and
// fate), is owned by the application that opened or accepted it, carries no
// transit, is not tracked in the edge tables and does not count toward the
// connectivity floor. Closing a session never touches the overlay edge to the
// same peer, and reaping that edge never touches the session.
//
// Media requirements are the opposite of the overlay's: a steady flow of small
// packets where LOSS IS FINE (a late frame is a useless frame) and HEAD-OF-LINE
// BLOCKING IS NOT. Hence two primitives instead of one reliable frame pipe:
// unreliable unordered datagrams for voice and latest-is-best data, and
// independent one-shot messages (each its own unidirectional stream) for video
// frames larger than a packet and feedback — reliable, but with no ordering
// between messages, so one lost message never delays the next.
//
// Reception bypasses the Transport's single Inbound funnel entirely: each
// session surfaces its traffic on its own bounded Datagrams and Messages
// channels, read by per-session receive goroutines, so a flood of media bytes
// can never wedge the node-wide dispatch loop. Every queue on the plane is
// bounded and every drop is visible in a counter (MediaStats) — overflow drops
// the newest item rather than blocking.

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/udisondev/nodenet/kad"
)

// Media subprotocol consensus (level-1 of the media subprotocol, not of the
// network: a peer that disagrees is excluded from media with this node, but
// remains a full overlay member — media support is not a membership condition).
const (
	// MaxMediaDatagram is the largest datagram payload SendDatagram accepts: a
	// conservative ceiling that keeps ChannelID + payload within a single QUIC
	// packet on any sane path. It is a constant, not a probed value: the QUIC
	// stack exposes no current-limit API, and growth after MTU discovery would
	// be learned only from send errors — so the plane pins the floor every
	// path supports.
	MaxMediaDatagram = 1200

	// FirstAppChannel is the first ChannelID an application may use. The first
	// byte of every datagram and message is its ChannelID: 0 is reserved for
	// the core (currently unused), 1–15 are reserved, 16–255 belong to the
	// application (audio/video/feedback — its convention with itself, opaque
	// here). A received frame on a reserved channel is dropped and counted
	// (level-2 self-protection); sending on one is a programmer error and
	// panics, like an oversized SetLen.
	FirstAppChannel = 16
)

// Media plane policy defaults (level-3): queue depths both staple
// implementations use, so behaviour — including which side drops under load —
// is identical on the in-memory and the QUIC transport.
const (
	// MediaTxRing is the datagram send ring's depth. SendDatagram never blocks:
	// a datagram is queued here for a pump goroutine to push into the
	// connection, and a full ring refuses with ErrMediaBackpressure — the
	// earliest "you are past the path's rate" signal an application's
	// bandwidth estimator can get, one RTT before any network loss.
	MediaTxRing = 64

	// MediaDatagramQueue and MediaMessageQueue are the depths of a session's
	// Datagrams and Messages channels. Overflow drops the NEWEST item and
	// counts it: dropping the oldest would need a hand-rolled race on top of
	// channels, and the difference is absorbed by the application's jitter
	// buffer anyway.
	MediaDatagramQueue = 256
	MediaMessageQueue  = 32
)

// Per-session receive budget (level-2 self-protection, default-on): a token
// bucket on bytes and one on packets per second. For datagrams both are
// charged BEFORE the frame is copied into a pooled buffer, so a flooding peer
// burns neither this node's CPU nor its packet pool. A message's size is only
// known once its stream is read, so there the packet bucket is charged at
// stream accept and the byte bucket after the read — bounded meanwhile by the
// per-session stream cap and read deadline. Generous against any legitimate
// call (~20 Mbit/s); an exceeded budget drops the frame and counts it.
const (
	MediaRxBytesRate  = 20_000_000 / 8 // bytes/s (20 Mbit/s)
	MediaRxBytesBurst = 256 << 10      // bytes
	MediaRxPPSRate    = 4000           // packets/s
	MediaRxPPSBurst   = 400            // packets
)

// Media sentinel errors. Callers match them with errors.Is.
var (
	// ErrMediaUnsupported means the peer cannot do media: it negotiated no
	// media protocol (an older node) or refused the session's requirements.
	// The overlay edge to that peer is unaffected — media support is not a
	// membership condition — so the caller should fall back to overlay-only
	// interaction, not treat the peer as down.
	ErrMediaUnsupported = errors.New("transport: peer does not support media")

	// ErrMediaClosed means the session is over — closed locally, by the peer,
	// or by path death (idle timeout) — and no further Send will succeed.
	// Re-establishing is the application's move: open a new session (the
	// connect cascade runs again and may find a better path).
	ErrMediaClosed = errors.New("transport: media session closed")

	// ErrMediaBackpressure means the frame was NOT sent because the send side
	// is full: the datagram tx-ring has no slot, or a message write stalled
	// past its bound and the stream was reset. The session is alive and later
	// sends may succeed — this is the earliest congestion signal, so a
	// bandwidth estimator should reduce its rate. The frame is discarded
	// (and counted); it is never queued unboundedly.
	ErrMediaBackpressure = errors.New("transport: media send queue full")

	// ErrBadMediaFrame means a media frame was malformed: empty, so it carries
	// no ChannelID byte. Callers match it with errors.Is.
	ErrBadMediaFrame = errors.New("transport: malformed media frame")
)

// Media is an optional capability a Transport may implement: opening and
// accepting media sessions. Both staple transports implement it — QUIC as a
// separate connection per session over the same socket and path as the overlay
// edge, the in-memory one as a deterministic mirror with an injectable link
// model — so media code, like overlay code, is written once. A caller discovers
// it by type-asserting a Transport to Media.
//
// Sessions are NOT edges: nothing here touches Inbound, the edge tables or the
// connectivity floor. Admission policy (proof-of-work, consent, session caps)
// is the node layer's job, applied to what InboundMedia yields.
type Media interface {
	// OpenMedia opens a media session to remoteID at addr — normally the
	// observed address of the live overlay edge to that peer, so the session
	// rides the exact path (and NAT mapping) already proven to work. It blocks
	// until the session is up, ctx is done, or it fails: ErrMediaUnsupported
	// if the peer cannot do media, ErrIdentityMismatch if the peer there
	// authenticates as someone else, ErrNoRoute if it cannot be reached. A
	// dial failure toward a live edge's own address is a liveness signal about
	// that edge — the caller should probe it rather than trust it.
	OpenMedia(ctx context.Context, remoteID kad.ID, addr Addr) (MediaSession, error)

	// InboundMedia surfaces sessions peers opened to this node, authenticated
	// to their NodeID but NOT yet vetted: the consumer (the node layer) must
	// apply its admission gates and Close what it refuses. The channel is
	// bounded; if no one consumes it, further inbound sessions are refused at
	// the transport. It is closed when the Transport closes.
	InboundMedia() <-chan MediaSession
}

// MediaSession is one live media channel to one peer, authenticated to its
// NodeID. It is owned by the application: whoever opened or accepted it closes
// it. Several sessions to the same peer are legal — that is the
// make-before-break primitive (open a second session over a better path,
// switch, close the old one). Simultaneous mutual opens are not deduplicated
// (sessions are not a table; duplicates are harmless); by convention the peer
// with the smaller NodeID stays the initiator.
//
// All methods are safe for concurrent use. When the session dies — Close, the
// peer's close, or path death (idle timeout, ≤ ~10 s) — Datagrams and Messages
// drain shut, Closed() is signalled, and every Send returns ErrMediaClosed.
type MediaSession interface {
	// Remote returns the authenticated NodeID of the peer.
	Remote() kad.ID

	// RemoteAddr returns the peer's endpoint on this session's path.
	RemoteAddr() Addr

	// SendDatagram sends one unreliable, unordered datagram on channel ch:
	// payload p, at most MaxMediaDatagram bytes — voice and latest-is-best
	// data. It NEVER blocks: the datagram is copied into a bounded tx-ring
	// for a pump goroutine to push out, and a full ring refuses with
	// ErrMediaBackpressure. Send BORROWS p exactly like Conn.Send — it copies
	// synchronously and the caller still owns and Releases p — so one buffer
	// drives many sends. A send error never closes the session. Sending on a
	// reserved channel (ch < FirstAppChannel) or an oversized payload panics —
	// programmer errors, like SetLen out of range.
	SendDatagram(ch uint8, p *Packet) error

	// SendMessage sends one reliable message on channel ch: payload p, at most
	// MaxPacketLen bytes — a video frame larger than a packet, feedback, any
	// one-shot data. One message is one short-lived unidirectional stream, so
	// messages never head-of-line block each other; within a message delivery
	// is reliable and whole. It blocks while the path accepts bytes; a write
	// stalled past the stall bound resets THIS stream and returns
	// ErrMediaBackpressure (the message is abandoned, the session lives on),
	// and cancelling ctx resets the stream likewise — "drop the stale frame".
	// Borrowing and the reserved-channel/oversize panics are as in
	// SendDatagram.
	SendMessage(ctx context.Context, ch uint8, p *Packet) error

	// Datagrams is the stream of received datagrams. Each carries the receive
	// timestamp its reader stamped (RxTime) — the one delay signal an
	// application cannot recover on its own — and a pooled Packet the receiver
	// owns and must Release. The channel is bounded (MediaDatagramQueue);
	// overflow drops the newest and counts it. It drains shut when the
	// session ends.
	Datagrams() <-chan MediaDatagram

	// Messages is the stream of received messages, each a whole reliable
	// payload in a pooled Packet the receiver owns and must Release. Bounded
	// (MediaMessageQueue), overflow drops the newest and counts it, drains
	// shut when the session ends.
	Messages() <-chan MediaMessage

	// Stats is a snapshot of the session's counters. Every bounded queue on
	// the plane reports its drops here, so a misbehaving path shows up in
	// numbers instead of silence.
	Stats() MediaStats

	// Closed is signalled (closed) when the session ends, however it ends.
	// It lets an owner — or the node's liveness coupling — observe path death
	// without consuming the data channels.
	Closed() <-chan struct{}

	// Close ends the session: pending sends are abandoned, the peer observes
	// the close, Datagrams/Messages drain shut. It is idempotent. It never
	// touches the overlay edge to the peer.
	Close() error
}

// MediaDatagram is one received datagram: its application channel, the moment
// the receive goroutine took it off the connection (RxTime — stamped as early
// as the implementation can see the datagram, the input a delay-based
// bandwidth estimator needs), and the payload in a pooled Packet that the
// receiver owns and must Release exactly once.
type MediaDatagram struct {
	Channel uint8
	RxTime  time.Time
	Pkt     *Packet
}

// MediaMessage is one received message: its application channel and the whole
// payload in a pooled Packet that the receiver owns and must Release exactly
// once. Messages carry no RxTime: a reliable multi-packet payload has no
// single arrival instant worth feeding an estimator.
type MediaMessage struct {
	Channel uint8
	Pkt     *Packet
}

// MediaStats is a snapshot of one session's counters, monotonic since the
// session opened. The Dropped counters make every bounded queue's overflow and
// every defensive shed visible — the plane's "no silent drops" rule — and
// TxDroppedQueue in particular reaches an application's bandwidth estimator a
// round-trip earlier than any network loss would.
type MediaStats struct {
	TxDatagrams    uint64 // datagrams accepted into the tx-ring
	TxDroppedQueue uint64 // datagrams refused with ErrMediaBackpressure (tx-ring full)
	TxDroppedSend  uint64 // datagrams the pump could not send (path MTU shrank, transient conn error)
	TxMessages     uint64 // messages fully written and finished
	TxDroppedStall uint64 // messages abandoned by the stall bound or ctx cancel (stream reset)

	RxDatagrams       uint64 // datagrams delivered into Datagrams()
	RxDroppedBudget   uint64 // frames shed by the receive budget (level-2)
	RxDroppedReserved uint64 // frames violating the media consensus: reserved channel, malformed, oversized (level-2)
	RxDroppedQueue    uint64 // datagrams dropped because Datagrams() was full
	RxMessages        uint64 // messages delivered into Messages()
	RxDroppedMessages uint64 // messages dropped: Messages() full, oversized, or truncated by the peer
}

// MediaCounters is the live, concurrency-safe counter block behind MediaStats.
// It is shared by the staple MediaSession implementations so they report the
// identical set of numbers; embedding it is not part of the MediaSession
// contract. Increments happen on send paths and per-session receive
// goroutines; Snapshot may be called from any goroutine.
type MediaCounters struct {
	TxDatagrams    atomic.Uint64
	TxDroppedQueue atomic.Uint64
	TxDroppedSend  atomic.Uint64
	TxMessages     atomic.Uint64
	TxDroppedStall atomic.Uint64

	RxDatagrams       atomic.Uint64
	RxDroppedBudget   atomic.Uint64
	RxDroppedReserved atomic.Uint64
	RxDroppedQueue    atomic.Uint64
	RxMessages        atomic.Uint64
	RxDroppedMessages atomic.Uint64
}

// Snapshot reads the counters into a MediaStats.
func (c *MediaCounters) Snapshot() MediaStats {
	return MediaStats{
		TxDatagrams:    c.TxDatagrams.Load(),
		TxDroppedQueue: c.TxDroppedQueue.Load(),
		TxDroppedSend:  c.TxDroppedSend.Load(),
		TxMessages:     c.TxMessages.Load(),
		TxDroppedStall: c.TxDroppedStall.Load(),

		RxDatagrams:       c.RxDatagrams.Load(),
		RxDroppedBudget:   c.RxDroppedBudget.Load(),
		RxDroppedReserved: c.RxDroppedReserved.Load(),
		RxDroppedQueue:    c.RxDroppedQueue.Load(),
		RxMessages:        c.RxMessages.Load(),
		RxDroppedMessages: c.RxDroppedMessages.Load(),
	}
}

// --- media frame codec ---
//
// A media frame — the bytes of one datagram or one message-stream — is
// ChannelID(1 byte) | payload, and the payload is fully opaque to the
// transport. This is the whole on-wire format of the plane: no version, no
// length (the datagram and the stream already delimit), no wire.Frame
// envelope. The parser is a single bounds check, but it reads untrusted input,
// so it follows the full decoder discipline: never panics, returns a sentinel
// on malformed bytes, and is fuzzed.

// MediaFrameLen reports the encoded size of a media frame carrying a payload
// of payloadLen bytes: the ChannelID byte plus the payload.
func MediaFrameLen(payloadLen int) int { return 1 + payloadLen }

// PutMediaFrame lays ch | payload into dst and returns the number of bytes
// written. It fails with ErrBadMediaFrame if dst is too short — size dst with
// MediaFrameLen. It allocates nothing.
func PutMediaFrame(dst []byte, ch uint8, payload []byte) (int, error) {
	if len(dst) < 1+len(payload) {
		return 0, ErrBadMediaFrame
	}
	dst[0] = ch
	copy(dst[1:], payload)
	return 1 + len(payload), nil
}

// ParseMediaFrame splits a received media frame into its channel and payload.
// The payload ALIASES b — copy it to keep it past the buffer's reuse. An empty
// frame is malformed (no channel byte): ErrBadMediaFrame, never a panic.
func ParseMediaFrame(b []byte) (ch uint8, payload []byte, err error) {
	if len(b) == 0 {
		return 0, nil, ErrBadMediaFrame
	}
	return b[0], b[1:], nil
}
