// Package wire is the byte-layout contract of nodenet: it turns protocol values
// into bytes and back, and nothing else. It is the lowest serialization layer —
// a stateless codec over a buffer that someone ELSE owns. It does no network
// I/O, holds no pool, and allocates nothing on the hot path.
//
// The on-wire frame is a single envelope:
//
//	version | type | uvarint(len) | payload
//
// version is a one-byte format tag, type is an opaque discriminator whose values
// are assigned by the packages that own the messages (routing, rendezvous, …),
// len is an unsigned varint, and payload is len raw bytes. Multi-byte integers
// are big-endian, matching the big-endian numbering kad uses for ID.
//
// # Why this is not bytes.Buffer
//
// wire is the anti-bytes.Buffer: it never owns memory, never grows, and never
// copies on the read side.
//
//   - It does not own the buffer. Encoding writes into a caller-supplied []byte
//     of fixed capacity (the node takes a MaxPacketLen-sized buffer from the
//     transport's pool). If the payload does not fit, that is an error
//     (ErrShortBuffer), not a reallocation — growth would mean an allocation.
//     bytes.Buffer, by contrast, grows and owns its backing array.
//   - It does not copy on read. Reader and ParseFrame return slices that ALIAS
//     the input buffer. A caller that needs the bytes beyond the buffer's lifetime
//     copies them itself. This is what makes zero-copy forwarding possible: a
//     received frame travels onward in the same buffer, never re-serialized.
//   - It is defensive against untrusted input (a level-2 self-protection
//     invariant): strict bounds checks, a MaxFrameLen cap, sentinel errors, and it
//     NEVER panics on malformed bytes.
//
// # Layering
//
// wire is a leaf contract, one notch above the kad keyspace (wire -> kad, for
// ID). Delivery of those bytes (the Transport interface, the buffer pool,
// Packet.Release) lives in transport; the high-level "build a message and send
// it / receive and dispatch" handles live in node, which composes wire (codec)
// with transport (pipe). wire itself knows nothing about sending.
package wire

import (
	"encoding/binary"
	"errors"

	"github.com/udisondev/nodenet/kad"
)

const (
	// Version is the one-byte frame format tag. A decoder rejects any other
	// value with ErrBadVersion; bumping it lets a future format coexist.
	Version = 1

	// MaxFrameLen caps the payload length a frame may declare — the parser's
	// absolute ceiling, rejected with ErrFrameTooLarge on both encode and
	// decode. The value is protocol consensus (level-1): every node enforces
	// the same cap, and changing it changes the protocol. Enforcing it on
	// decode doubles as level-2 self-protection — a hostile uvarint length
	// cannot drive an absurd read.
	//
	// It is NOT the practical frame budget. That budget belongs to the
	// transport: a frame must fit one transport packet (transport.MaxPacketLen,
	// 64 KiB), which binds far sooner. The layering contract is one-way —
	// MaxFrameLen must be >= any payload a transport packet can carry — so wire
	// stays ignorant of transport and never rejects a frame the transport could
	// deliver. The headroom above the packet size is deliberate: the parser cap
	// is fixed consensus, the packet size is a transport tunable below it.
	MaxFrameLen = 1 << 20 // 1 MiB
)

// Type is the frame discriminator. wire treats it as opaque: the concrete values
// are defined by the packages that own each message kind, as those messages are
// designed. wire only carries it through the envelope.
//
// The value space is one flat byte shared by all owning packages, and nothing
// checks uniqueness at compile time — so the allocation is recorded here.
// Claim a range in this registry before assigning a new value:
//
//	1–7    routing    (Route, Ping, Pong, Lookup, Neighbors, Siblings, Leave)
//	8–9    rendezvous (Hello, Reply)
//	10–14  nat        (Connect, ConnectAck, RelayRequest, RelayGrant, RelayBind)
//	15–63  unassigned
//	64     node       (TypeApp — application payload)
type Type uint8

// Sentinel errors. They are matched with errors.Is by callers; the decode path
// returns one of these instead of panicking on malformed input.
var (
	// ErrShortBuffer means the buffer ended before a value or frame was complete
	// (on decode), or a destination buffer was too small to hold a frame (on
	// encode). On encode it signals "give me a bigger buffer", never a regrow.
	ErrShortBuffer = errors.New("wire: short buffer")
	// ErrFrameTooLarge means a frame's declared payload length exceeds
	// MaxFrameLen.
	ErrFrameTooLarge = errors.New("wire: frame exceeds MaxFrameLen")
	// ErrBadVersion means the frame's version byte is not Version.
	ErrBadVersion = errors.New("wire: unsupported version")
)

// The Put* primitives are the thin encode side: they write one big-endian value
// into dst at off and return the new offset. They are the building blocks an
// owning package uses to lay a payload into a buffer before framing it.
//
// They deliberately do NOT grow dst and do NOT return an error: dst must already
// be large enough (the caller sizes it from a pooled buffer). A too-small dst is
// a programmer error and surfaces as an index panic, exactly like writing past
// the end of any slice. The frame layer (EncodeFrame) is the one that turns an
// undersized buffer into a clean ErrShortBuffer for the network path.

// PutUint32 writes v big-endian at dst[off:] and returns off+4.
func PutUint32(dst []byte, off int, v uint32) int {
	binary.BigEndian.PutUint32(dst[off:], v)
	return off + 4
}

// PutUvarint writes v as an unsigned varint at dst[off:] and returns the offset
// past it (off + 1..10).
func PutUvarint(dst []byte, off int, v uint64) int {
	return off + binary.PutUvarint(dst[off:], v)
}

// PutID writes the 32 raw bytes of id at dst[off:] and returns off+kad.IDLen.
func PutID(dst []byte, off int, id kad.ID) int {
	return off + copy(dst[off:off+kad.IDLen], id[:])
}

// UvarintLen reports how many bytes the unsigned varint encoding of v occupies
// (1..10). It lets a caller size a header or a message before writing it, without a
// trial encode — the same job PutUvarint's return offset gives after the fact.
func UvarintLen(v uint64) int {
	n := 1
	for v >= 0x80 {
		v >>= 7
		n++
	}
	return n
}
