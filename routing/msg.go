package routing

import (
	"crypto/ed25519"
	"encoding/binary"
	"hash"
	"sync"
	"time"

	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/wire"
	"golang.org/x/crypto/blake2b"
)

// blakePool reuses BLAKE2b-256 hashers across signingDigest calls so signing and
// verifying do not allocate a fresh hasher each time. Reset returns a pooled hasher to
// its initial state before reuse.
var blakePool = sync.Pool{New: func() any { h, _ := blake2b.New256(nil); return h }}

// MaxEnvelopeAge is the freshness window for a routed message: a forwarder or terminal
// drops one whose authenticated timestamp is older than this (or that far in the future,
// for clock skew). It bounds how long a captured packet can be replayed — the network-
// wide replay horizon — and must comfortably exceed worst-case overlay latency across
// MaxHops plus reasonable clock skew. Level-2 self-protection. (It does not stop a replay
// WITHIN the window; full dedup would need per-node origin state, which a best-effort
// overlay deliberately avoids — the e2e layers, QUIC and sealed-box, carry their own
// freshness for content that needs it.)
const MaxEnvelopeAge = 30 * time.Second

// tsLen is the width of the authenticated origination timestamp in a routed message: an
// int64 of Unix nanoseconds, big-endian.
const tsLen = 8

// SigLen is the length of the Ed25519 signature carried at the tail of every routed
// message. The originator signs the message at origination and a terminal or
// amplifying node verifies it before trusting or acting on the originator's behalf.
const SigLen = ed25519.SignatureSize

// sigDomain separates routing-envelope signatures from any other use of the identity
// key (a domain-separation prefix folded into the signed digest). sigDomainBytes is
// the pre-converted form so signingDigest does no per-call string→[]byte allocation.
const sigDomain = "nodenet/v1/routing-envelope"

var sigDomainBytes = []byte(sigDomain)

// Signer is the subset of identity.Identity that SignMsg needs: it signs a digest with
// the node's long-lived Ed25519 key. The interface exists for the codec tests' stub
// signer (wire-layout round-trips without real key material); the one production
// implementation is *identity.Identity, which routing already imports for DeriveID.
// The edPub a caller supplies beside a Signer must be that signer's public key, or
// receivers will silently drop the frames at VerifySig.
type Signer interface {
	Sign(msg []byte) []byte
}

const (
	// TypeRoute is the wire-frame type of a routing message — the envelope the
	// overlay greedily forwards over live edges. routing owns this discriminator
	// (wire treats Type as opaque). Level-1 protocol consensus.
	TypeRoute wire.Type = 1

	// MaxHops is the hop-budget ceiling a forwarder clamps an incoming TTL to
	// before decrementing it. The cap is level-1 consensus (the network's max-TTL);
	// the clamp a forwarder performs on every packet is a level-2 self-protection
	// invariant that stops a hostile or mis-set originator from making a packet
	// wander. With small-world fingers the overlay reaches any node in O(log N)
	// hops, so this is generous.
	MaxHops = 16

	// ttlOffset is where the one-byte TTL sits inside an encoded routing message:
	// right after the 32-byte target. SetTTL patches it in place so a forwarder can
	// decrement the hop budget without re-serialising the frame (zero-copy forward).
	ttlOffset = kad.IDLen
)

// Msg is a routing message: the overlay's unit of recursive delivery. It rides in
// the payload of a wire frame (TypeRoute) and carries everything a forwarder needs
// to make a level-2-checked greedy decision and everything the destination needs to
// act, with no per-hop re-serialisation.
//
// On the wire:
//
//	target(32) | ttl(1) | ed_pub(32) | sent(8) | uvarint(navoid) | avoid(navoid*32) | uvarint(plen) | payload | sig(64)
//
// DecodeMsg returns a Msg whose Avoid and Payload ALIAS the source buffer (zero
// copy); copy them to retain past the buffer's lifetime. Target, EdPub and Sig are
// stack values, copied out.
type Msg struct {
	// Target is the destination NodeID; greedy forwarding converges to it.
	Target kad.ID
	// TTL is the remaining hop budget. A forwarder clamps it to MaxHops and
	// decrements; at zero the packet is dropped.
	TTL uint8
	// EdPub is the originator's Ed25519 public key. Every forwarder checks
	// DeriveID(EdPub) clears the PoW threshold (origination-PoW, level-2), so a
	// sub-threshold originator's traffic dies at the first honest hop.
	EdPub [32]byte
	// Sent is the origination time (Unix nanoseconds), authenticated by Sig. Fresh
	// checks it against MaxEnvelopeAge so a replayed-stale packet is dropped. SignMsg
	// stamps it.
	Sent int64
	// Avoid is the disjoint-path avoid-set: NodeIDs a forwarder skips when choosing
	// the next hop, so sibling branches of a multi-path request stay apart.
	Avoid AvoidSet
	// Payload is the opaque content carried to the destination (rendezvous hello,
	// control, …); the overlay does not interpret it.
	Payload []byte
	// Sig is the originator's Ed25519 signature over the frame type, target, EdPub,
	// Sent and payload (NOT ttl or avoid, which mutate along the path). SignMsg stamps
	// it; VerifySig checks it at a terminal/amplifying hop, so a forwarder cannot forge
	// an originator or make a node amplify on a forged originator's behalf. The
	// forwarding hot path does not verify the signature — it only clamps TTL, checks
	// PoW, and checks Fresh (a cheap time comparison, no crypto).
	Sig [SigLen]byte
}

// signingDigest hashes the immutable, per-hop-stable parts of a routed message — the
// frame type, target, originator key, origination time, and payload — that the
// originator signs and a terminal/amplifying node verifies. TTL and the avoid-set are
// deliberately excluded: they change along the path (TTL per hop, avoid per disjoint
// copy), so they are not authenticated; tampering with them only wastes a hop, never
// forges an originator. Pre-hashing bounds the signed input to 32 bytes regardless of
// payload size.
func signingDigest(typ wire.Type, target kad.ID, edPub *[32]byte, sent int64, payload []byte) [blake2b.Size256]byte {
	h := blakePool.Get().(hash.Hash)
	h.Reset()
	var hdr [1 + kad.IDLen + 32 + tsLen]byte
	hdr[0] = byte(typ)
	copy(hdr[1:], target[:])
	copy(hdr[1+kad.IDLen:], edPub[:])
	binary.BigEndian.PutUint64(hdr[1+kad.IDLen+32:], uint64(sent))
	h.Write(sigDomainBytes)
	h.Write(hdr[:])
	h.Write(payload)
	var d [blake2b.Size256]byte
	h.Sum(d[:0])
	blakePool.Put(h)
	return d
}

// SignMsg stamps m.Sent with now and m.Sig with the originator's signature over (typ,
// target, EdPub, Sent, payload). Call it once at origination; the same signature is valid
// for every disjoint copy of the message, since it does not cover the per-copy avoid-set.
func SignMsg(s Signer, typ wire.Type, m *Msg, now time.Time) {
	m.Sent = now.UnixNano()
	d := signingDigest(typ, m.Target, &m.EdPub, m.Sent, m.Payload)
	copy(m.Sig[:], s.Sign(d[:]))
}

// VerifySig reports whether m carries a valid originator signature for a frame of type
// typ. A terminal/amplifying hop calls it before trusting m.EdPub as the originator or
// answering/learning on its behalf. It returns false on any mismatch and never panics
// (m.EdPub is always 32 bytes, the one length ed25519.Verify requires).
func (m *Msg) VerifySig(typ wire.Type) bool {
	d := signingDigest(typ, m.Target, &m.EdPub, m.Sent, m.Payload)
	return ed25519.Verify(ed25519.PublicKey(m.EdPub[:]), d[:], m.Sig[:])
}

// Fresh reports whether m's origination timestamp is within maxAge of now in either
// direction (the future tolerance absorbs clock skew). A forwarder calls it on the hot
// path — it is a plain time comparison, no crypto — to drop replayed-stale packets early;
// the timestamp is authenticated by Sig, so a forger cannot make a stale packet look
// fresh without also passing the signature check at the terminal.
//
// m.Sent is attacker-controlled and may be any int64, so the window is checked by
// comparing it directly against [now-maxAge, now+maxAge] rather than computing
// now.Sub(time.Unix(0, m.Sent)) — that subtraction is a time.Duration (int64 ns) and
// would overflow and WRAP for a Sent near MinInt64/MaxInt64, letting a crafted timestamp
// land back inside the window. now and maxAge are sane (a real clock, a 30 s window), so
// nowN±maxN cannot overflow, and m.Sent is never fed into a subtraction.
func (m *Msg) Fresh(now time.Time, maxAge time.Duration) bool {
	nowN := now.UnixNano()
	maxN := int64(maxAge)
	return m.Sent >= nowN-maxN && m.Sent <= nowN+maxN
}

// AvoidSet is an avoid-set as it sits on the wire: navoid raw NodeIDs back to back.
// On decode it ALIASES the frame buffer, so membership tests cost no allocation and
// no []kad.ID is ever materialised on the forwarding hot path. Build one for encode
// by concatenating raw IDs (see node origination); its length is always a multiple
// of kad.IDLen.
type AvoidSet []byte

// Len reports how many NodeIDs the set holds.
func (a AvoidSet) Len() int { return len(a) / kad.IDLen }

// At returns the i-th NodeID, copied out to a stack value.
func (a AvoidSet) At(i int) kad.ID {
	off := i * kad.IDLen
	return kad.ID(a[off : off+kad.IDLen])
}

// Has reports whether id is in the set, scanning the raw bytes without allocating.
func (a AvoidSet) Has(id kad.ID) bool {
	for off := 0; off+kad.IDLen <= len(a); off += kad.IDLen {
		if kad.ID(a[off:off+kad.IDLen]) == id {
			return true
		}
	}
	return false
}

// msgLen reports the encoded size of m (without the wire frame header).
func msgLen(m *Msg) int {
	navoid := m.Avoid.Len()
	return kad.IDLen + 1 + len(m.EdPub) + tsLen +
		wire.UvarintLen(uint64(navoid)) + navoid*kad.IDLen +
		wire.UvarintLen(uint64(len(m.Payload))) + len(m.Payload) + SigLen
}

// EncodeMsg writes m into dst in place and returns the number of bytes written. It
// does not grow dst: a too-small dst is ErrShortBuffer, and a message larger than
// wire.MaxFrameLen is ErrFrameTooLarge. dst is typically the payload region of a
// frame; EncodeRouteFrame wraps this with the frame header in one pass.
func EncodeMsg(dst []byte, m *Msg) (int, error) {
	n := msgLen(m)
	if n > wire.MaxFrameLen {
		return 0, wire.ErrFrameTooLarge
	}
	if len(dst) < n {
		return 0, wire.ErrShortBuffer
	}
	off := wire.PutID(dst, 0, m.Target)
	dst[off] = m.TTL
	off++
	off += copy(dst[off:], m.EdPub[:])
	binary.BigEndian.PutUint64(dst[off:], uint64(m.Sent))
	off += tsLen
	off = wire.PutUvarint(dst, off, uint64(m.Avoid.Len()))
	off += copy(dst[off:], m.Avoid)
	off = wire.PutUvarint(dst, off, uint64(len(m.Payload)))
	off += copy(dst[off:], m.Payload)
	off += copy(dst[off:], m.Sig[:])
	return off, nil
}

// EncodeRouteFrame writes the complete wire frame (envelope + m as the TypeRoute
// payload) into dst in place and returns its total length. Errors mirror EncodeMsg.
func EncodeRouteFrame(dst []byte, m *Msg) (int, error) {
	return EncodeMsgFrame(dst, TypeRoute, m)
}

// EncodeMsgFrame writes a Msg into dst as the payload of a frame of type t, in one
// pass: because the message length is known up front, the header width is computed
// directly and the message is laid straight into its final position — no
// intermediate buffer or copy. It is the one generic framer behind EncodeRouteFrame,
// EncodeLookupFrame and EncodeNeighborsFrame; a package layered above routing
// (rendezvous, through node) uses it to wrap its own routed content under its own
// wire.Type while reusing the same Msg envelope and the same greedy Decide/SetTTL
// forwarding, so a new routed message needs no new forward path.
func EncodeMsgFrame(dst []byte, t wire.Type, m *Msg) (int, error) {
	ml := msgLen(m)
	if ml > wire.MaxFrameLen {
		return 0, wire.ErrFrameTooLarge
	}
	hdr := wire.FrameHeaderLen(ml)
	if len(dst) < hdr+ml {
		return 0, wire.ErrShortBuffer
	}
	wire.PutFrameHeader(dst, t, ml)
	if _, err := EncodeMsg(dst[hdr:], m); err != nil {
		return 0, err
	}
	return hdr + ml, nil
}

// DecodeMsg parses a routing message from b — the payload of a TypeRoute frame
// (after wire.ParseFrame). The returned Msg's Avoid and Payload ALIAS b. It is
// defensive against untrusted input: strict bounds checks, sentinel errors from
// wire, and it NEVER panics on malformed bytes.
func DecodeMsg(b []byte) (Msg, error) {
	var m Msg
	r := wire.NewReader(b)

	var err error
	if m.Target, err = r.ID(); err != nil {
		return m, err
	}
	ttl, err := r.Bytes(1)
	if err != nil {
		return m, err
	}
	m.TTL = ttl[0]
	ep, err := r.Bytes(len(m.EdPub))
	if err != nil {
		return m, err
	}
	copy(m.EdPub[:], ep)
	sent, err := r.Bytes(tsLen)
	if err != nil {
		return m, err
	}
	m.Sent = int64(binary.BigEndian.Uint64(sent))

	navoid, err := r.Uvarint()
	if err != nil {
		return m, err
	}
	// Guard the multiply against overflow before converting to int: a hostile
	// navoid cannot make us index past the buffer.
	if navoid > uint64(r.Remaining()/kad.IDLen) {
		return m, wire.ErrShortBuffer
	}
	avoid, err := r.Bytes(int(navoid) * kad.IDLen)
	if err != nil {
		return m, err
	}
	m.Avoid = AvoidSet(avoid)

	plen, err := r.Uvarint()
	if err != nil {
		return m, err
	}
	// The payload must leave room for the trailing signature, so guard plen against the
	// remaining buffer minus SigLen before slicing it out (checked so the subtraction
	// cannot underflow on a too-short buffer).
	if r.Remaining() < SigLen || plen > uint64(r.Remaining()-SigLen) {
		return m, wire.ErrShortBuffer
	}
	payload, err := r.Bytes(int(plen))
	if err != nil {
		return m, err
	}
	m.Payload = payload

	sig, err := r.Bytes(SigLen)
	if err != nil {
		return m, err
	}
	copy(m.Sig[:], sig)
	// Reject trailing bytes so the wire form is canonical: a frame and frame+junk must not
	// both decode to the same Msg. The payload length is explicit and signed, so trailing
	// bytes are never a signature-forgery vector, but a non-canonical encoding would bite
	// any future dedup/cache that keys on raw frame bytes.
	if r.Remaining() != 0 {
		return m, wire.ErrShortBuffer
	}
	return m, nil
}

// SetTTL patches the TTL byte of an already-encoded routing message in place.
// encoded is the frame payload (the slice wire.ParseFrame returns). This is how a
// forwarder decrements the hop budget on the hot path without rebuilding the frame.
func SetTTL(encoded []byte, ttl uint8) {
	// Defensive: encoded is a frame payload whose length is attacker-influenced. A frame
	// that decoded past the TTL slot is always long enough here, but the guard keeps the
	// exported function from panicking on a short slice, per the codec's never-panic
	// contract.
	if len(encoded) <= ttlOffset {
		return
	}
	encoded[ttlOffset] = ttl
}
