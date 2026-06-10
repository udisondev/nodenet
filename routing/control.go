package routing

import (
	"strings"
	"time"

	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/wire"
)

// The control protocol: the small frames the maintenance loop exchanges to keep a
// node's live-edge set healthy under churn, beside the data envelope (TypeRoute).
// routing owns these discriminators (wire treats Type as opaque); their values are
// level-1 protocol consensus. The codecs are defensive against untrusted input the
// same way the message codec is — strict bounds checks, MaxFrameLen, sentinel
// errors, never a panic on malformed bytes — but, unlike the forwarding hot path,
// the contact-list decode allocates (it owns its strings and slices so a learned
// contact outlives the receive buffer); this is control traffic, not transit.
const (
	// TypePing / TypePong are a per-edge liveness exchange (not routed): keepalive
	// over an idle live edge, and the chance for the responder to tell the pinger
	// the address it was seen coming from (reflexive-address learning). A Ping frame
	// carries no payload; the authenticated Conn identifies the pinger.
	TypePing wire.Type = 2
	TypePong wire.Type = 3

	// TypeLookup is a routed discovery request. It shares the Msg layout exactly, with a
	// LookupNonceLen-byte correlation nonce as its payload, so it is forwarded greedily by
	// the same Decide and SetTTL the data path uses; the node nearest the target answers
	// with a routed TypeNeighbors back to the originator, echoing the nonce so the
	// requester can match the answer to a request it actually made.
	TypeLookup wire.Type = 4

	// TypeNeighbors carries a list of Contacts prefixed by the LookupNonceLen-byte nonce
	// of the request it answers. It is both the response to a TypeLookup (routed back to
	// the requester) and the response to a per-edge TypeSiblings request (sent straight
	// back over the edge); in both cases the nonce lets the requester accept only an
	// answer it solicited.
	TypeNeighbors wire.Type = 5

	// TypeSiblings is a per-edge request for the peer's sibling set; the peer answers
	// with TypeNeighbors. Its payload is the LookupNonceLen-byte correlation nonce the
	// answer echoes.
	TypeSiblings wire.Type = 6

	// TypeLeave is a per-edge graceful-leave announcement: the sender is shutting
	// down, so the neighbour can proactively drop the edge and replace it instead of
	// waiting for a timeout. It carries no payload (the authenticated Conn names the
	// leaver).
	TypeLeave wire.Type = 7
)

// minContactWireLen is the smallest a contact can be on the wire (all variable
// parts empty). DecodeNeighbors uses it (and transport.MinAddrWireLen for the
// addresses) to bound a declared count against the buffer before allocating, so a
// hostile count cannot drive an absurd allocation.
const minContactWireLen = 3*kad.IDLen + 4 + 1 // id + ed_pub + x_pub + caps + uvarint(0 addrs)

// LookupNonceLen is the width of the correlation nonce a lookup/sibling request carries
// and its neighbours answer echoes. It lets a requester accept only an answer to a request
// it actually made: the nonce is fresh random bytes the originator keeps, so an off-path
// attacker — who never saw the request — cannot forge a neighbours response that the
// requester will fold into its knowledge table (closing unsolicited table poisoning). 8
// bytes of crypto-random is unguessable in the response window.
const LookupNonceLen = 8

// EncodeLookupFrame writes a routed discovery request (m as a TypeLookup frame).
// m.Payload carries the LookupNonceLen-byte correlation nonce the neighbours answer
// echoes (see TypeLookup); everything else (target, ttl, ed_pub, avoid) works the
// same as a data frame, so the lookup is forwarded by Decide and SetTTL unchanged.
func EncodeLookupFrame(dst []byte, m *Msg) (int, error) {
	return EncodeMsgFrame(dst, TypeLookup, m)
}

// EncodePingFrame writes a payload-less TypePing frame into dst and returns its
// length.
func EncodePingFrame(dst []byte) (int, error) { return encodeEmptyFrame(dst, TypePing) }

// EncodeLeaveFrame writes a payload-less TypeLeave frame into dst and returns its
// length.
func EncodeLeaveFrame(dst []byte) (int, error) { return encodeEmptyFrame(dst, TypeLeave) }

// EncodeSiblingsFrame writes a TypeSiblings request whose payload is the correlation
// nonce, so the neighbours answer can echo it and the requester can match the answer to
// this request. Returns the frame length.
func EncodeSiblingsFrame(dst []byte, nonce [LookupNonceLen]byte) (int, error) {
	f, err := wire.EncodeFrame(dst, TypeSiblings, nonce[:])
	if err != nil {
		return 0, err
	}
	return len(f), nil
}

// DecodeSiblings parses the correlation nonce from a TypeSiblings frame's payload. It is
// defensive against untrusted input: a payload of the wrong length is ErrShortBuffer and
// it never panics.
func DecodeSiblings(b []byte) ([LookupNonceLen]byte, error) {
	var nonce [LookupNonceLen]byte
	if len(b) != LookupNonceLen {
		return nonce, wire.ErrShortBuffer
	}
	copy(nonce[:], b)
	return nonce, nil
}

func encodeEmptyFrame(dst []byte, t wire.Type) (int, error) {
	f, err := wire.EncodeFrame(dst, t, nil)
	if err != nil {
		return 0, err
	}
	return len(f), nil
}

// EncodePongFrame writes a TypePong frame whose payload is observed — the address
// the responder saw the pinger arrive from, in the canonical transport encoding.
// The pinger reads it to learn its own reflexive (externally-visible) address.
func EncodePongFrame(dst []byte, observed transport.Addr) (int, error) {
	pl := transport.AddrWireLen(observed)
	if pl > wire.MaxFrameLen {
		return 0, wire.ErrFrameTooLarge
	}
	hdr := wire.FrameHeaderLen(pl)
	if len(dst) < hdr+pl {
		return 0, wire.ErrShortBuffer
	}
	wire.PutFrameHeader(dst, TypePong, pl)
	// The length check above guarantees capacity, so the append writes in place into
	// dst's backing array — no growth, no allocation.
	transport.AppendAddr(dst[:hdr], observed)
	return hdr + pl, nil
}

// DecodePong parses the address echoed in a TypePong frame's payload b. It copies
// the strings out (the transport codec owns its strings), so the result outlives b.
// The payload must be exactly one address — trailing bytes are rejected so the wire
// form stays canonical, like DecodeMsg.
func DecodePong(b []byte) (transport.Addr, error) {
	a, n, err := transport.ParseAddr(b)
	if err != nil {
		return transport.Addr{}, err
	}
	if n != len(b) {
		return transport.Addr{}, wire.ErrShortBuffer
	}
	return a, nil
}

// EncodeNeighborsFrame writes a routed neighbors message into dst and returns its
// length: a Msg addressed to target (TTL ttl, originator key edPub, no avoid-set)
// whose payload is the correlation nonce followed by the contact list cs, framed as
// TypeNeighbors. Sharing the Msg envelope — built by the same SignMsg/EncodeMsgFrame
// as every routed message, so the signed layout has one point of truth — means the
// overlay forwards it to target by the same greedy Decide/SetTTL as a data message
// and the requester verifies it with the same VerifySig. The receiver, once it is
// the target, splits the nonce off the payload to confirm it solicited this answer,
// then decodes cs with DecodeNeighbors and learns the contacts. A direct per-edge
// response (sibling-set exchange) uses target = the neighbour and ttl = 1.
//
// nonce echoes the nonce of the lookup/sibling request being answered, so the requester
// folds the contacts in only for a request it actually made.
//
// The payload is staged in a scratch slice — this is control traffic, which may
// allocate (see the control-protocol comment at the top of this file). now stamps
// the freshness timestamp; edPub must be signer's own Ed25519 public key. Errors
// mirror EncodeMsg.
func EncodeNeighborsFrame(dst []byte, signer Signer, edPub [32]byte, target kad.ID, ttl uint8, now time.Time, nonce [LookupNonceLen]byte, cs []Contact) (int, error) {
	payload := make([]byte, LookupNonceLen+neighborsLen(cs))
	copy(payload, nonce[:])
	if _, err := EncodeNeighbors(payload[LookupNonceLen:], cs); err != nil {
		return 0, err
	}
	m := Msg{Target: target, TTL: ttl, EdPub: edPub, Payload: payload}
	SignMsg(signer, TypeNeighbors, &m, now)
	return EncodeMsgFrame(dst, TypeNeighbors, &m)
}

// EncodeNeighbors writes the contact list into dst (the frame payload region) and
// returns the bytes written. Only the wire-relevant fields are encoded — ID, the
// two public keys, capabilities, and the addresses — never the table-internal
// subnet or last-seen, which the receiver re-derives on Observe.
//
// On the wire (the address list is the canonical transport encoding):
//
//	uvarint(ncontacts) | contact*
//	contact = id(32) | ed_pub(32) | x_pub(32) | caps(4) | uvarint(naddrs) | addr*
//	addr    = uvarint(len net) | net | uvarint(len endpoint) | endpoint
func EncodeNeighbors(dst []byte, cs []Contact) (int, error) {
	n := neighborsLen(cs)
	if n > wire.MaxFrameLen {
		return 0, wire.ErrFrameTooLarge
	}
	if len(dst) < n {
		return 0, wire.ErrShortBuffer
	}
	off := wire.PutUvarint(dst, 0, uint64(len(cs)))
	for i := range cs {
		c := &cs[i]
		off = wire.PutID(dst, off, c.ID)
		off += copy(dst[off:], c.EdPub[:])
		off += copy(dst[off:], c.XPub[:])
		off = wire.PutUint32(dst, off, uint32(c.Caps))
		// dst is pre-sized (the length check above), so the append-style transport
		// encoder writes the address list in place — no growth, no allocation.
		off = len(transport.AppendAddrs(dst[:off], c.Addrs))
	}
	return off, nil
}

// DecodeNeighbors parses a contact list from b — the payload of a TypeNeighbors
// frame. Unlike the forwarding decoders it does NOT alias b: every returned Contact
// owns its ID, keys, and address strings, so it can be Observed into the knowledge
// table and outlive the receive buffer. It is defensive against untrusted input —
// declared counts are bounded against the remaining buffer before allocating, and
// it never panics on malformed bytes.
func DecodeNeighbors(b []byte) ([]Contact, error) {
	// Validate the whole frame up front and learn the exact sizes, so the fill below
	// needs no bounds checks and every contact's addresses share one backing slice
	// and one backing string — instead of a slice per contact and a string per field.
	nc, totalAddr, totalStr, err := scanNeighbors(b)
	if err != nil {
		return nil, err
	}
	if nc == 0 {
		return nil, nil
	}
	cs := make([]Contact, nc)
	var flat []transport.Addr
	if totalAddr > 0 {
		flat = make([]transport.Addr, totalAddr)
	}
	// All Net/Endpoint bytes go into one builder; its String() hands back the buffer
	// without a second copy, so every address string is a sub-string of one backing.
	var sb strings.Builder
	sb.Grow(totalStr)
	// sref records where each address's two strings landed, so they can be re-pointed
	// at the backing string once it is finalized (the builder may move bytes while it
	// is still growing).
	type sref struct{ no, nl, eo, el int }
	srefs := make([]sref, totalAddr)

	r := wire.NewReader(b)
	r.Uvarint() // contact count — already validated by the scan
	ai := 0
	for i := range cs {
		c := &cs[i]
		c.ID, _ = r.ID()
		ep, _ := r.Bytes(len(c.EdPub))
		copy(c.EdPub[:], ep)
		xp, _ := r.Bytes(len(c.XPub))
		copy(c.XPub[:], xp)
		caps, _ := r.Uint32()
		c.Caps = Capability(caps)

		na64, _ := r.Uvarint()
		na := int(na64)
		if na == 0 {
			continue
		}
		c.Addrs = flat[ai : ai+na : ai+na]
		for range na {
			nl64, _ := r.Uvarint()
			nb, _ := r.Bytes(int(nl64))
			no := sb.Len()
			sb.Write(nb)
			el64, _ := r.Uvarint()
			eb, _ := r.Bytes(int(el64))
			eo := sb.Len()
			sb.Write(eb)
			srefs[ai] = sref{no, int(nl64), eo, int(el64)}
			ai++
		}
	}

	backing := sb.String()
	for k := range flat {
		s := srefs[k]
		flat[k].Net = backing[s.no : s.no+s.nl]
		flat[k].Endpoint = backing[s.eo : s.eo+s.el]
	}
	return cs, nil
}

// scanNeighbors walks a TypeNeighbors payload purely to validate it and total up the
// sizes DecodeNeighbors allocates: the contact count, the address count across all
// contacts, and the combined Net+Endpoint byte length. It mirrors the field layout
// of the fill pass exactly — walking the canonical transport address layout by hand
// rather than via transport.ParseAddr, which would copy two strings per address that
// the scan only measures — and is defensive against untrusted input: declared counts
// are bounded against the remaining buffer and it never panics. Like DecodeMsg it
// accepts only the canonical form, rejecting trailing bytes after the list.
func scanNeighbors(b []byte) (nc, totalAddr, totalStr int, err error) {
	r := wire.NewReader(b)
	cnt, err := r.Uvarint()
	if err != nil {
		return 0, 0, 0, err
	}
	if cnt > uint64(r.Remaining()/minContactWireLen) {
		return 0, 0, 0, wire.ErrShortBuffer
	}
	var c Contact
	for range cnt {
		if _, err = r.ID(); err != nil {
			return 0, 0, 0, err
		}
		if _, err = r.Bytes(len(c.EdPub)); err != nil {
			return 0, 0, 0, err
		}
		if _, err = r.Bytes(len(c.XPub)); err != nil {
			return 0, 0, 0, err
		}
		if _, err = r.Uint32(); err != nil {
			return 0, 0, 0, err
		}
		na, err := r.Uvarint()
		if err != nil {
			return 0, 0, 0, err
		}
		if na > uint64(r.Remaining()/transport.MinAddrWireLen) {
			return 0, 0, 0, wire.ErrShortBuffer
		}
		for range na {
			nl, err := r.Uvarint()
			if err != nil {
				return 0, 0, 0, err
			}
			if nl > uint64(r.Remaining()) {
				return 0, 0, 0, wire.ErrShortBuffer
			}
			if _, err = r.Bytes(int(nl)); err != nil {
				return 0, 0, 0, err
			}
			el, err := r.Uvarint()
			if err != nil {
				return 0, 0, 0, err
			}
			if el > uint64(r.Remaining()) {
				return 0, 0, 0, wire.ErrShortBuffer
			}
			if _, err = r.Bytes(int(el)); err != nil {
				return 0, 0, 0, err
			}
			totalAddr++
			totalStr += int(nl) + int(el)
		}
	}
	// Reject trailing bytes so the wire form is canonical (see DecodeMsg): a payload
	// and payload+junk must not both decode to the same contact list.
	if r.Remaining() != 0 {
		return 0, 0, 0, wire.ErrShortBuffer
	}
	return int(cnt), totalAddr, totalStr, nil
}

func neighborsLen(cs []Contact) int {
	n := wire.UvarintLen(uint64(len(cs)))
	for i := range cs {
		n += contactWireLen(&cs[i])
	}
	return n
}

func contactWireLen(c *Contact) int {
	return 3*kad.IDLen + 4 + transport.AddrsWireLen(c.Addrs)
}
