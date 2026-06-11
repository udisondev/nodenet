package transport

import (
	"encoding/binary"
	"errors"
	"math"
)

// Addr is a transport-level endpoint hint: where a peer can be reached before a
// Conn exists. It is opaque to the overlay — routing keys on kad.ID, never on
// Addr — and is used only by Dial to locate and contact a peer.
//
// For the QUIC transport, Net is "quic" and Endpoint is a "host:port" UDP
// address; for the in-memory transport, Net is "mem" and Endpoint is the
// hub-unique name of the target transport. Addr is deliberately a struct of two
// strings, not an interface and not net.Addr: it is a comparable value (no
// slices, no maps), so it copies cheaply and can be used directly as a map key,
// and it costs no interface allocation on the dial path.
type Addr struct {
	Net      string // transport family: "quic", "mem"
	Endpoint string // family-specific location: "host:port", or a mem hub name
}

// String renders the address as "net://endpoint" for logs and diagnostics. The
// zero Addr renders as "://".
func (a Addr) String() string {
	return a.Net + "://" + a.Endpoint
}

// --- address codec ---
//
// The one canonical wire encoding of an Addr, shared by every overlay message
// that carries addresses (routing contact lists and pong echoes, rendezvous
// handshakes, NAT hole-punch candidates):
//
//	addr  = uvarint(len net) | net | uvarint(len endpoint) | endpoint
//	addrs = uvarint(count) | addr*
//
// uvarint is the standard encoding/binary varint. The codec lives here, next to
// the type, so the packages above agree on the format by construction instead of
// by parallel reimplementation. It depends only on the stdlib — transport still
// does not import wire; framing an encoded address into a wire message remains
// the caller's job.
//
// The encoders are append-style and allocation-free given capacity. The parsers
// are defensive against untrusted input (level-2: every byte off the wire is
// bounds-checked before use, declared counts are bounded before allocating —
// list decoders of untrusted input pass their protocol cap to ParseAddrsN — and
// malformed bytes return ErrBadAddr — never a panic). Parsed strings are COPIES
// of the input, so an Addr safely outlives the receive buffer it was parsed
// from (Packet buffers return to a pool).

// MinAddrWireLen is the smallest encoded address: two zero-length string
// headers. Decoders use it to bound a declared address count against the
// remaining buffer before allocating, so a hostile count cannot drive an
// absurd allocation.
const MinAddrWireLen = 2

// ErrBadAddr means an encoded address (or address list) was malformed: the
// buffer ended mid-value, a declared length ran past it, or a varint did not
// decode. Callers match it with errors.Is.
var ErrBadAddr = errors.New("transport: malformed address encoding")

// ErrTooManyAddrs means a declared address count exceeded the caller's cap
// (ParseAddrsN) — the list is refused before anything is allocated. Encoders of
// capped messages return it as well, so a message that would not decode is never
// produced. Callers match it with errors.Is.
var ErrTooManyAddrs = errors.New("transport: address count exceeds cap")

// AddrWireLen reports the encoded size of a — what AppendAddr will append.
// It lets a caller size a buffer exactly before encoding.
func AddrWireLen(a Addr) int {
	return uvarintLen(uint64(len(a.Net))) + len(a.Net) +
		uvarintLen(uint64(len(a.Endpoint))) + len(a.Endpoint)
}

// AddrsWireLen reports the encoded size of the address list, count prefix
// included — what AppendAddrs will append.
func AddrsWireLen(addrs []Addr) int {
	n := uvarintLen(uint64(len(addrs)))
	for i := range addrs {
		n += AddrWireLen(addrs[i])
	}
	return n
}

// AppendAddr appends the canonical encoding of a to dst and returns the
// extended slice. Like the stdlib append-style encoders it allocates only if
// dst lacks capacity; pre-size with AddrWireLen for an allocation-free encode.
func AppendAddr(dst []byte, a Addr) []byte {
	dst = binary.AppendUvarint(dst, uint64(len(a.Net)))
	dst = append(dst, a.Net...)
	dst = binary.AppendUvarint(dst, uint64(len(a.Endpoint)))
	dst = append(dst, a.Endpoint...)
	return dst
}

// AppendAddrs appends the uvarint-counted encoding of the address list to dst
// and returns the extended slice. Pre-size with AddrsWireLen to avoid regrowth.
func AppendAddrs(dst []byte, addrs []Addr) []byte {
	dst = binary.AppendUvarint(dst, uint64(len(addrs)))
	for i := range addrs {
		dst = AppendAddr(dst, addrs[i])
	}
	return dst
}

// ParseAddr parses one address from the front of b and returns it together with
// the number of bytes consumed, so list decoders advance through a buffer by
// re-slicing. Trailing bytes after the address are not an error — a caller that
// expects b to be exactly one address checks n == len(b). The returned Addr owns
// its strings (they are copied out of b). Malformed input is ErrBadAddr, never
// a panic.
func ParseAddr(b []byte) (a Addr, n int, err error) {
	net, n, err := parseAddrString(b, 0)
	if err != nil {
		return Addr{}, 0, err
	}
	endpoint, n, err := parseAddrString(b, n)
	if err != nil {
		return Addr{}, 0, err
	}
	return Addr{Net: net, Endpoint: endpoint}, n, nil
}

// ParseAddrs parses a uvarint-counted address list from the front of b and
// returns it with the number of bytes consumed. The declared count is bounded
// only against the remaining buffer (MinAddrWireLen per entry), so a hostile
// count cannot run past it — but every entry can still be a 2-byte empty address
// that expands to a 32-byte Addr, a ~16x allocation amplification. Decoders of
// untrusted input therefore use ParseAddrsN with their protocol cap instead;
// this uncapped form is for input whose size the caller already bounds. An
// empty list parses to a nil slice. Trailing bytes are the caller's, as with
// ParseAddr.
func ParseAddrs(b []byte) (addrs []Addr, n int, err error) {
	return ParseAddrsN(b, math.MaxInt)
}

// ParseAddrsN is ParseAddrs with a count cap: a declared count above max is
// refused with ErrTooManyAddrs BEFORE the slice is allocated (level-2
// self-protection — the decoder's allocation stays a protocol constant,
// independent of how large a frame a peer can deliver). Every decoder of an
// untrusted address list passes the small per-message cap of its protocol.
func ParseAddrsN(b []byte, max int) (addrs []Addr, n int, err error) {
	cnt, n := binary.Uvarint(b)
	if n <= 0 {
		return nil, 0, ErrBadAddr
	}
	if max < 0 || cnt > uint64(max) {
		return nil, 0, ErrTooManyAddrs
	}
	if cnt > uint64(len(b)-n)/MinAddrWireLen {
		return nil, 0, ErrBadAddr
	}
	if cnt == 0 {
		return nil, n, nil
	}
	addrs = make([]Addr, cnt)
	for i := range addrs {
		a, an, err := ParseAddr(b[n:])
		if err != nil {
			return nil, 0, err
		}
		addrs[i] = a
		n += an
	}
	return addrs, n, nil
}

// parseAddrString reads one uvarint-prefixed string at b[off:] and returns the
// string (copied) and the offset past it. Both failure modes — a varint that is
// truncated or overflows, and a declared length running past the buffer — are
// ErrBadAddr.
func parseAddrString(b []byte, off int) (string, int, error) {
	l, vn := binary.Uvarint(b[off:])
	if vn <= 0 {
		return "", 0, ErrBadAddr
	}
	off += vn
	if l > uint64(len(b)-off) {
		return "", 0, ErrBadAddr
	}
	return string(b[off : off+int(l)]), off + int(l), nil
}

// uvarintLen reports how many bytes the varint encoding of v occupies (1..10),
// so encoded sizes can be computed without a trial encode.
func uvarintLen(v uint64) int {
	n := 1
	for v >= 0x80 {
		v >>= 7
		n++
	}
	return n
}
