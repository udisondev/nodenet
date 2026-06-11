package routing

import (
	"errors"
	"testing"

	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/wire"
)

// stubSigner is a Signer that returns a fixed-length zero signature, for codec
// round-trip tests that exercise the wire layout but not signature verification
// (which lives in the node-level tests).
type stubSigner struct{}

func (stubSigner) Sign(msg []byte) []byte { return make([]byte, SigLen) }

// contactsEqual compares the wire-relevant fields of two contact lists (the
// table-internal subnet/last-seen are never encoded, so they are not compared).
func contactsEqual(a, b []Contact) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ID != b[i].ID || a[i].EdPub != b[i].EdPub || a[i].XPub != b[i].XPub ||
			a[i].Caps != b[i].Caps || len(a[i].Addrs) != len(b[i].Addrs) {
			return false
		}
		for j := range a[i].Addrs {
			if a[i].Addrs[j] != b[i].Addrs[j] {
				return false
			}
		}
	}
	return true
}

func TestPongRoundTrip(t *testing.T) {
	cases := []transport.Addr{
		{Net: "quic", Endpoint: "192.0.2.7:443"},
		{Net: "mem", Endpoint: "node-3"},
		{}, // zero addr: two empty strings
	}
	for _, want := range cases {
		buf := make([]byte, 256)
		n, err := EncodePongFrame(buf, want)
		if err != nil {
			t.Fatalf("EncodePongFrame(%v): %v", want, err)
		}
		typ, payload, rest, err := wire.ParseFrame(buf[:n])
		if err != nil {
			t.Fatalf("ParseFrame: %v", err)
		}
		if typ != TypePong {
			t.Fatalf("type = %d, want TypePong", typ)
		}
		if len(rest) != 0 {
			t.Fatalf("trailing bytes after frame: %d", len(rest))
		}
		got, err := DecodePong(payload)
		if err != nil {
			t.Fatalf("DecodePong: %v", err)
		}
		if got != want {
			t.Fatalf("pong addr = %v, want %v", got, want)
		}
	}
}

func TestNeighborsRoundTrip(t *testing.T) {
	want := []Contact{
		{ID: fill(1), EdPub: fill32(2), XPub: fill32(3), Caps: PublicAnchor},
		{
			ID: fill(4), EdPub: fill32(5), Caps: CanRelay | PublicAnchor,
			Addrs: []transport.Addr{
				{Net: "quic", Endpoint: "198.51.100.9:7000"},
				{Net: "mem", Endpoint: "n4"},
			},
		},
		{ID: fill(6)}, // no keys, no addrs
	}
	target := fill(0xaa)
	nonce := [LookupNonceLen]byte{1, 2, 3, 4, 5, 6, 7, 8}
	buf := make([]byte, 1<<12)
	n, err := EncodeNeighborsFrame(buf, stubSigner{}, fill32(0xbb), target, 9, t0, nonce, want)
	if err != nil {
		t.Fatalf("EncodeNeighborsFrame: %v", err)
	}
	typ, payload, _, err := wire.ParseFrame(buf[:n])
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if typ != TypeNeighbors {
		t.Fatalf("type = %d, want TypeNeighbors", typ)
	}
	// A neighbors frame is a Msg whose payload is the nonce followed by the contact list,
	// so it forwards by the same Decide/SetTTL as a data frame and the contacts ride in
	// the payload after the echoed nonce.
	m, err := DecodeMsg(payload)
	if err != nil {
		t.Fatalf("DecodeMsg: %v", err)
	}
	if m.Target != target || m.TTL != 9 || m.EdPub != fill32(0xbb) || m.Avoid.Len() != 0 {
		t.Fatalf("neighbors msg header mismatch: %+v", m)
	}
	if len(m.Payload) < LookupNonceLen || [LookupNonceLen]byte(m.Payload[:LookupNonceLen]) != nonce {
		t.Fatalf("nonce not echoed in payload: %x", m.Payload)
	}
	got, err := DecodeNeighbors(m.Payload[LookupNonceLen:])
	if err != nil {
		t.Fatalf("DecodeNeighbors: %v", err)
	}
	if !contactsEqual(got, want) {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", got, want)
	}
}

func TestNeighborsEmpty(t *testing.T) {
	buf := make([]byte, 256)
	n, err := EncodeNeighborsFrame(buf, stubSigner{}, fill32(2), fill(1), 1, t0, [LookupNonceLen]byte{}, nil)
	if err != nil {
		t.Fatalf("EncodeNeighborsFrame(nil): %v", err)
	}
	_, payload, _, err := wire.ParseFrame(buf[:n])
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	m, err := DecodeMsg(payload)
	if err != nil {
		t.Fatalf("DecodeMsg: %v", err)
	}
	got, err := DecodeNeighbors(m.Payload[LookupNonceLen:])
	if err != nil {
		t.Fatalf("DecodeNeighbors: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("len = %d, want 0", len(got))
	}
}

func TestSiblingsNonceRoundTrip(t *testing.T) {
	nonce := [LookupNonceLen]byte{9, 8, 7, 6, 5, 4, 3, 2}
	buf := make([]byte, 64)
	n, err := EncodeSiblingsFrame(buf, nonce)
	if err != nil {
		t.Fatalf("EncodeSiblingsFrame: %v", err)
	}
	typ, payload, _, err := wire.ParseFrame(buf[:n])
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if typ != TypeSiblings {
		t.Fatalf("type = %d, want TypeSiblings", typ)
	}
	got, err := DecodeSiblings(payload)
	if err != nil {
		t.Fatalf("DecodeSiblings: %v", err)
	}
	if got != nonce {
		t.Fatalf("nonce = %x, want %x", got, nonce)
	}
	// A payload of the wrong length is rejected, never panics.
	if _, err := DecodeSiblings([]byte{1, 2, 3}); !errors.Is(err, wire.ErrShortBuffer) {
		t.Fatalf("DecodeSiblings(short) = %v, want ErrShortBuffer", err)
	}
}

// The control decoders accept only the canonical wire form, like DecodeMsg: a
// payload and payload+junk must not both decode to the same value (a non-canonical
// encoding would bite any future dedup/cache keyed on raw frame bytes).
func TestDecodePongRejectsTrailingBytes(t *testing.T) {
	buf := make([]byte, 64)
	n, err := EncodePongFrame(buf, transport.Addr{Net: "quic", Endpoint: "192.0.2.7:443"})
	if err != nil {
		t.Fatalf("EncodePongFrame: %v", err)
	}
	_, payload, _, err := wire.ParseFrame(buf[:n])
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if _, err := DecodePong(payload); err != nil {
		t.Fatalf("DecodePong of an exact-length payload: %v", err)
	}
	junk := append(append([]byte(nil), payload...), 0x00)
	if _, err := DecodePong(junk); err == nil {
		t.Fatal("DecodePong accepted a payload with a trailing byte")
	}
}

func TestDecodeNeighborsRejectsTrailingBytes(t *testing.T) {
	cs := []Contact{{ID: fill(1), EdPub: fill32(2), Addrs: []transport.Addr{{Net: "quic", Endpoint: "h:1"}}}}
	buf := make([]byte, neighborsLen(cs))
	n, err := EncodeNeighbors(buf, cs)
	if err != nil {
		t.Fatalf("EncodeNeighbors: %v", err)
	}
	if _, err := DecodeNeighbors(buf[:n]); err != nil {
		t.Fatalf("DecodeNeighbors of an exact-length payload: %v", err)
	}
	junk := append(append([]byte(nil), buf[:n]...), 0xAA)
	if _, err := DecodeNeighbors(junk); !errors.Is(err, wire.ErrShortBuffer) {
		t.Fatalf("DecodeNeighbors with a trailing byte: err = %v, want ErrShortBuffer", err)
	}
}

func TestDecodeNeighborsShortBuffer(t *testing.T) {
	// A declared count far beyond what the buffer can hold must be rejected, not
	// drive a huge allocation.
	bad := []byte{0xff, 0xff, 0xff, 0xff, 0x0f} // uvarint ~ a billion contacts
	if _, err := DecodeNeighbors(bad); !errors.Is(err, wire.ErrShortBuffer) {
		t.Fatalf("err = %v, want ErrShortBuffer", err)
	}
	// An empty buffer is truncated — it lacks even the count varint (a valid empty
	// list encodes as a single 0x00 byte), so it is rejected, not read as zero.
	if _, err := DecodeNeighbors(nil); !errors.Is(err, wire.ErrShortBuffer) {
		t.Fatalf("DecodeNeighbors(nil) = %v, want ErrShortBuffer", err)
	}
}

// TestDecodeNeighborsBoundsAddrAmplification: an answer that declares one contact
// carrying a flood of empty addresses must be refused, not decoded. Each empty
// address is two wire bytes but expands to a 32-byte transport.Addr plus scan
// bookkeeping (~32x); the buffer-only bound let a 64 KiB frame drive ~2 MB. The
// absolute per-answer address cap closes it.
func TestDecodeNeighborsBoundsAddrAmplification(t *testing.T) {
	const naddrs = maxNeighborsAddrs + 1024 // over the cap, but small on the wire
	var b []byte
	b = appendUvarint(b, 1) // one contact
	b = append(b, make([]byte, 3*kad.IDLen+4)...)
	b = appendUvarint(b, naddrs)
	for range naddrs {
		b = append(b, 0x00, 0x00) // empty net, empty endpoint
	}
	if _, err := DecodeNeighbors(b); !errors.Is(err, wire.ErrShortBuffer) {
		t.Fatalf("DecodeNeighbors(flood of empty addrs) err = %v, want ErrShortBuffer", err)
	}
}

// TestDecodeNeighborsRejectsAbsurdContactCount: a legitimate answer holds at most
// Siblings+1 contacts; a larger declared count is hostile and must be refused
// before the per-contact allocation.
func TestDecodeNeighborsRejectsAbsurdContactCount(t *testing.T) {
	const ncontacts = maxNeighborsContacts + 1
	var b []byte
	b = appendUvarint(b, ncontacts)
	for range ncontacts {
		b = append(b, make([]byte, 3*kad.IDLen+4)...) // id+keys+caps
		b = appendUvarint(b, 0)                        // zero addresses
	}
	if _, err := DecodeNeighbors(b); !errors.Is(err, wire.ErrShortBuffer) {
		t.Fatalf("DecodeNeighbors(%d contacts) err = %v, want ErrShortBuffer", ncontacts, err)
	}
}

// appendUvarint appends the uvarint encoding of v to dst.
func appendUvarint(dst []byte, v uint64) []byte {
	var tmp [10]byte
	n := wire.PutUvarint(tmp[:], 0, v)
	return append(dst, tmp[:n]...)
}

func TestEmptyControlFrames(t *testing.T) {
	for _, tc := range []struct {
		name string
		enc  func([]byte) (int, error)
		want wire.Type
	}{
		{"ping", EncodePingFrame, TypePing},
		{"leave", EncodeLeaveFrame, TypeLeave},
	} {
		buf := make([]byte, 8)
		n, err := tc.enc(buf)
		if err != nil {
			t.Fatalf("%s encode: %v", tc.name, err)
		}
		typ, payload, _, err := wire.ParseFrame(buf[:n])
		if err != nil {
			t.Fatalf("%s ParseFrame: %v", tc.name, err)
		}
		if typ != tc.want {
			t.Fatalf("%s type = %d, want %d", tc.name, typ, tc.want)
		}
		if len(payload) != 0 {
			t.Fatalf("%s payload len = %d, want 0", tc.name, len(payload))
		}
	}
}

func TestLookupFrameReusesMsg(t *testing.T) {
	// A lookup shares the Msg layout under TypeLookup (in production its payload is
	// the correlation nonce); it must decode with the same DecodeMsg and forward
	// with the same Decide/SetTTL as a data frame.
	m := &Msg{Target: fill(9), TTL: 12, EdPub: fill32(8), Avoid: avoidOf(fill(7))}
	buf := make([]byte, 1<<10)
	n, err := EncodeLookupFrame(buf, m)
	if err != nil {
		t.Fatalf("EncodeLookupFrame: %v", err)
	}
	typ, payload, _, err := wire.ParseFrame(buf[:n])
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if typ != TypeLookup {
		t.Fatalf("type = %d, want TypeLookup", typ)
	}
	got, err := DecodeMsg(payload)
	if err != nil {
		t.Fatalf("DecodeMsg: %v", err)
	}
	if got.Target != m.Target || got.TTL != m.TTL || got.EdPub != m.EdPub || len(got.Payload) != 0 {
		t.Fatalf("lookup round-trip mismatch: %+v", got)
	}
	// SetTTL patches the same offset for a lookup as for a data frame.
	SetTTL(payload, 3)
	if got2, _ := DecodeMsg(payload); got2.TTL != 3 {
		t.Fatalf("SetTTL on lookup: TTL = %d, want 3", got2.TTL)
	}
}
