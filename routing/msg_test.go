package routing

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/wire"
)

// fill returns an ID/key with every byte set to b — a cheap distinct value.
func fill(b byte) kad.ID {
	var id kad.ID
	for i := range id {
		id[i] = b
	}
	return id
}

func fill32(b byte) [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = b
	}
	return k
}

// avoidOf builds an AvoidSet from ids, the way an originator concatenates the other
// first-hops for a disjoint copy.
func avoidOf(ids ...kad.ID) AvoidSet {
	b := make([]byte, 0, len(ids)*kad.IDLen)
	for _, id := range ids {
		b = append(b, id[:]...)
	}
	return AvoidSet(b)
}

// sigOf returns a signature-sized array with every byte set to b — a cheap
// distinct value for codec round-trips that do not verify.
func sigOf(b byte) [SigLen]byte {
	var s [SigLen]byte
	for i := range s {
		s[i] = b
	}
	return s
}

// eqMsg compares every wire field of a Msg, the authenticated Sent and Sig included.
func eqMsg(t *testing.T, got, want Msg) {
	t.Helper()
	if got.Target != want.Target {
		t.Errorf("Target = %v, want %v", got.Target, want.Target)
	}
	if got.TTL != want.TTL {
		t.Errorf("TTL = %d, want %d", got.TTL, want.TTL)
	}
	if got.EdPub != want.EdPub {
		t.Errorf("EdPub = %x, want %x", got.EdPub, want.EdPub)
	}
	if got.Sent != want.Sent {
		t.Errorf("Sent = %d, want %d", got.Sent, want.Sent)
	}
	if !bytes.Equal(got.Avoid, want.Avoid) {
		t.Errorf("Avoid = %x, want %x", []byte(got.Avoid), []byte(want.Avoid))
	}
	if !bytes.Equal(got.Payload, want.Payload) {
		t.Errorf("Payload = %q, want %q", got.Payload, want.Payload)
	}
	if got.Sig != want.Sig {
		t.Errorf("Sig = %x, want %x", got.Sig, want.Sig)
	}
}

func TestMsgRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		msg  Msg
	}{
		{"minimal", Msg{Target: fill(1), TTL: 16, EdPub: fill32(2)}},
		{"payload-only", Msg{Target: fill(3), TTL: 9, EdPub: fill32(4), Payload: []byte("hello rendezvous")}},
		{"avoid-only", Msg{Target: fill(5), TTL: 5, EdPub: fill32(6), Avoid: avoidOf(fill(7), fill(8))}},
		{"full", Msg{Target: fill(9), TTL: 1, EdPub: fill32(10), Avoid: avoidOf(fill(11), fill(12)), Payload: bytes.Repeat([]byte{0xcd}, 300)}},
		{"sent-and-sig", Msg{Target: fill(13), TTL: 4, EdPub: fill32(14), Sent: 1_700_000_123_456_789_000, Payload: []byte("signed"), Sig: sigOf(0xab)}},
	}
	buf := make([]byte, 1<<16)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n, err := EncodeMsg(buf, &tc.msg)
			if err != nil {
				t.Fatalf("EncodeMsg: %v", err)
			}
			if n != msgLen(&tc.msg) {
				t.Errorf("EncodeMsg n = %d, want msgLen %d", n, msgLen(&tc.msg))
			}
			got, err := DecodeMsg(buf[:n])
			if err != nil {
				t.Fatalf("DecodeMsg: %v", err)
			}
			eqMsg(t, got, tc.msg)
		})
	}
}

// EncodeRouteFrame must produce a TypeRoute frame that ParseFrame splits cleanly,
// whose payload DecodeMsg reads back as the same message — the origination path.
func TestEncodeRouteFrame(t *testing.T) {
	m := Msg{Target: fill(1), TTL: 16, EdPub: fill32(2), Avoid: avoidOf(fill(3)), Payload: []byte("ping")}
	buf := make([]byte, 1<<16)
	n, err := EncodeRouteFrame(buf, &m)
	if err != nil {
		t.Fatalf("EncodeRouteFrame: %v", err)
	}
	typ, payload, rest, err := wire.ParseFrame(buf[:n])
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if typ != TypeRoute {
		t.Errorf("type = %d, want TypeRoute %d", typ, TypeRoute)
	}
	if len(rest) != 0 {
		t.Errorf("trailing %d bytes after frame", len(rest))
	}
	got, err := DecodeMsg(payload)
	if err != nil {
		t.Fatalf("DecodeMsg: %v", err)
	}
	eqMsg(t, got, m)
}

// EncodeMsgFrame frames a Msg under an arbitrary type (here a placeholder a package
// above routing would own); the envelope round-trips and the Msg decodes back equal.
func TestEncodeMsgFrame(t *testing.T) {
	const typ wire.Type = 42
	m := Msg{Target: fill(1), TTL: 9, EdPub: fill32(2), Payload: []byte("content")}
	buf := make([]byte, 1<<16)
	n, err := EncodeMsgFrame(buf, typ, &m)
	if err != nil {
		t.Fatalf("EncodeMsgFrame: %v", err)
	}
	gotTyp, payload, _, err := wire.ParseFrame(buf[:n])
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if gotTyp != typ {
		t.Errorf("type = %d, want %d", gotTyp, typ)
	}
	got, err := DecodeMsg(payload)
	if err != nil {
		t.Fatalf("DecodeMsg: %v", err)
	}
	eqMsg(t, got, m)
}

// Every prefix shorter than a full message must return an error, never panic.
func TestDecodeMsgTruncated(t *testing.T) {
	m := Msg{Target: fill(1), TTL: 5, EdPub: fill32(2), Avoid: avoidOf(fill(3)), Payload: []byte("hi")}
	buf := make([]byte, 1<<16)
	n, err := EncodeMsg(buf, &m)
	if err != nil {
		t.Fatalf("EncodeMsg: %v", err)
	}
	for i := range n {
		if _, err := DecodeMsg(buf[:i]); err == nil {
			t.Errorf("DecodeMsg of %d-byte prefix: got nil error, want truncation error", i)
		}
	}
}

// A declared avoid count or payload length larger than the buffer must be rejected,
// not used to index past the end.
func TestDecodeMsgOversizedLengths(t *testing.T) {
	// target(32) | ttl(1) | edpub(32) | navoid=0xff (huge) ... nothing follows.
	b := make([]byte, kad.IDLen+1+32)
	b = append(b, 0xff, 0x01) // navoid varint = 255
	if _, err := DecodeMsg(b); !errors.Is(err, wire.ErrShortBuffer) {
		t.Errorf("oversized navoid: err = %v, want ErrShortBuffer", err)
	}
}

func TestEncodeMsgShortBuffer(t *testing.T) {
	m := Msg{Target: fill(1), Payload: make([]byte, 200)}
	if _, err := EncodeMsg(make([]byte, 16), &m); !errors.Is(err, wire.ErrShortBuffer) {
		t.Errorf("err = %v, want ErrShortBuffer", err)
	}
}

// SetTTL patches the TTL byte in place and leaves every other field intact — the
// zero-copy forwarding decrement.
func TestSetTTL(t *testing.T) {
	m := Msg{Target: fill(9), TTL: 16, EdPub: fill32(1), Payload: []byte("body")}
	buf := make([]byte, 1<<16)
	n, _ := EncodeMsg(buf, &m)
	SetTTL(buf[:n], 3)
	got, err := DecodeMsg(buf[:n])
	if err != nil {
		t.Fatalf("DecodeMsg: %v", err)
	}
	if got.TTL != 3 {
		t.Errorf("TTL after SetTTL = %d, want 3", got.TTL)
	}
	m.TTL = 3
	eqMsg(t, got, m)
}

// TestMsgFreshAndSentRoundTrip: SignMsg stamps Sent, it survives the wire round-trip and
// is covered by the signature, and Fresh enforces the window in both directions.
func TestMsgFreshAndSentRoundTrip(t *testing.T) {
	id := identity.FromSeed([identity.SeedLen]byte{7})
	var ed [32]byte
	copy(ed[:], id.EdPublic())
	now := time.Unix(1_700_000_000, 0)

	m := Msg{Target: fill(1), TTL: 16, EdPub: ed, Payload: []byte("hi")}
	SignMsg(id, TypeRoute, &m, now)

	buf := make([]byte, 1<<10)
	n, _ := EncodeMsg(buf, &m)
	got, err := DecodeMsg(buf[:n])
	if err != nil {
		t.Fatalf("DecodeMsg: %v", err)
	}
	if got.Sent != m.Sent {
		t.Fatalf("Sent round-trip: got %d want %d", got.Sent, m.Sent)
	}
	if !got.VerifySig(TypeRoute) {
		t.Fatal("signature did not verify after round-trip")
	}
	if !got.Fresh(now.Add(10*time.Second), MaxEnvelopeAge) {
		t.Error("a 10s-old message should be fresh")
	}
	if got.Fresh(now.Add(time.Hour), MaxEnvelopeAge) {
		t.Error("a 1h-old message must be stale")
	}
	if got.Fresh(now.Add(-time.Hour), MaxEnvelopeAge) {
		t.Error("a far-future message must be rejected")
	}
	// Tampering with Sent breaks the signature (it is authenticated).
	got.Sent++
	if got.VerifySig(TypeRoute) {
		t.Error("signature verified despite a tampered timestamp")
	}
}

func TestAvoidSet(t *testing.T) {
	a, b, c := fill(1), fill(2), fill(3)
	s := avoidOf(a, b)
	if s.Len() != 2 {
		t.Fatalf("Len = %d, want 2", s.Len())
	}
	if s.At(0) != a || s.At(1) != b {
		t.Errorf("At: got %v,%v want %v,%v", s.At(0), s.At(1), a, b)
	}
	if !s.Has(a) || !s.Has(b) {
		t.Error("Has: member reported absent")
	}
	if s.Has(c) {
		t.Error("Has: non-member reported present")
	}
	var empty AvoidSet
	if empty.Len() != 0 || empty.Has(a) {
		t.Error("empty AvoidSet not empty")
	}
}
