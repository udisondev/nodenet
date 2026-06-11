package rendezvous

import (
	"encoding/binary"
	"errors"
	"reflect"
	"testing"

	"github.com/udisondev/nodenet/transport"
)

func sampleAddrs() []transport.Addr {
	return []transport.Addr{
		{Net: "mem", Endpoint: "node-7"},
		{Net: "quic", Endpoint: "192.0.2.7:443"},
	}
}

func TestHelloRoundTrip(t *testing.T) {
	a := idFromSeed(1)
	r := idFromSeed(2) // recipient; target = r.ID()

	h := Hello{XPub: a.KEXPublic(), Addrs: sampleAddrs(), Nonce: [NonceLen]byte{1, 2, 3}}
	SignHello(a, r.ID(), &h)

	b, err := MarshalHello(&h)
	if err != nil {
		t.Fatalf("MarshalHello: %v", err)
	}
	got, err := DecodeHello(b)
	if err != nil {
		t.Fatalf("DecodeHello: %v", err)
	}
	if got.XPub != h.XPub || got.Nonce != h.Nonce || got.Sig != h.Sig ||
		!reflect.DeepEqual(got.Addrs, h.Addrs) {
		t.Fatal("hello round-trip mismatch")
	}
	// The decoded hello verifies under A's originator key for delivery to R.
	var aEd [32]byte
	copy(aEd[:], a.EdPublic())
	if err := VerifyHello(r.ID(), aEd, &got); err != nil {
		t.Fatalf("VerifyHello: %v", err)
	}
}

func TestVerifyHelloRejectsTamper(t *testing.T) {
	a := idFromSeed(1)
	r := idFromSeed(2)
	var aEd [32]byte
	copy(aEd[:], a.EdPublic())

	h := Hello{XPub: a.KEXPublic(), Addrs: sampleAddrs(), Nonce: [NonceLen]byte{9}}
	SignHello(a, r.ID(), &h)

	// Wrong target (hello was bound to r.ID()).
	if err := VerifyHello(idFromSeed(3).ID(), aEd, &h); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("wrong target: err = %v, want ErrBadSignature", err)
	}
	// Tampered nonce.
	bad := h
	bad.Nonce[0] ^= 0xff
	if err := VerifyHello(r.ID(), aEd, &bad); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered nonce: err = %v, want ErrBadSignature", err)
	}
	// Wrong originator key.
	var wrongEd [32]byte
	copy(wrongEd[:], idFromSeed(4).EdPublic())
	if err := VerifyHello(r.ID(), wrongEd, &h); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("wrong originator: err = %v, want ErrBadSignature", err)
	}
}

func TestReplyRoundTripAndVerify(t *testing.T) {
	r := idFromSeed(2) // R answers
	nonce := [NonceLen]byte{4, 5, 6}

	rep := Reply{XPub: r.KEXPublic(), Addrs: sampleAddrs(), Nonce: nonce}
	SignReply(r, &rep)

	b, err := MarshalReply(&rep)
	if err != nil {
		t.Fatalf("MarshalReply: %v", err)
	}
	got, err := DecodeReply(b)
	if err != nil {
		t.Fatalf("DecodeReply: %v", err)
	}
	if got.EdPub != rep.EdPub || got.XPub != rep.XPub || got.Nonce != rep.Nonce ||
		got.Sig != rep.Sig || !reflect.DeepEqual(got.Addrs, rep.Addrs) {
		t.Fatal("reply round-trip mismatch")
	}
	// A verifies the reply against the handshake it initiated to NodeID_R.
	if err := VerifyReply(r.ID(), nonce, &got); err != nil {
		t.Fatalf("VerifyReply: %v", err)
	}
}

func TestVerifyReplyRejections(t *testing.T) {
	r := idFromSeed(2)
	nonce := [NonceLen]byte{7}
	rep := Reply{XPub: r.KEXPublic(), Addrs: sampleAddrs(), Nonce: nonce}
	SignReply(r, &rep)

	// Anti-MITM: a forwarder answering in R's place uses its own key, so
	// DeriveID(EdPub) != NodeID_R.
	if err := VerifyReply(idFromSeed(99).ID(), nonce, &rep); !errors.Is(err, ErrWrongTarget) {
		t.Fatalf("wrong target: err = %v, want ErrWrongTarget", err)
	}
	// Stale/replayed: nonce does not match this handshake.
	if err := VerifyReply(r.ID(), [NonceLen]byte{0xff}, &rep); !errors.Is(err, ErrNonceMismatch) {
		t.Fatalf("nonce mismatch: err = %v, want ErrNonceMismatch", err)
	}
	// Tampered signed content (x_pub) with nonce/key intact: signature fails.
	bad := rep
	bad.XPub[0] ^= 0xff
	if err := VerifyReply(r.ID(), nonce, &bad); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered xpub: err = %v, want ErrBadSignature", err)
	}
}

// TestDecodeRejectsTrailingJunk: the decoders enforce the canonical wire form — a payload
// and payload||junk must not both decode to the same message (same rule routing.DecodeMsg
// enforces). The signature is rebuilt from the parsed fields, so without this check the
// junk-suffixed payload would verify identically.
func TestDecodeRejectsTrailingJunk(t *testing.T) {
	a := idFromSeed(1)
	r := idFromSeed(2)

	h := Hello{XPub: a.KEXPublic(), Addrs: sampleAddrs(), Nonce: [NonceLen]byte{1}}
	SignHello(a, r.ID(), &h)
	hb, err := MarshalHello(&h)
	if err != nil {
		t.Fatalf("MarshalHello: %v", err)
	}
	if _, err := DecodeHello(append(hb, 0xde)); err == nil {
		t.Error("DecodeHello accepted trailing junk")
	}

	rep := Reply{XPub: r.KEXPublic(), Addrs: sampleAddrs(), Nonce: [NonceLen]byte{2}}
	SignReply(r, &rep)
	rb, err := MarshalReply(&rep)
	if err != nil {
		t.Fatalf("MarshalReply: %v", err)
	}
	if _, err := DecodeReply(append(rb, 0xde)); err == nil {
		t.Error("DecodeReply accepted trailing junk")
	}
}

// floodPayload builds a Hello/Reply payload whose address list declares cnt
// entries over 2*cnt zero bytes (each 0x00 0x00 = one empty address), framed by
// lead prefix bytes (the public keys) and the trailing nonce+sig. Without a count
// cap the whole declared count allocates and parses.
func floodPayload(lead, cnt int) []byte {
	b := make([]byte, 0, lead+binary.MaxVarintLen64+2*cnt+NonceLen+64)
	b = append(b, make([]byte, lead)...)
	b = binary.AppendUvarint(b, uint64(cnt))
	b = append(b, make([]byte, 2*cnt)...)
	return append(b, make([]byte, NonceLen+64)...)
}

// TestDecodeRejectsAddrFlood: a payload declaring an absurd address count (~500k
// over ~1 MiB of zeros) must be refused before the slice is allocated — otherwise
// every delivered frame costs a ~16 MiB zeroed allocation on the dispatch
// goroutine, and the Reply path runs before any signature or nonce check. A real
// hello/reply carries a handful of coordinates, so the cap rejects nothing
// legitimate.
func TestDecodeRejectsAddrFlood(t *testing.T) {
	const cnt = 500_000
	var h Hello
	var rep Reply
	hello := floodPayload(len(h.XPub), cnt)
	reply := floodPayload(len(rep.EdPub)+len(rep.XPub), cnt)
	if allocs := testing.AllocsPerRun(10, func() {
		if _, err := DecodeHello(hello); !errors.Is(err, transport.ErrTooManyAddrs) {
			t.Fatalf("DecodeHello(flood): err = %v, want transport.ErrTooManyAddrs", err)
		}
		if _, err := DecodeReply(reply); !errors.Is(err, transport.ErrTooManyAddrs) {
			t.Fatalf("DecodeReply(flood): err = %v, want transport.ErrTooManyAddrs", err)
		}
	}); allocs != 0 {
		t.Errorf("flood rejection allocated %.0f times, want 0", allocs)
	}
}

// The protocol cap is symmetric: the encoders refuse a list the decoders would
// reject, and a list exactly at the cap round-trips.
func TestAddrCapBoundary(t *testing.T) {
	atCap := make([]transport.Addr, maxCoordAddrs)
	h := Hello{Addrs: atCap}
	hb, err := MarshalHello(&h)
	if err != nil {
		t.Fatalf("MarshalHello(at cap): %v", err)
	}
	if got, err := DecodeHello(hb); err != nil || len(got.Addrs) != maxCoordAddrs {
		t.Fatalf("DecodeHello(at cap) = %d addrs, err %v", len(got.Addrs), err)
	}
	rep := Reply{Addrs: atCap}
	rb, err := MarshalReply(&rep)
	if err != nil {
		t.Fatalf("MarshalReply(at cap): %v", err)
	}
	if got, err := DecodeReply(rb); err != nil || len(got.Addrs) != maxCoordAddrs {
		t.Fatalf("DecodeReply(at cap) = %d addrs, err %v", len(got.Addrs), err)
	}

	over := make([]transport.Addr, maxCoordAddrs+1)
	if _, err := MarshalHello(&Hello{Addrs: over}); !errors.Is(err, transport.ErrTooManyAddrs) {
		t.Fatalf("MarshalHello(over cap): err = %v, want transport.ErrTooManyAddrs", err)
	}
	if _, err := MarshalReply(&Reply{Addrs: over}); !errors.Is(err, transport.ErrTooManyAddrs) {
		t.Fatalf("MarshalReply(over cap): err = %v, want transport.ErrTooManyAddrs", err)
	}
}

func FuzzDecodeHello(f *testing.F) {
	a := idFromSeed(1)
	h := Hello{XPub: a.KEXPublic(), Addrs: sampleAddrs(), Nonce: [NonceLen]byte{1}}
	SignHello(a, idFromSeed(2).ID(), &h)
	if b, err := MarshalHello(&h); err == nil {
		f.Add(b)
	}
	noAddr := Hello{XPub: a.KEXPublic()}
	if b, err := MarshalHello(&noAddr); err == nil {
		f.Add(b)
	}
	f.Add([]byte{})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0x0f}) // huge declared addr count
	f.Add(floodPayload(32, 1000))               // over-cap count with a parseable body

	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := DecodeHello(b) // must never panic
		if err != nil {
			return
		}
		if len(got.Addrs) > maxCoordAddrs {
			t.Fatalf("decoded %d addrs, cap is %d", len(got.Addrs), maxCoordAddrs)
		}
		buf, err := MarshalHello(&got)
		if err != nil {
			t.Fatalf("re-encode: %v", err)
		}
		got2, err := DecodeHello(buf)
		if err != nil {
			t.Fatalf("re-decode: %v", err)
		}
		if got2.XPub != got.XPub || got2.Nonce != got.Nonce || got2.Sig != got.Sig ||
			!reflect.DeepEqual(got2.Addrs, got.Addrs) {
			t.Fatal("round-trip mismatch")
		}
	})
}

func FuzzDecodeReply(f *testing.F) {
	r := idFromSeed(2)
	rep := Reply{XPub: r.KEXPublic(), Addrs: sampleAddrs(), Nonce: [NonceLen]byte{3}}
	SignReply(r, &rep)
	if b, err := MarshalReply(&rep); err == nil {
		f.Add(b)
	}
	f.Add([]byte{})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0x0f})
	f.Add(floodPayload(64, 1000)) // over-cap count with a parseable body

	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := DecodeReply(b) // must never panic
		if err != nil {
			return
		}
		if len(got.Addrs) > maxCoordAddrs {
			t.Fatalf("decoded %d addrs, cap is %d", len(got.Addrs), maxCoordAddrs)
		}
		buf, err := MarshalReply(&got)
		if err != nil {
			t.Fatalf("re-encode: %v", err)
		}
		got2, err := DecodeReply(buf)
		if err != nil {
			t.Fatalf("re-decode: %v", err)
		}
		if got2.EdPub != got.EdPub || got2.XPub != got.XPub || got2.Nonce != got.Nonce ||
			got2.Sig != got.Sig || !reflect.DeepEqual(got2.Addrs, got.Addrs) {
			t.Fatal("round-trip mismatch")
		}
	})
}
