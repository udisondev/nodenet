package rendezvous

import (
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

	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := DecodeHello(b) // must never panic
		if err != nil {
			return
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

	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := DecodeReply(b) // must never panic
		if err != nil {
			return
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
