package quic

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func sampleExt() peerExt {
	edPub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	sig := make([]byte, ed25519.SignatureSize)
	for i := range edPub {
		edPub[i] = byte(i + 1)
	}
	for i := range sig {
		sig[i] = byte(0x80 + i)
	}
	return peerExt{EdPub: edPub, Sig: sig}
}

func TestPeerExtRoundTrip(t *testing.T) {
	want := sampleExt()
	raw := encodePeerExt(want)
	if len(raw) != peerExtLen {
		t.Fatalf("encoded length = %d, want %d", len(raw), peerExtLen)
	}
	got, err := decodePeerExt(raw)
	if err != nil {
		t.Fatalf("decodePeerExt: %v", err)
	}
	if !bytes.Equal(got.EdPub, want.EdPub) {
		t.Errorf("EdPub = %x, want %x", got.EdPub, want.EdPub)
	}
	if !bytes.Equal(got.Sig, want.Sig) {
		t.Errorf("Sig = %x, want %x", got.Sig, want.Sig)
	}
}

func TestPeerExtDecodeRejectsBadLength(t *testing.T) {
	cases := map[string][]byte{
		"empty":      {},
		"short":      make([]byte, peerExtLen-1),
		"long":       make([]byte, peerExtLen+1),
		"only-edpub": make([]byte, ed25519.PublicKeySize),
		"only-sig":   make([]byte, ed25519.SignatureSize),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := decodePeerExt(raw); err != errBadExtension {
				t.Fatalf("err = %v, want errBadExtension", err)
			}
		})
	}
}

func TestPeerExtDecodeDoesNotAlias(t *testing.T) {
	raw := encodePeerExt(sampleExt())
	got, err := decodePeerExt(raw)
	if err != nil {
		t.Fatalf("decodePeerExt: %v", err)
	}
	// Mutating the source must not change the decoded copy.
	orig := append([]byte(nil), got.EdPub...)
	for i := range raw {
		raw[i] ^= 0xff
	}
	if !bytes.Equal(got.EdPub, orig) {
		t.Fatal("decoded EdPub aliases the input buffer")
	}
}

func TestPeerExtEncodePanicsOnBadInput(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on wrong-sized input")
		}
	}()
	encodePeerExt(peerExt{EdPub: make(ed25519.PublicKey, 4), Sig: make([]byte, 64)})
}
