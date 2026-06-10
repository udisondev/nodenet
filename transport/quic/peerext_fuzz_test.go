package quic

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

// FuzzDecodePeerExt asserts the identity-extension decoder is robust against
// arbitrary bytes off a peer's certificate: it must never panic, every accepted
// value must have a 32-byte key and 64-byte signature, and re-encoding an
// accepted value must reproduce the input exactly.
func FuzzDecodePeerExt(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, peerExtLen-1))
	f.Add(make([]byte, peerExtLen))
	f.Add(make([]byte, peerExtLen+1))
	f.Add(encodePeerExt(sampleExt()))

	f.Fuzz(func(t *testing.T, raw []byte) {
		e, err := decodePeerExt(raw)
		if err != nil {
			return // rejecting malformed input is fine; not panicking is the point
		}
		if len(e.EdPub) != ed25519.PublicKeySize {
			t.Fatalf("accepted ext with EdPub len %d", len(e.EdPub))
		}
		if len(e.Sig) != ed25519.SignatureSize {
			t.Fatalf("accepted ext with Sig len %d", len(e.Sig))
		}
		if !bytes.Equal(encodePeerExt(e), raw) {
			t.Fatal("re-encode of accepted extension does not match input")
		}
	})
}
