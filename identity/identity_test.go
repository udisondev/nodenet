package identity

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io"
	"testing"

	"golang.org/x/crypto/blake2b"
)

// goldenIDHex pins the NodeID derived from fixedSeed(); see TestGoldenVector.
const goldenIDHex = "45cd1496465d1e9e045a991d920ec5054c312f077765113c936b4d5c6d1e6ad5"

// fixedSeed is a deterministic, non-zero seed for the tests.
func fixedSeed() [SeedLen]byte {
	var s [SeedLen]byte
	for i := range s {
		s[i] = byte(i + 1)
	}
	return s
}

// TestFromSeedDeterministic: the same seed always derives the same key material.
func TestFromSeedDeterministic(t *testing.T) {
	seed := fixedSeed()
	a := FromSeed(seed)
	b := FromSeed(seed)

	if a.ID() != b.ID() {
		t.Errorf("ID mismatch: %s vs %s", a.ID(), b.ID())
	}
	if !a.EdPublic().Equal(b.EdPublic()) {
		t.Error("Ed25519 public keys differ for the same seed")
	}
	if a.KEXPublic() != b.KEXPublic() {
		t.Error("X25519 public keys differ for the same seed")
	}
	if a.Seed() != seed {
		t.Error("Seed() did not round-trip the input seed")
	}
}

// TestDifferentSeedsDifferentIdentities: distinct seeds yield distinct identities.
func TestDifferentSeedsDifferentIdentities(t *testing.T) {
	a := FromSeed(fixedSeed())
	var other [SeedLen]byte
	for i := range other {
		other[i] = byte(0xff - i)
	}
	b := FromSeed(other)

	if a.ID() == b.ID() {
		t.Error("different seeds produced the same NodeID")
	}
	if a.KEXPublic() == b.KEXPublic() {
		t.Error("different seeds produced the same X25519 public key")
	}
}

// TestKeypairsIndependent: domain separation makes the Ed25519 and X25519 key
// material genuinely independent — the public keys must not coincide.
func TestKeypairsIndependent(t *testing.T) {
	id := FromSeed(fixedSeed())
	kexPub := id.KEXPublic()
	if bytes.Equal(id.EdPublic(), kexPub[:]) {
		t.Error("Ed25519 and X25519 public keys are equal — domain separation failed")
	}
}

// TestDeriveID: NodeID is exactly BLAKE2b-256(ed_pub).
func TestDeriveID(t *testing.T) {
	id := FromSeed(fixedSeed())
	want := blake2b.Sum256(id.EdPublic())
	if id.ID() != want {
		t.Errorf("ID() = %s, want BLAKE2b(ed_pub) = %x", id.ID(), want)
	}
	if DeriveID(id.EdPublic()) != id.ID() {
		t.Error("DeriveID(EdPublic) != ID()")
	}
}

// TestSignVerify: signatures round-trip; tampering with message or signature fails.
func TestSignVerify(t *testing.T) {
	id := FromSeed(fixedSeed())
	msg := []byte("nodenet rendezvous coordinates")
	sig := id.Sign(msg)

	if !ed25519.Verify(id.EdPublic(), msg, sig) {
		t.Fatal("valid signature failed to verify")
	}

	bad := append([]byte(nil), msg...)
	bad[0] ^= 0x01
	if ed25519.Verify(id.EdPublic(), bad, sig) {
		t.Error("signature verified for a tampered message")
	}

	badSig := append([]byte(nil), sig...)
	badSig[0] ^= 0x01
	if ed25519.Verify(id.EdPublic(), msg, badSig) {
		t.Error("tampered signature verified")
	}
}

// TestNewMatchesFromSeed: New reads its seed from the reader, so a fixed reader
// reproduces FromSeed exactly.
func TestNewMatchesFromSeed(t *testing.T) {
	seed := fixedSeed()
	id, err := New(bytes.NewReader(seed[:]))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if id.ID() != FromSeed(seed).ID() {
		t.Error("New(fixed seed) != FromSeed(seed)")
	}
}

// TestNewShortReader: New fails cleanly when the reader cannot supply a full seed.
func TestNewShortReader(t *testing.T) {
	short := make([]byte, SeedLen-1)
	_, err := New(bytes.NewReader(short))
	if err == nil {
		t.Fatal("expected error from a short reader, got nil")
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("expected io.ErrUnexpectedEOF, got %v", err)
	}
}

// TestKEXConsistency: KEXPublic matches the private key's public, and the static
// X25519 ECDH is symmetric across two identities (groundwork for sealed-box).
func TestKEXConsistency(t *testing.T) {
	a := FromSeed(fixedSeed())
	var bSeed [SeedLen]byte
	for i := range bSeed {
		bSeed[i] = byte(100 + i)
	}
	b := FromSeed(bSeed)

	pub := a.KEXPublic()
	if !bytes.Equal(pub[:], a.KEX().PublicKey().Bytes()) {
		t.Error("KEXPublic() does not match KEX().PublicKey()")
	}

	ssAB, err := a.KEX().ECDH(b.KEX().PublicKey())
	if err != nil {
		t.Fatalf("ECDH a->b: %v", err)
	}
	ssBA, err := b.KEX().ECDH(a.KEX().PublicKey())
	if err != nil {
		t.Fatalf("ECDH b->a: %v", err)
	}
	if !bytes.Equal(ssAB, ssBA) {
		t.Error("X25519 shared secret is not symmetric")
	}
}

// TestGoldenVector pins the derivation: this NodeID for fixedSeed() must never
// change silently (a changed HKDF label or hash would break it). Regenerate
// intentionally only when the derivation scheme is deliberately revised.
func TestGoldenVector(t *testing.T) {
	const wantID = goldenIDHex
	got := FromSeed(fixedSeed()).ID().String()
	if got != wantID {
		t.Errorf("golden NodeID changed:\n got  %s\n want %s", got, wantID)
	}
}
