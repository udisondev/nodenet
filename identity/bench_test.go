package identity

import (
	"crypto/ed25519"
	"testing"
)

// These benchmarks rely on b.Loop() (Go 1.24+): it keeps the loop body's calls
// and their results alive, so the compiler does not eliminate them as dead code.
// No sink variables are needed — verified by a no-sink probe matching ns/op.

// BenchmarkFromSeed measures the full derivation: HKDF extract + two expands,
// Ed25519 and X25519 key construction, and the NodeID hash.
func BenchmarkFromSeed(b *testing.B) {
	seed := fixedSeed()
	b.ReportAllocs()
	for b.Loop() {
		FromSeed(seed)
	}
}

// BenchmarkIDFromSeed measures the NodeID-only derivation used by the PoW grind:
// HKDF extract + the Ed25519 expand and key construction, skipping the X25519
// scalar-mult. It should be markedly cheaper than BenchmarkFromSeed, which is the
// whole point — the grind runs this ~2^d times and FromSeed only once.
func BenchmarkIDFromSeed(b *testing.B) {
	seed := fixedSeed()
	b.ReportAllocs()
	for b.Loop() {
		IDFromSeed(seed)
	}
}

// BenchmarkSign measures one Ed25519 signature.
func BenchmarkSign(b *testing.B) {
	id := FromSeed(fixedSeed())
	msg := []byte("nodenet rendezvous coordinates")
	b.ReportAllocs()
	for b.Loop() {
		id.Sign(msg)
	}
}

// BenchmarkVerify measures one Ed25519 verification.
func BenchmarkVerify(b *testing.B) {
	id := FromSeed(fixedSeed())
	msg := []byte("nodenet rendezvous coordinates")
	sig := id.Sign(msg)
	pub := id.EdPublic()
	b.ReportAllocs()
	for b.Loop() {
		ed25519.Verify(pub, msg, sig)
	}
}

// BenchmarkDeriveID measures the NodeID hash alone — the common operation of
// checking a presented ed_pub against an expected NodeID.
func BenchmarkDeriveID(b *testing.B) {
	id := FromSeed(fixedSeed())
	pub := id.EdPublic()
	b.ReportAllocs()
	for b.Loop() {
		DeriveID(pub)
	}
}
