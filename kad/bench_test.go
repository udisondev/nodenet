package kad

import (
	"math/rand/v2"
	"testing"
)

// No sink variables: b.Loop() keeps the loop body alive against dead-code
// elimination on its own. The hot-path benches must report 0 allocs/op.

// benchIDs returns a fixed triple of distinct random IDs, which differ in the
// first byte and so exit the scan on the first word.
func benchIDs() (target, a, b ID) {
	rng := rand.New(rand.NewPCG(42, 1337))
	return randID(rng), randID(rng), randID(rng)
}

// nearIDs returns a triple sharing a long prefix, differing only in the last
// byte, so the scan runs to the final word. This mirrors routing comparing
// candidates clustered around a key.
func nearIDs() (target, a, b ID) {
	rng := rand.New(rand.NewPCG(42, 1337))
	target = randID(rng)
	a, b = target, target
	a[IDLen-1] ^= 0x01
	b[IDLen-1] ^= 0x02
	return target, a, b
}

func BenchmarkDistance(b *testing.B) {
	_, x, y := benchIDs()
	b.ReportAllocs()
	for b.Loop() {
		Distance(x, y)
	}
}

func BenchmarkDistanceCmp(b *testing.B) {
	target, x, y := benchIDs()
	b.ReportAllocs()
	for b.Loop() {
		DistanceCmp(target, x, y)
	}
}

func BenchmarkDistanceCmpNear(b *testing.B) {
	target, x, y := nearIDs()
	b.ReportAllocs()
	for b.Loop() {
		DistanceCmp(target, x, y)
	}
}

func BenchmarkCommonPrefixLen(b *testing.B) {
	_, x, y := benchIDs()
	b.ReportAllocs()
	for b.Loop() {
		CommonPrefixLen(x, y)
	}
}

func BenchmarkCommonPrefixLenNear(b *testing.B) {
	_, x, y := nearIDs()
	b.ReportAllocs()
	for b.Loop() {
		CommonPrefixLen(x, y)
	}
}
