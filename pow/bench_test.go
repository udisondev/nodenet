package pow

import (
	"context"
	"testing"
)

// BenchmarkSatisfies measures the per-packet forwarder check. It is the hot
// path and must report 0 allocs/op. The ID has a non-zero high word, so the
// scan exits on the first word — the common case.
func BenchmarkSatisfies(b *testing.B) {
	id := idWithLeadingZeros(12)
	b.ReportAllocs()
	for b.Loop() {
		Satisfies(id, 8)
	}
}

// BenchmarkLeadingZeros guards the underlying measure against alloc regressions.
func BenchmarkLeadingZeros(b *testing.B) {
	id := idWithLeadingZeros(12)
	b.ReportAllocs()
	for b.Loop() {
		LeadingZeros(id)
	}
}

// BenchmarkSolve is informational, not a regression gate: grinding cost grows
// ~2^d, so the number reported swings with d and entropy. A small fixed d keeps
// it quick while still exercising the parallel search.
func BenchmarkSolve(b *testing.B) {
	const d = 12
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Solve(context.Background(), &counterReader{}, d); err != nil {
			b.Fatal(err)
		}
	}
}
