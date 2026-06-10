package transport

import "testing"

// The Get/Release round-trip is the buffer hot path under every send and
// receive. After warmup the pool serves both ends, so it must report 0 allocs/op.
// b.Loop (Go 1.24+) keeps the body live, so no sink variable is needed.
func BenchmarkPacketGetRelease(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		p := Get()
		p.SetLen(64)
		p.Release()
	}
}

// Encoding an address into a pre-sized buffer is allocation-free: 0 allocs/op.
func BenchmarkAppendAddr(b *testing.B) {
	a := Addr{Net: "quic", Endpoint: "203.0.113.4:443"}
	dst := make([]byte, 0, AddrWireLen(a))
	b.ReportAllocs()
	for b.Loop() {
		dst = AppendAddr(dst[:0], a)
	}
}

// Decoding allocates exactly the two string copies (Net and Endpoint) — they are
// mandatory, because the Addr must outlive the pooled receive buffer it was
// parsed from. Everything else on the parse path is allocation-free.
func BenchmarkParseAddr(b *testing.B) {
	enc := AppendAddr(nil, Addr{Net: "quic", Endpoint: "203.0.113.4:443"})
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := ParseAddr(enc); err != nil {
			b.Fatal(err)
		}
	}
}
