package transport

import (
	"testing"
	"time"
)

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

// The media-class Get/Release round-trip backs every datagram sent and
// received, thousands per second per call: 0 allocs/op after warmup.
func BenchmarkPacketGetReleaseMedia(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		p := GetMedia()
		p.SetLen(MaxMediaDatagram)
		p.Release()
	}
}

// Laying a media frame (channel byte + payload copy) into a pooled buffer is
// the datagram send path's only byte work: 0 allocs/op.
func BenchmarkPutMediaFrame(b *testing.B) {
	payload := make([]byte, MaxMediaDatagram)
	dst := make([]byte, MaxMediaPacketLen)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := PutMediaFrame(dst, FirstAppChannel, payload); err != nil {
			b.Fatal(err)
		}
	}
}

// Splitting a received media frame is a single bounds check and a re-slice:
// 0 allocs/op.
func BenchmarkParseMediaFrame(b *testing.B) {
	frame := make([]byte, MaxMediaDatagram+1)
	frame[0] = FirstAppChannel
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := ParseMediaFrame(frame); err != nil {
			b.Fatal(err)
		}
	}
}

// AllowN is charged per received datagram (bytes + packets), on the receive
// goroutine's hot path: 0 allocs/op.
func BenchmarkTokenBucketAllowN(b *testing.B) {
	var tb TokenBucket
	now := time.Unix(1000, 0)
	b.ReportAllocs()
	for b.Loop() {
		// Advance time each iteration so the bucket keeps refilling and the
		// allowed branch (the hot one) is what gets measured.
		now = now.Add(time.Second)
		if !tb.AllowN(now, 1200, MediaRxBytesRate, MediaRxBytesBurst) {
			b.Fatal("AllowN refused with a refilling bucket")
		}
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
