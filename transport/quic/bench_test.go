package quic

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"testing"
)

// nopWriter is a concrete, non-retaining sink, mirroring how quic-go's
// Stream.Write consumes bytes synchronously — so the framing write benches the
// real escape behaviour rather than an interface-induced heap escape.
type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

// BenchmarkWriteFrame measures the Send hot path's framing: a uvarint length
// prefix written from the reused per-connection scratch, then the payload. With
// the scratch preallocated (as it is on quicConn) the write is allocation-free —
// it must report 0 allocs/op.
func BenchmarkWriteFrame(b *testing.B) {
	payload := []byte("small control frame")
	var whdr [binary.MaxVarintLen64]byte // stands in for quicConn.whdr (allocated once)
	var sink nopWriter
	b.ReportAllocs()
	for b.Loop() {
		n := binary.PutUvarint(whdr[:], uint64(len(payload)))
		if _, err := sink.Write(whdr[:n]); err != nil {
			b.Fatalf("write hdr: %v", err)
		}
		if _, err := sink.Write(payload); err != nil {
			b.Fatalf("write payload: %v", err)
		}
	}
}

// BenchmarkReadFrame measures the read path's length-prefix parse over a buffered
// reader, the per-frame cost of the read loop's framing. Target 0 allocs/op.
func BenchmarkReadFrame(b *testing.B) {
	frame := appendFrame(nil, []byte("small control frame"))
	src := bytes.NewReader(nil)
	br := bufio.NewReader(src)
	b.ReportAllocs()
	for b.Loop() {
		src.Reset(frame)
		br.Reset(src)
		n, err := readFrameLen(br)
		if err != nil {
			b.Fatalf("readFrameLen: %v", err)
		}
		if _, err := br.Discard(n); err != nil {
			b.Fatalf("discard: %v", err)
		}
	}
}
