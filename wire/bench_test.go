package wire

import (
	"encoding/binary"
	"testing"

	"github.com/udisondev/nodenet/kad"
)

// These benchmarks rely on b.Loop() (Go 1.24+): it keeps the loop body's calls
// and their results alive, so the compiler does not eliminate them as dead code.
// No sink variables are needed. The hot-path benches must report 0 allocs/op.

// benchPayload mirrors a typical small control message: an ID plus a few
// scalar fields.
func benchPayload() []byte {
	id := sampleID()
	p := make([]byte, kad.IDLen+12)
	off := PutID(p, 0, id)
	off = PutUint32(p, off, 0xdeadbeef)
	off = PutUint32(p, off, 0xcafef00d)
	PutUint32(p, off, 0x01020304)
	return p
}

func BenchmarkReaderUint32(b *testing.B) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], 0x01020304)
	b.ReportAllocs()
	for b.Loop() {
		r := Reader{buf: buf[:]} // stack Reader: no heap escape
		r.Uint32()
	}
}

func BenchmarkReaderUvarint(b *testing.B) {
	var buf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(buf[:], 0x0708090a0b0c0d0e)
	b.ReportAllocs()
	for b.Loop() {
		r := Reader{buf: buf[:n]}
		r.Uvarint()
	}
}

func BenchmarkReaderID(b *testing.B) {
	var buf [kad.IDLen]byte
	PutID(buf[:], 0, sampleID())
	b.ReportAllocs()
	for b.Loop() {
		r := Reader{buf: buf[:]}
		r.ID()
	}
}

func BenchmarkEncodeFrame(b *testing.B) {
	p := benchPayload()
	dst := make([]byte, len(p)+16)
	b.ReportAllocs()
	for b.Loop() {
		EncodeFrame(dst, 7, p)
	}
}

func BenchmarkParseFrame(b *testing.B) {
	p := benchPayload()
	dst := make([]byte, len(p)+16)
	frame, _ := EncodeFrame(dst, 7, p)
	b.ReportAllocs()
	for b.Loop() {
		ParseFrame(frame)
	}
}
