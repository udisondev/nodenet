package wire

import (
	"encoding/binary"

	"github.com/udisondev/nodenet/kad"
)

// Reader is a zero-copy cursor over a received buffer. Each accessor reads one
// value at the current offset, advances past it, and reports ErrShortBuffer (not
// a panic) if the buffer ends first; a failed read leaves the offset untouched,
// so decoding can stop cleanly at the first error. Slice-returning accessors
// (Bytes) return a window that ALIASES the underlying buffer — valid only while
// that buffer lives; copy it to retain it.
//
// Reader is a small value type; construct it with NewReader. NewReader inlines,
// and a Reader that does not escape lives on the stack — decode paths built on
// it reach 0 allocs/op without any special construction.
type Reader struct {
	buf []byte
	off int
}

// NewReader returns a Reader positioned at the start of b. It reads from b
// in place and never copies it.
func NewReader(b []byte) *Reader { return &Reader{buf: b} }

// Remaining reports how many unread bytes are left.
func (r *Reader) Remaining() int { return len(r.buf) - r.off }

// Uint32 reads a big-endian uint32 and advances 4 bytes.
func (r *Reader) Uint32() (uint32, error) {
	if len(r.buf)-r.off < 4 {
		return 0, ErrShortBuffer
	}
	v := binary.BigEndian.Uint32(r.buf[r.off:])
	r.off += 4
	return v, nil
}

// Uvarint reads an unsigned varint and advances past it. It returns
// ErrShortBuffer if the buffer ends mid-varint or the encoding overflows 64
// bits (a malformed value is treated as truncated input — never a panic).
func (r *Reader) Uvarint() (uint64, error) {
	v, n := binary.Uvarint(r.buf[r.off:])
	if n <= 0 {
		return 0, ErrShortBuffer
	}
	r.off += n
	return v, nil
}

// Bytes returns the next n raw bytes as a slice ALIASING the underlying buffer
// and advances past them. It returns ErrShortBuffer if fewer than n bytes (or a
// negative n) remain. Copy the result to keep it beyond the buffer's lifetime.
func (r *Reader) Bytes(n int) ([]byte, error) {
	if n < 0 || len(r.buf)-r.off < n {
		return nil, ErrShortBuffer
	}
	b := r.buf[r.off : r.off+n]
	r.off += n
	return b, nil
}

// ID reads a kad.ID (kad.IDLen raw bytes) into a value and advances past it. It
// copies into the returned array (which is a stack value, not an alias), so the
// ID outlives the buffer.
func (r *Reader) ID() (kad.ID, error) {
	var id kad.ID
	if len(r.buf)-r.off < kad.IDLen {
		return id, ErrShortBuffer
	}
	copy(id[:], r.buf[r.off:])
	r.off += kad.IDLen
	return id, nil
}
