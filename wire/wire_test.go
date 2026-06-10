package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/udisondev/nodenet/kad"
)

// sampleID is a deterministic, non-zero ID for the tests.
func sampleID() kad.ID {
	var id kad.ID
	for i := range id {
		id[i] = byte(i + 1)
	}
	return id
}

// --- Reader round-trips ---

func TestReaderPrimitivesRoundTrip(t *testing.T) {
	id := sampleID()
	buf := make([]byte, 64)
	off := PutUint32(buf, 0, 0x03040506)
	off = PutID(buf, off, id)

	r := NewReader(buf[:off])
	if v, err := r.Uint32(); err != nil || v != 0x03040506 {
		t.Fatalf("Uint32 = %#x, %v", v, err)
	}
	if v, err := r.ID(); err != nil || v != id {
		t.Fatalf("ID = %s, %v", v, err)
	}
	if r.Remaining() != 0 {
		t.Fatalf("Remaining = %d, want 0", r.Remaining())
	}
}

func TestUvarintRoundTrip(t *testing.T) {
	// Boundary values around the 7-bit varint group edges, plus the max.
	vals := []uint64{0, 1, 127, 128, 16383, 16384, 1<<32 - 1, 1<<64 - 1}
	for _, v := range vals {
		buf := make([]byte, binary.MaxVarintLen64)
		off := PutUvarint(buf, 0, v)
		r := NewReader(buf[:off])
		got, err := r.Uvarint()
		if err != nil || got != v {
			t.Fatalf("Uvarint %d round-trip = %d, %v", v, got, err)
		}
		if r.Remaining() != 0 {
			t.Fatalf("Uvarint %d: Remaining = %d, want 0", v, r.Remaining())
		}
	}
}

func TestBytesAliasesBuffer(t *testing.T) {
	buf := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	r := NewReader(buf)
	got, err := r.Bytes(3)
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	if !bytes.Equal(got, buf[:3]) {
		t.Fatalf("Bytes = %x, want %x", got, buf[:3])
	}
	// Aliasing: mutating the source must show through the returned slice.
	buf[0] = 0x00
	if got[0] != 0x00 {
		t.Fatal("Bytes returned a copy, expected an alias of the buffer")
	}
}

// --- Reader error paths: short / truncated input must error, never panic ---

func TestReaderShortBuffer(t *testing.T) {
	cases := []struct {
		name string
		read func(*Reader) error
	}{
		{"uint32", func(r *Reader) error { _, e := r.Uint32(); return e }},
		{"id", func(r *Reader) error { _, e := r.ID(); return e }},
		{"bytes", func(r *Reader) error { _, e := r.Bytes(8); return e }},
		{"bytes-negative", func(r *Reader) error { _, e := r.Bytes(-1); return e }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := NewReader([]byte{0x01}) // 1 byte: too short for every case
			if err := c.read(r); !errors.Is(err, ErrShortBuffer) {
				t.Fatalf("err = %v, want ErrShortBuffer", err)
			}
		})
	}
}

func TestUvarintShortBuffer(t *testing.T) {
	cases := map[string][]byte{
		"empty":     {},     // nothing to read
		"truncated": {0x80}, // continuation bit set but no following byte
	}
	for name, buf := range cases {
		t.Run(name, func(t *testing.T) {
			r := NewReader(buf)
			if _, err := r.Uvarint(); !errors.Is(err, ErrShortBuffer) {
				t.Fatalf("err = %v, want ErrShortBuffer", err)
			}
		})
	}
}

// --- Frame round-trips and error paths ---

func TestFrameRoundTrip(t *testing.T) {
	payloads := [][]byte{
		{},                           // empty: 1-byte uvarint len
		[]byte("hello"),              // small
		bytes.Repeat([]byte{7}, 200), // crosses the 1→2 byte uvarint boundary (>127)
	}
	for _, p := range payloads {
		dst := make([]byte, len(p)+16)
		frame, err := EncodeFrame(dst, 42, p)
		if err != nil {
			t.Fatalf("EncodeFrame(len=%d): %v", len(p), err)
		}
		typ, payload, rest, err := ParseFrame(frame)
		if err != nil {
			t.Fatalf("ParseFrame(len=%d): %v", len(p), err)
		}
		if typ != 42 {
			t.Fatalf("type = %d, want 42", typ)
		}
		if !bytes.Equal(payload, p) {
			t.Fatalf("payload = %x, want %x", payload, p)
		}
		if len(rest) != 0 {
			t.Fatalf("rest = %x, want empty", rest)
		}
	}
}

func TestEncodeFrameHeaderLayout(t *testing.T) {
	// A short payload gets a 1-byte length, so the header is exactly
	// version|type|len = 3 bytes and the payload follows with no gap.
	p := []byte("abc")
	dst := make([]byte, 32)
	frame, err := EncodeFrame(dst, 9, p)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte{Version, 9, byte(len(p))}, p...)
	if !bytes.Equal(frame, want) {
		t.Fatalf("frame = %x, want %x", frame, want)
	}
}

func TestParseFrameRest(t *testing.T) {
	// Two frames concatenated in one buffer: ParseFrame peels the first and
	// returns the second as rest.
	buf := make([]byte, 64)
	f1, _ := EncodeFrame(buf, 1, []byte("aa"))
	f2, _ := EncodeFrame(buf[len(f1):], 2, []byte("bbbb"))
	stream := buf[:len(f1)+len(f2)]

	typ, payload, rest, err := ParseFrame(stream)
	if err != nil || typ != 1 || string(payload) != "aa" {
		t.Fatalf("first frame: typ=%d payload=%q err=%v", typ, payload, err)
	}
	typ, payload, rest, err = ParseFrame(rest)
	if err != nil || typ != 2 || string(payload) != "bbbb" {
		t.Fatalf("second frame: typ=%d payload=%q err=%v", typ, payload, err)
	}
	if len(rest) != 0 {
		t.Fatalf("trailing rest = %x, want empty", rest)
	}
}

func TestEncodeFrameErrors(t *testing.T) {
	t.Run("short-dst", func(t *testing.T) {
		dst := make([]byte, 3) // can't hold header+payload
		if _, err := EncodeFrame(dst, 1, []byte("hello")); !errors.Is(err, ErrShortBuffer) {
			t.Fatalf("err = %v, want ErrShortBuffer", err)
		}
	})
	t.Run("too-large", func(t *testing.T) {
		big := make([]byte, MaxFrameLen+1)
		dst := make([]byte, MaxFrameLen+16)
		if _, err := EncodeFrame(dst, 1, big); !errors.Is(err, ErrFrameTooLarge) {
			t.Fatalf("err = %v, want ErrFrameTooLarge", err)
		}
	})
}

func TestParseFrameErrors(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		if _, _, _, err := ParseFrame(nil); !errors.Is(err, ErrShortBuffer) {
			t.Fatalf("err = %v, want ErrShortBuffer", err)
		}
	})
	t.Run("bad-version", func(t *testing.T) {
		if _, _, _, err := ParseFrame([]byte{0xff, 0x01, 0x00}); !errors.Is(err, ErrBadVersion) {
			t.Fatalf("err = %v, want ErrBadVersion", err)
		}
	})
	t.Run("truncated-payload", func(t *testing.T) {
		// header says len=5 but only 2 payload bytes present
		if _, _, _, err := ParseFrame([]byte{Version, 1, 5, 0xaa, 0xbb}); !errors.Is(err, ErrShortBuffer) {
			t.Fatalf("err = %v, want ErrShortBuffer", err)
		}
	})
	t.Run("too-large", func(t *testing.T) {
		// declare a length past MaxFrameLen via a varint; payload absent
		var hdr [2 + binary.MaxVarintLen64]byte
		hdr[0] = Version
		hdr[1] = 1
		w := binary.PutUvarint(hdr[2:], uint64(MaxFrameLen)+1)
		if _, _, _, err := ParseFrame(hdr[:2+w]); !errors.Is(err, ErrFrameTooLarge) {
			t.Fatalf("err = %v, want ErrFrameTooLarge", err)
		}
	})
	t.Run("truncated-uvarint", func(t *testing.T) {
		if _, _, _, err := ParseFrame([]byte{Version, 1, 0x80}); !errors.Is(err, ErrShortBuffer) {
			t.Fatalf("err = %v, want ErrShortBuffer", err)
		}
	})
}

// TestFrameHeaderHelpers checks that PutFrameHeader + a payload placed at
// FrameHeaderLen produce exactly the frame ParseFrame reads back — the split-header
// path used for zero-copy in-place message encoding. Sizes straddle the uvarint
// width boundary (1-byte length below 128, 2-byte at/above).
func TestFrameHeaderHelpers(t *testing.T) {
	for _, plen := range []int{0, 1, 127, 128, 300} {
		payload := bytes.Repeat([]byte{0xab}, plen)
		hdr := FrameHeaderLen(plen)
		dst := make([]byte, hdr+plen)
		if got := PutFrameHeader(dst, 9, plen); got != hdr {
			t.Fatalf("plen %d: PutFrameHeader = %d, want FrameHeaderLen %d", plen, got, hdr)
		}
		copy(dst[hdr:], payload)

		typ, got, rest, err := ParseFrame(dst)
		if err != nil {
			t.Fatalf("plen %d: ParseFrame: %v", plen, err)
		}
		if typ != 9 {
			t.Errorf("plen %d: type = %d, want 9", plen, typ)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("plen %d: payload mismatch", plen)
		}
		if len(rest) != 0 {
			t.Errorf("plen %d: rest = %d bytes, want 0", plen, len(rest))
		}
	}
}
