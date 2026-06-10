package quic

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/udisondev/nodenet/transport"
)

// appendFrame appends uvarint(len(payload)) | payload to dst — the test-side encode
// counterpart of the production read path (readFrameLen + io.ReadFull). Send streams
// the same layout using a reused per-connection header scratch.
func appendFrame(dst, payload []byte) []byte {
	var hdr [binary.MaxVarintLen64]byte
	w := binary.PutUvarint(hdr[:], uint64(len(payload)))
	dst = append(dst, hdr[:w]...)
	return append(dst, payload...)
}

func TestFramingRoundTripStream(t *testing.T) {
	frames := [][]byte{
		{},
		[]byte("a"),
		[]byte("hello control frame"),
		bytes.Repeat([]byte{0xab}, 4096),
	}
	var buf []byte
	for _, f := range frames {
		buf = appendFrame(buf, f)
	}

	br := bufio.NewReader(bytes.NewReader(buf))
	for i, want := range frames {
		n, err := readFrameLen(br)
		if err != nil {
			t.Fatalf("frame %d: readFrameLen: %v", i, err)
		}
		if n != len(want) {
			t.Fatalf("frame %d: len = %d, want %d", i, n, len(want))
		}
		got := make([]byte, n)
		if _, err := io.ReadFull(br, got); err != nil {
			t.Fatalf("frame %d: read payload: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("frame %d: payload = %q, want %q", i, got, want)
		}
	}
}

// TestFramingTruncatedStream: a stream that ends mid-frame surfaces as an error from
// the production read pair — either readFrameLen (truncated prefix) or the ReadFull
// that follows it (truncated payload) — never as a silently short frame.
func TestFramingTruncatedStream(t *testing.T) {
	full := appendFrame(nil, []byte("payload"))

	// Truncated payload: the prefix parses, ReadFull must report the missing byte.
	br := bufio.NewReader(bytes.NewReader(full[:len(full)-1]))
	n, err := readFrameLen(br)
	if err != nil {
		t.Fatalf("readFrameLen: %v", err)
	}
	if _, err := io.ReadFull(br, make([]byte, n)); err != io.ErrUnexpectedEOF {
		t.Fatalf("ReadFull on truncated payload: err = %v, want io.ErrUnexpectedEOF", err)
	}

	// Empty stream: no prefix at all.
	br = bufio.NewReader(bytes.NewReader(nil))
	if _, err := readFrameLen(br); err != io.EOF {
		t.Fatalf("readFrameLen on empty stream: err = %v, want io.EOF", err)
	}
}

func TestReadFrameLenTooLarge(t *testing.T) {
	var hdr [binary.MaxVarintLen64]byte
	w := binary.PutUvarint(hdr[:], transport.MaxPacketLen+1)
	br := bufio.NewReader(bytes.NewReader(hdr[:w]))
	if _, err := readFrameLen(br); err != errFrameTooLarge {
		t.Fatalf("err = %v, want errFrameTooLarge", err)
	}
}
