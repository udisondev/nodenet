package quic

import (
	"bufio"
	"bytes"
	"io"
	"testing"

	"github.com/udisondev/nodenet/transport"
)

// FuzzReadFrame fuzzes the production framing decoder — readFrameLen + io.ReadFull,
// exactly the pair readLoop runs against peer-controlled bytes. It must never panic,
// never accept a frame longer than MaxPacketLen, and every accepted payload must
// survive a canonical encode/decode round-trip. The input is consumed as a stream of
// frames, mirroring how consecutive frames share one bufio.Reader in readLoop.
func FuzzReadFrame(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})                   // zero-length frame
	f.Add(appendFrame(nil, []byte("hi"))) // one valid frame
	f.Add(appendFrame(appendFrame(nil, nil), []byte{1, 2, 3}))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0x0f}) // large length prefix

	f.Fuzz(func(t *testing.T, b []byte) {
		br := bufio.NewReader(bytes.NewReader(b))
		for {
			n, err := readFrameLen(br)
			if err != nil {
				return // rejecting malformed/truncated/oversized input is fine
			}
			if n > transport.MaxPacketLen {
				t.Fatalf("accepted frame length %d > MaxPacketLen", n)
			}
			payload := make([]byte, n)
			if _, err := io.ReadFull(br, payload); err != nil {
				return // stream ended mid-frame: the read loop drops the edge
			}
			// Canonical round-trip: re-encoding the payload and reading it back must
			// reproduce exactly the payload. (A byte-for-byte match against the input
			// does NOT hold: binary.ReadUvarint accepts non-minimal length prefixes
			// that PutUvarint never emits.)
			rb := bufio.NewReader(bytes.NewReader(appendFrame(nil, payload)))
			m, err := readFrameLen(rb)
			if err != nil || m != n {
				t.Fatalf("re-read of re-encoded frame: len = %d, err = %v, want %d, nil", m, err, n)
			}
			back := make([]byte, m)
			if _, err := io.ReadFull(rb, back); err != nil || !bytes.Equal(back, payload) {
				t.Fatal("encode/decode round-trip is not stable")
			}
		}
	})
}
