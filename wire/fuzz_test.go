package wire

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// FuzzParseFrame asserts the decoder is robust against arbitrary bytes: it must
// never panic, and whenever it accepts a frame the result must be internally
// consistent and re-encode to the same frame.
func FuzzParseFrame(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{Version, 1, 0})             // empty payload
	f.Add([]byte{Version, 1, 5, 0xaa, 0xbb}) // truncated payload
	f.Add([]byte{0xff, 1, 0})                // bad version
	f.Add([]byte{Version, 1, 0x80})          // truncated uvarint
	if frame, err := EncodeFrame(make([]byte, 32), 7, []byte("hello")); err == nil {
		f.Add(frame) // a valid frame
	}

	f.Fuzz(func(t *testing.T, b []byte) {
		typ, payload, rest, err := ParseFrame(b)
		if err != nil {
			return // rejecting malformed input is fine; not panicking is the point
		}
		// On success the slices must be windows into b that account for it exactly.
		if len(payload) > MaxFrameLen {
			t.Fatalf("accepted payload len %d > MaxFrameLen", len(payload))
		}
		if len(payload)+len(rest) > len(b) {
			t.Fatalf("payload+rest (%d) exceeds input (%d)", len(payload)+len(rest), len(b))
		}
		// A parsed frame must re-encode and re-parse identically.
		dst := make([]byte, len(payload)+2+binary.MaxVarintLen64)
		re, err := EncodeFrame(dst, typ, payload)
		if err != nil {
			t.Fatalf("re-encode of accepted frame failed: %v", err)
		}
		typ2, payload2, rest2, err := ParseFrame(re)
		if err != nil || typ2 != typ || !bytes.Equal(payload2, payload) || len(rest2) != 0 {
			t.Fatalf("round-trip mismatch: typ %d→%d, err %v, rest %x", typ, typ2, err, rest2)
		}
	})
}

// FuzzEncodeFrameRoundTrip asserts that any (type, payload) within bounds encodes
// to a frame that parses back to the same type and payload with no leftover.
func FuzzEncodeFrameRoundTrip(f *testing.F) {
	f.Add(uint8(0), []byte(nil))
	f.Add(uint8(42), []byte("hello"))
	f.Add(uint8(255), bytes.Repeat([]byte{7}, 300)) // 2-byte uvarint length

	f.Fuzz(func(t *testing.T, typ uint8, payload []byte) {
		if len(payload) > MaxFrameLen {
			payload = payload[:MaxFrameLen]
		}
		dst := make([]byte, len(payload)+2+binary.MaxVarintLen64)
		frame, err := EncodeFrame(dst, Type(typ), payload)
		if err != nil {
			t.Fatalf("EncodeFrame: %v", err)
		}
		gotT, gotP, rest, err := ParseFrame(frame)
		if err != nil {
			t.Fatalf("ParseFrame: %v", err)
		}
		if gotT != Type(typ) {
			t.Fatalf("type = %d, want %d", gotT, typ)
		}
		if !bytes.Equal(gotP, payload) {
			t.Fatalf("payload = %x, want %x", gotP, payload)
		}
		if len(rest) != 0 {
			t.Fatalf("rest = %x, want empty", rest)
		}
	})
}

// FuzzReader drives the Reader with arbitrary bytes: no accessor may panic, and a
// failed read must leave the offset untouched (no partial advance).
func FuzzReader(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})
	f.Add([]byte{0x80, 0x80, 0x01})

	f.Fuzz(func(t *testing.T, b []byte) {
		r := NewReader(b)
		for i := 0; i < len(b)+8; i++ {
			before := r.Remaining()
			if before < 0 || before > len(b) {
				t.Fatalf("Remaining out of range: %d (len %d)", before, len(b))
			}
			var err error
			switch i % 4 {
			case 0:
				_, err = r.Uint32()
			case 1:
				_, err = r.Uvarint()
			case 2:
				_, err = r.ID()
			case 3:
				_, err = r.Bytes(3)
			}
			if err != nil && r.Remaining() != before {
				t.Fatalf("failed read advanced offset: %d → %d", before, r.Remaining())
			}
		}
	})
}
