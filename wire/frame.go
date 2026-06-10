package wire

import "encoding/binary"

// EncodeFrame writes the envelope version|type|uvarint(len)|payload into dst in
// place and returns the slice of dst holding the finished frame. It does not
// grow dst: if dst is too small it returns ErrShortBuffer, and if payload is
// longer than MaxFrameLen it returns ErrFrameTooLarge.
//
// Because the payload length is known up front, the header width is computed
// directly (no reserve-and-patch needed) and the payload is laid down right
// after it — a single copy into the caller's buffer, no second allocation. (The
// reserve-then-right-align trick is only needed for a streaming writer that
// frames a body before its length is known; we don't need it here.)
func EncodeFrame(dst []byte, t Type, payload []byte) ([]byte, error) {
	n := len(payload)
	if n > MaxFrameLen {
		return nil, ErrFrameTooLarge
	}
	hdr := FrameHeaderLen(n)
	if len(dst) < hdr+n {
		return nil, ErrShortBuffer
	}
	PutFrameHeader(dst, t, n) // safe: dst bounds already checked above
	copy(dst[hdr:], payload)
	return dst[:hdr+n], nil
}

// FrameHeaderLen reports the width of the envelope header (version | type |
// uvarint(len)) for a payload of payloadLen bytes. It lets a caller that knows the
// payload length up front place the payload directly at dst[FrameHeaderLen:] and
// then back-fill the header with PutFrameHeader — encoding a message into its final
// frame position in one pass, with no intermediate payload buffer or copy.
func FrameHeaderLen(payloadLen int) int {
	return 2 + UvarintLen(uint64(payloadLen))
}

// PutFrameHeader writes the envelope header version | type | uvarint(payloadLen) at
// the front of dst and returns its width (== FrameHeaderLen(payloadLen)). The caller
// is responsible for having placed payloadLen payload bytes at dst[width:] and for
// sizing dst (it does not bounds-check, like the Put* primitives — a too-small dst
// is a programmer error surfacing as an index panic). Use EncodeFrame instead when
// the payload is a ready slice to copy.
func PutFrameHeader(dst []byte, t Type, payloadLen int) int {
	dst[0] = Version
	dst[1] = byte(t)
	return 2 + binary.PutUvarint(dst[2:], uint64(payloadLen))
}

// ParseFrame decodes one frame from the front of b. It returns the frame type,
// the payload (a slice ALIASING b — copy it to retain it), and rest, the bytes
// in b after this frame (so several concatenated frames can be parsed in a
// loop). On any malformed input it returns a sentinel error and never panics.
func ParseFrame(b []byte) (t Type, payload, rest []byte, err error) {
	if len(b) < 2 {
		return 0, nil, nil, ErrShortBuffer
	}
	if b[0] != Version {
		return 0, nil, nil, ErrBadVersion
	}
	t = Type(b[1])

	n64, w := binary.Uvarint(b[2:])
	if w <= 0 {
		return 0, nil, nil, ErrShortBuffer
	}
	if n64 > MaxFrameLen {
		return 0, nil, nil, ErrFrameTooLarge
	}
	off := 2 + w
	end := off + int(n64)
	if end > len(b) {
		return 0, nil, nil, ErrShortBuffer
	}
	return t, b[off:end], b[end:], nil
}
