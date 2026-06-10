package quic

import (
	"bufio"
	"encoding/binary"
	"errors"

	"github.com/udisondev/nodenet/transport"
)

// Frames travel the single bidirectional stream of an edge as uvarint(len) |
// payload, repeated. The length is clamped to transport.MaxPacketLen on read: a
// peer cannot declare a huge frame and make us allocate or block for it
// (level-2 self-protection). The write side lives inline in quicConn.Send so the
// hot path stays allocation-free; this file owns the read/parse side — the one
// decoder of untrusted input, which is what the fuzzer exercises.

// errFrameTooLarge means a frame's declared length exceeds MaxPacketLen.
var errFrameTooLarge = errors.New("quic: frame exceeds MaxPacketLen")

// readFrameLen reads a uvarint length prefix from br and validates it against
// MaxPacketLen. It consumes exactly the prefix bytes, leaving the payload for the
// caller to ReadFull. binary.ReadUvarint reads one byte at a time, which is why
// the caller wraps the stream in a bufio.Reader.
func readFrameLen(br *bufio.Reader) (int, error) {
	n, err := binary.ReadUvarint(br)
	if err != nil {
		return 0, err
	}
	if n > transport.MaxPacketLen {
		return 0, errFrameTooLarge
	}
	return int(n), nil
}
