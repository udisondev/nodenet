package nat

import (
	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/wire"
)

const (
	// TypeConnect is the hole-punch request: the initiator routes it to the peer's
	// NodeID over the overlay (any common neighbour forwards it, like a rendezvous
	// Hello), carrying the initiator's candidate addresses. nat owns 10..14 in the
	// wire.Type space (see the registry on wire.Type).
	TypeConnect wire.Type = 10

	// TypeConnectAck is the peer's answer, routed back to the initiator, carrying the
	// peer's candidate addresses. It shares the Connect layout exactly.
	TypeConnectAck wire.Type = 11

	// NonceLen is the byte length of the request nonce that pairs a reply with its
	// request (a TypeConnectAck with its TypeConnect, a relay grant with its relay
	// request): a reply echoing a nonce the initiator is not waiting on is stale and
	// ignored.
	NonceLen = 16
)

// Connect carries the candidate addresses one side offers for a hole-punch, plus the
// nonce that pairs a TypeConnectAck with its TypeConnect. The addresses are hints
// only: they are not signed, because a forged hint costs at most a wasted punch — the
// QUIC edge that results is still mutual-TLS authenticated to the peer's NodeID, so a
// forwarder cannot redirect the connection to an impostor, only make it fail.
//
// On the wire (the routing.Msg payload):
//
//	nonce(16) | addrs
//
// where addrs is the canonical address-list encoding from transport
// (AppendAddrs/ParseAddrs).
type Connect struct {
	Nonce [NonceLen]byte
	Addrs []transport.Addr
}

// MarshalConnect encodes c into a fresh buffer to carry as a routing.Msg payload.
// This is control-plane content, not a hot path, so it allocates.
func MarshalConnect(c *Connect) ([]byte, error) {
	buf := make([]byte, connectLen(c))
	n, err := EncodeConnect(buf, c)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// EncodeConnect writes c into dst in place and returns the bytes written. It does not
// grow dst: a dst shorter than the encoding fails with wire.ErrShortBuffer, and an
// encoding exceeding wire.MaxFrameLen with wire.ErrFrameTooLarge.
func EncodeConnect(dst []byte, c *Connect) (int, error) {
	n := connectLen(c)
	if n > wire.MaxFrameLen {
		return 0, wire.ErrFrameTooLarge
	}
	if len(dst) < n {
		return 0, wire.ErrShortBuffer
	}
	off := copy(dst, c.Nonce[:])
	return len(transport.AppendAddrs(dst[:off], c.Addrs)), nil
}

// DecodeConnect parses a Connect from b (a routing.Msg payload). The returned Connect
// owns its address strings, so it outlives b. It is defensive against untrusted input
// (the address codec bounds the declared count before allocating and never panics on
// malformed bytes); trailing bytes after the address list are ignored.
func DecodeConnect(b []byte) (Connect, error) {
	var c Connect
	if len(b) < NonceLen {
		return c, wire.ErrShortBuffer
	}
	copy(c.Nonce[:], b[:NonceLen])
	addrs, _, err := transport.ParseAddrs(b[NonceLen:])
	if err != nil {
		return c, err
	}
	c.Addrs = addrs
	return c, nil
}

func connectLen(c *Connect) int { return NonceLen + transport.AddrsWireLen(c.Addrs) }
