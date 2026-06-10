package nat

import (
	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/wire"
)

const (
	// TypeRelayRequest is sent by a peer (A) to a volunteer relay (R) over their live
	// edge, asking R to splice a tunnel to target. It carries a nonce that pairs the
	// grant with the request, and the target NodeID R must bind the far side to.
	TypeRelayRequest wire.Type = 12

	// TypeRelayGrant is R's answer to the requester A, over the same edge: the address
	// A should dial (R's allocation facing A), echoing the request nonce. A then raises
	// a normal QUIC connection to target through that address.
	TypeRelayGrant wire.Type = 13

	// TypeRelayBind tells the callee B (over R's edge to B) the address to register and
	// expect the relayed connection on — R's allocation facing B. B opens its NAT
	// mapping toward it and its listener accepts the inbound connection (authenticated
	// to the caller's NodeID, not to R).
	TypeRelayBind wire.Type = 14
)

// EncodeRelayRequestFrame writes a TypeRelayRequest frame (nonce | target) into dst.
func EncodeRelayRequestFrame(dst []byte, nonce [NonceLen]byte, target kad.ID) (int, error) {
	pl := NonceLen + kad.IDLen
	hdr, err := frameHeader(dst, TypeRelayRequest, pl)
	if err != nil {
		return 0, err
	}
	off := hdr
	off += copy(dst[off:], nonce[:])
	off += copy(dst[off:], target[:])
	return off, nil
}

// DecodeRelayRequest parses the nonce and target from a TypeRelayRequest payload.
func DecodeRelayRequest(b []byte) (nonce [NonceLen]byte, target kad.ID, err error) {
	r := wire.NewReader(b)
	np, err := r.Bytes(NonceLen)
	if err != nil {
		return nonce, target, err
	}
	copy(nonce[:], np)
	target, err = r.ID()
	return nonce, target, err
}

// EncodeRelayGrantFrame writes a TypeRelayGrant frame (nonce | addr) into dst.
func EncodeRelayGrantFrame(dst []byte, nonce [NonceLen]byte, addr transport.Addr) (int, error) {
	pl := NonceLen + transport.AddrWireLen(addr)
	hdr, err := frameHeader(dst, TypeRelayGrant, pl)
	if err != nil {
		return 0, err
	}
	off := hdr + copy(dst[hdr:], nonce[:])
	return len(transport.AppendAddr(dst[:off], addr)), nil
}

// DecodeRelayGrant parses the nonce and address from a TypeRelayGrant payload.
// Trailing bytes after the address are ignored.
func DecodeRelayGrant(b []byte) (nonce [NonceLen]byte, addr transport.Addr, err error) {
	if len(b) < NonceLen {
		return nonce, addr, wire.ErrShortBuffer
	}
	copy(nonce[:], b[:NonceLen])
	addr, _, err = transport.ParseAddr(b[NonceLen:])
	return nonce, addr, err
}

// EncodeRelayBindFrame writes a TypeRelayBind frame (addr) into dst.
func EncodeRelayBindFrame(dst []byte, addr transport.Addr) (int, error) {
	hdr, err := frameHeader(dst, TypeRelayBind, transport.AddrWireLen(addr))
	if err != nil {
		return 0, err
	}
	return len(transport.AppendAddr(dst[:hdr], addr)), nil
}

// DecodeRelayBind parses the address from a TypeRelayBind payload. Trailing bytes
// after the address are ignored.
func DecodeRelayBind(b []byte) (transport.Addr, error) {
	addr, _, err := transport.ParseAddr(b)
	return addr, err
}

// frameHeader writes a frame header of type t for a payload of pl bytes into dst and
// returns the header length, or an error if dst is too small or pl too large.
func frameHeader(dst []byte, t wire.Type, pl int) (int, error) {
	if pl > wire.MaxFrameLen {
		return 0, wire.ErrFrameTooLarge
	}
	hdr := wire.FrameHeaderLen(pl)
	if len(dst) < hdr+pl {
		return 0, wire.ErrShortBuffer
	}
	wire.PutFrameHeader(dst, t, pl)
	return hdr, nil
}
