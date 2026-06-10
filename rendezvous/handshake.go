package rendezvous

import (
	"crypto/ed25519"

	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/wire"
)

const (
	// TypeHello is the wire-frame type of a rendezvous Hello: A's signed request to
	// NodeID_R for R's keys and coordinates. It rides in the payload of a routing.Msg
	// (the node applies that envelope) and is forwarded greedily like any routed
	// message. rendezvous owns 8..9 in the wire.Type space (see the registry on
	// wire.Type).
	TypeHello wire.Type = 8

	// TypeReply is the wire-frame type of a rendezvous Reply: R's signed answer routed
	// back to NodeID_A, carrying R's {ed_pub, x_pub, coordinates} and echoing the
	// hello nonce.
	TypeReply wire.Type = 9

	// NonceLen is the per-handshake challenge length. The nonce binds a reply to its
	// hello: a reply that does not echo it is stale or replayed and is rejected.
	NonceLen = 16
)

// Hello is A's rendezvous request to R. A fills XPub (its static X25519 public key),
// Addrs (its reflexive coordinates — where R can later reach it directly), and a fresh
// Nonce, then signs with SignHello. The originator's Ed25519 public key is NOT carried
// here: it travels in the routing envelope (Msg.EdPub) and is what VerifyHello checks
// the signature against.
//
// On the wire (the routing.Msg payload):
//
//	x_pub(32) | addrs | nonce(16) | sig(64)
//
// where addrs is the canonical address-list encoding owned by transport
// (transport.AppendAddrs / transport.ParseAddrs).
type Hello struct {
	XPub  [32]byte
	Addrs []transport.Addr
	Nonce [NonceLen]byte
	Sig   [ed25519.SignatureSize]byte
}

// Reply is R's answer to a Hello, routed back to A. R fills EdPub (its Ed25519 public
// key — A checks DeriveID(EdPub) == NodeID_R, the anti-MITM check), XPub, Addrs, and
// echoes the hello Nonce, then signs with SignReply.
//
// On the wire (the routing.Msg payload):
//
//	ed_pub(32) | x_pub(32) | addrs | nonce(16) | sig(64)
type Reply struct {
	EdPub [32]byte
	XPub  [32]byte
	Addrs []transport.Addr
	Nonce [NonceLen]byte
	Sig   [ed25519.SignatureSize]byte
}

// SignHello signs h for delivery to target under id's Ed25519 key, filling h.Sig. The
// signature covers target so the hello is bound to its intended recipient (R verifies
// it was addressed to itself), plus h's content (x_pub, addrs, nonce).
func SignHello(id *identity.Identity, target kad.ID, h *Hello) {
	copy(h.Sig[:], id.Sign(helloSigMsg(target, h)))
}

// VerifyHello checks that h was signed by originEdPub (the originator key from the
// routing envelope) for delivery to target. It returns ErrBadSignature on mismatch.
// The PoW check on DeriveID(originEdPub) is the node's job (level-2 origination),
// done once on the routing envelope like every routed message.
func VerifyHello(target kad.ID, originEdPub [32]byte, h *Hello) error {
	if !ed25519.Verify(ed25519.PublicKey(originEdPub[:]), helloSigMsg(target, h), h.Sig[:]) {
		return ErrBadSignature
	}
	return nil
}

// SignReply fills r.EdPub from id and signs r under id's Ed25519 key, filling r.Sig.
// r.Nonce must already hold the nonce echoed from the hello.
func SignReply(id *identity.Identity, r *Reply) {
	copy(r.EdPub[:], id.EdPublic())
	copy(r.Sig[:], id.Sign(replySigMsg(r)))
}

// VerifyReply checks a reply against the handshake A initiated: target is NodeID_R (the
// ID A sent the hello to) and nonce is the hello nonce. It enforces, in order:
//
//   - DeriveID(r.EdPub) == target — the reply really comes from R; a forwarder on the
//     path cannot answer in R's place because it cannot produce R's key (ErrWrongTarget);
//   - r.Nonce == nonce — this is the answer to THIS hello, not a stale/replayed one
//     (ErrNonceMismatch);
//   - the Ed25519 signature verifies under r.EdPub (ErrBadSignature).
func VerifyReply(target kad.ID, nonce [NonceLen]byte, r *Reply) error {
	if identity.DeriveID(ed25519.PublicKey(r.EdPub[:])) != target {
		return ErrWrongTarget
	}
	if r.Nonce != nonce {
		return ErrNonceMismatch
	}
	if !ed25519.Verify(ed25519.PublicKey(r.EdPub[:]), replySigMsg(r), r.Sig[:]) {
		return ErrBadSignature
	}
	return nil
}

// MarshalHello encodes h into a fresh buffer to carry as a routing.Msg payload. This
// is control-plane content, not a hot path, so it allocates.
func MarshalHello(h *Hello) ([]byte, error) {
	buf := make([]byte, helloLen(h))
	n, err := EncodeHello(buf, h)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// MarshalReply encodes r into a fresh buffer to carry as a routing.Msg payload.
func MarshalReply(r *Reply) ([]byte, error) {
	buf := make([]byte, replyLen(r))
	n, err := EncodeReply(buf, r)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// EncodeHello writes h into dst in place and returns the bytes written. It does not
// grow dst (a dst shorter than the encoding is wire.ErrShortBuffer; an encoding past
// wire.MaxFrameLen is wire.ErrFrameTooLarge): the appends below stay within dst's
// checked length, so they never reallocate.
func EncodeHello(dst []byte, h *Hello) (int, error) {
	n := helloLen(h)
	if n > wire.MaxFrameLen {
		return 0, wire.ErrFrameTooLarge
	}
	if len(dst) < n {
		return 0, wire.ErrShortBuffer
	}
	b := append(dst[:0], h.XPub[:]...)
	b = transport.AppendAddrs(b, h.Addrs)
	b = append(b, h.Nonce[:]...)
	b = append(b, h.Sig[:]...)
	return len(b), nil
}

// EncodeReply writes r into dst in place and returns the bytes written.
func EncodeReply(dst []byte, r *Reply) (int, error) {
	n := replyLen(r)
	if n > wire.MaxFrameLen {
		return 0, wire.ErrFrameTooLarge
	}
	if len(dst) < n {
		return 0, wire.ErrShortBuffer
	}
	b := append(dst[:0], r.EdPub[:]...)
	b = append(b, r.XPub[:]...)
	b = transport.AppendAddrs(b, r.Addrs)
	b = append(b, r.Nonce[:]...)
	b = append(b, r.Sig[:]...)
	return len(b), nil
}

// DecodeHello parses a Hello from b (a routing.Msg payload). The returned Hello owns
// its address strings, so it outlives b. It is defensive against untrusted input: the
// address count is bounded before allocating (inside transport.ParseAddrs), it never
// panics on malformed bytes, and it enforces the canonical wire form — b must end
// exactly where the message does, so b and b||junk never decode to the same Hello
// (the same rule routing.DecodeMsg applies).
func DecodeHello(b []byte) (Hello, error) {
	var h Hello
	if len(b) < len(h.XPub) {
		return h, wire.ErrShortBuffer
	}
	copy(h.XPub[:], b)
	addrs, n, err := transport.ParseAddrs(b[len(h.XPub):])
	if err != nil {
		return h, err
	}
	h.Addrs = addrs
	tail := b[len(h.XPub)+n:]
	if len(tail) != NonceLen+len(h.Sig) {
		return h, wire.ErrShortBuffer
	}
	copy(h.Nonce[:], tail)
	copy(h.Sig[:], tail[NonceLen:])
	return h, nil
}

// DecodeReply parses a Reply from b. The returned Reply owns its address strings. Like
// DecodeHello it is defensive against untrusted input and rejects a payload that does
// not end exactly where the message does.
func DecodeReply(b []byte) (Reply, error) {
	var rep Reply
	const pubsLen = len(rep.EdPub) + len(rep.XPub)
	if len(b) < pubsLen {
		return rep, wire.ErrShortBuffer
	}
	copy(rep.EdPub[:], b)
	copy(rep.XPub[:], b[len(rep.EdPub):])
	addrs, n, err := transport.ParseAddrs(b[pubsLen:])
	if err != nil {
		return rep, err
	}
	rep.Addrs = addrs
	tail := b[pubsLen+n:]
	if len(tail) != NonceLen+len(rep.Sig) {
		return rep, wire.ErrShortBuffer
	}
	copy(rep.Nonce[:], tail)
	copy(rep.Sig[:], tail[NonceLen:])
	return rep, nil
}

func helloLen(h *Hello) int {
	return len(h.XPub) + transport.AddrsWireLen(h.Addrs) + NonceLen + len(h.Sig)
}

func replyLen(r *Reply) int {
	return len(r.EdPub) + len(r.XPub) + transport.AddrsWireLen(r.Addrs) + NonceLen + len(r.Sig)
}

// Domain-separation labels prefixed into the signed message so a signature made for one
// purpose can never be replayed as another, even though all of them use the same identity
// Ed25519 key. They are level-1 protocol constants.
const (
	domainHello = "nodenet/v1/rendezvous-hello"
	domainReply = "nodenet/v1/rendezvous-reply"
)

// helloSigMsg / replySigMsg build the byte string that is signed and verified. They
// allocate (control plane): a stable, canonical serialization of the signed fields,
// prefixed with a domain-separation label.
func helloSigMsg(target kad.ID, h *Hello) []byte {
	m := make([]byte, 0, len(domainHello)+kad.IDLen+len(h.XPub)+transport.AddrsWireLen(h.Addrs)+NonceLen)
	m = append(m, domainHello...)
	m = append(m, target[:]...)
	m = append(m, h.XPub[:]...)
	m = transport.AppendAddrs(m, h.Addrs)
	m = append(m, h.Nonce[:]...)
	return m
}

func replySigMsg(r *Reply) []byte {
	m := make([]byte, 0, len(domainReply)+len(r.EdPub)+len(r.XPub)+transport.AddrsWireLen(r.Addrs)+NonceLen)
	m = append(m, domainReply...)
	m = append(m, r.EdPub[:]...)
	m = append(m, r.XPub[:]...)
	m = transport.AppendAddrs(m, r.Addrs)
	m = append(m, r.Nonce[:]...)
	return m
}
