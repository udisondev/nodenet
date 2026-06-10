package quic

import (
	"crypto/ed25519"
	"errors"
)

// peerExtLen is the fixed length of the identity-extension value: the Ed25519
// public key followed by its signature over the cert public key. A fixed layout
// (no ASN.1 inside the value) keeps the decoder a trivial bounds check and easy
// to fuzz.
const peerExtLen = ed25519.PublicKeySize + ed25519.SignatureSize // 32 + 64 = 96

// errBadExtension is returned when the identity extension value is malformed
// (wrong length). It is the only failure mode of decodePeerExt. It stays
// unexported, like the sibling tlsauth errors: it can only surface through the
// TLS handshake (where quic-go swallows it) and Dial's sentinel mapping, so no
// external errors.Is on it is possible.
var errBadExtension = errors.New("quic: malformed identity extension")

// peerExt is the decoded identity extension: an Ed25519 public key and the
// signature, made by that key's owner, over the certificate's public key. The
// signature is what proves the cert key was authorized by the identity key.
type peerExt struct {
	EdPub ed25519.PublicKey // 32 bytes
	Sig   []byte            // 64 bytes
}

// encodePeerExt serializes the extension as edPub(32) ‖ sig(64). It panics on
// wrong-sized inputs: callers pass identity.EdPublic() and identity.Sign(), both
// fixed-size, so a bad length here is a programmer error, not untrusted input.
func encodePeerExt(e peerExt) []byte {
	if len(e.EdPub) != ed25519.PublicKeySize || len(e.Sig) != ed25519.SignatureSize {
		panic("quic: encodePeerExt: wrong key/signature length")
	}
	out := make([]byte, peerExtLen)
	copy(out, e.EdPub)
	copy(out[ed25519.PublicKeySize:], e.Sig)
	return out
}

// decodePeerExt parses an identity-extension value. The input is untrusted (it
// comes off a peer's certificate), so it never panics: any malformed value yields
// errBadExtension. On success EdPub is 32 bytes and Sig is 64 bytes, both slices
// copied out of the input so they do not alias it.
func decodePeerExt(raw []byte) (peerExt, error) {
	if len(raw) != peerExtLen {
		return peerExt{}, errBadExtension
	}
	e := peerExt{
		EdPub: make(ed25519.PublicKey, ed25519.PublicKeySize),
		Sig:   make([]byte, ed25519.SignatureSize),
	}
	copy(e.EdPub, raw[:ed25519.PublicKeySize])
	copy(e.Sig, raw[ed25519.PublicKeySize:])
	return e, nil
}
