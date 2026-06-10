package rendezvous

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"time"

	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/wire"
	"golang.org/x/crypto/chacha20poly1305"
)

// tsLen is the width of the authenticated timestamp carried in a sealed box: an int64 of
// Unix nanoseconds, big-endian.
const tsLen = 8

// labelSealedBox is the HKDF-Expand domain-separation label for the sealed-box
// symmetric material. It is a level-1 protocol constant: changing it changes the
// key/nonce derived from the same ECDH secret, i.e. it is a different (incompatible)
// sealed-box scheme. Versioned so a future scheme can coexist.
const labelSealedBox = "nodenet/v1/sealed-box"

// ephPubLen is the X25519 public-key length carried in a sealed box.
const ephPubLen = 32

// Seal encrypts plaintext to the recipient identified by recipientXPub (its static
// X25519 public key) and authenticates it as coming from sender. The result is a
// self-contained box that forwarders carry as opaque overlay content: they see only
// ciphertext.
//
// The scheme is ephemeral-static ECDH + AEAD + a sender signature:
//
//  1. a fresh ephemeral X25519 keypair is drawn from rand;
//  2. shared = ECDH(ephemeral_priv, recipient_x_pub);
//  3. key||nonce = HKDF(shared) — fresh per box, so the derived nonce never repeats;
//  4. ct = ChaCha20-Poly1305(key, nonce).Seal(plaintext, aad);
//  5. sig = Ed25519 sign over (eph_pub || recipient_x_pub || timestamp || ct) under the
//     sender's identity key, binding the box to this ephemeral key, this recipient, and
//     the moment it was sealed.
//
// On the wire:
//
//	eph_pub(32) | sender_ed_pub(32) | timestamp(8) | uvarint(len ct) | ct | sig(64)
//
// The authenticated timestamp (now, as Unix nanoseconds) is the anti-replay guard: Open
// rejects a box whose timestamp lies outside the freshness window the recipient allows,
// so a captured box re-sent later is refused. aad is additional data authenticated by the
// AEAD tag but not encrypted (it may be nil). Pass crypto/rand.Reader and the real clock
// in production; a fixed reader and a fixed time make a box deterministic for tests/fuzz
// seeds. This is control-plane content, not a per-packet hot path, so it allocates the
// returned box freely.
//
// The PoW check on the sender's NodeID is deliberately NOT done here — it stays at
// the node layer, the same level-2 origination check every routed message gets.
func Seal(rand io.Reader, sender *identity.Identity, recipientXPub [32]byte, plaintext, aad []byte, now time.Time) ([]byte, error) {
	eph, err := ecdh.X25519().GenerateKey(rand)
	if err != nil {
		return nil, err
	}
	recipientPub, err := ecdh.X25519().NewPublicKey(recipientXPub[:])
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(recipientPub)
	if err != nil {
		return nil, err
	}
	key, nonce := sealKeyNonce(shared)

	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce[:], plaintext, aad)

	var ts [tsLen]byte
	binary.BigEndian.PutUint64(ts[:], uint64(now.UnixNano()))

	ephPub := eph.PublicKey().Bytes() // 32 bytes
	sig := sender.Sign(sealSigMsg(ephPub, recipientXPub[:], ts[:], ct))
	edPub := sender.EdPublic()

	box := make([]byte, 0, ephPubLen+ed25519.PublicKeySize+tsLen+wire.UvarintLen(uint64(len(ct)))+len(ct)+ed25519.SignatureSize)
	box = append(box, ephPub...)
	box = append(box, edPub...)
	box = append(box, ts[:]...)
	box = binary.AppendUvarint(box, uint64(len(ct)))
	box = append(box, ct...)
	box = append(box, sig...)
	return box, nil
}

// Open authenticates and decrypts a sealed box addressed to recipient. It returns the
// sender's NodeID (BLAKE2b(sender_ed_pub)) and the plaintext, or an error if the box
// is malformed, the signature does not verify, the box was sealed to a different
// recipient, or the AEAD tag is wrong. It is defensive against untrusted input: it
// parses with bounds checks and NEVER panics on arbitrary bytes.
//
// aad must match what Seal was given. now is the current time and maxAge the freshness
// window: Open rejects (ErrExpired) a box whose authenticated timestamp is older than
// maxAge or more than maxAge in the future (clock-skew tolerance), which is the
// anti-replay guard. The signature is verified before the ECDH and decryption so a
// forgery is rejected cheaply, and the freshness check runs on the authenticated
// timestamp (after the signature) so a tampered timestamp fails as a bad signature.
func Open(recipient *identity.Identity, box, aad []byte, now time.Time, maxAge time.Duration) (senderID kad.ID, plaintext []byte, err error) {
	r := wire.NewReader(box)

	ephPub, err := r.Bytes(ephPubLen)
	if err != nil {
		return senderID, nil, err
	}
	edPub, err := r.Bytes(ed25519.PublicKeySize)
	if err != nil {
		return senderID, nil, err
	}
	ts, err := r.Bytes(tsLen)
	if err != nil {
		return senderID, nil, err
	}
	ctLen, err := r.Uvarint()
	if err != nil {
		return senderID, nil, err
	}
	if ctLen > uint64(r.Remaining()) {
		return senderID, nil, wire.ErrShortBuffer
	}
	ct, err := r.Bytes(int(ctLen))
	if err != nil {
		return senderID, nil, err
	}
	sig, err := r.Bytes(ed25519.SignatureSize)
	if err != nil {
		return senderID, nil, err
	}
	// Enforce the canonical wire form: the signature is the last field, so a box with
	// trailing bytes is malformed — box and box||junk must not both open (the same rule
	// routing.DecodeMsg applies). Checked before the signature as the cheapest refusal.
	if r.Remaining() != 0 {
		return senderID, nil, wire.ErrShortBuffer
	}

	// Verify the sender signature against this recipient's static X25519 public key:
	// a box sealed to a different recipient signs over different bytes and fails here.
	recipientXPub := recipient.KEXPublic()
	if !ed25519.Verify(ed25519.PublicKey(edPub), sealSigMsg(ephPub, recipientXPub[:], ts, ct), sig) {
		return senderID, nil, ErrBadSignature
	}

	// Anti-replay: the timestamp is now authenticated, so enforce the freshness window.
	sealed := time.Unix(0, int64(binary.BigEndian.Uint64(ts)))
	if age := now.Sub(sealed); age > maxAge || age < -maxAge {
		return senderID, nil, ErrExpired
	}

	ephPubKey, err := ecdh.X25519().NewPublicKey(ephPub)
	if err != nil {
		return senderID, nil, err
	}
	shared, err := recipient.KEX().ECDH(ephPubKey)
	if err != nil {
		return senderID, nil, err
	}
	key, nonce := sealKeyNonce(shared)

	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return senderID, nil, err
	}
	pt, err := aead.Open(nil, nonce[:], ct, aad)
	if err != nil {
		return senderID, nil, err
	}
	return identity.DeriveID(ed25519.PublicKey(edPub)), pt, nil
}

// sealKeyNonce derives the ChaCha20-Poly1305 key and nonce from the ECDH shared
// secret: one HKDF-Extract then one Expand under labelSealedBox, mirroring the
// identity key-derivation pattern. Because the ephemeral key (and thus the shared
// secret) is fresh per box, the derived nonce is unique per box without a counter.
// HKDF over a fixed-length secret cannot fail, so a failure is an invariant violation
// surfaced as a panic.
func sealKeyNonce(shared []byte) (key [chacha20poly1305.KeySize]byte, nonce [chacha20poly1305.NonceSize]byte) {
	prk, err := hkdf.Extract(sha256.New, shared, nil)
	if err != nil {
		panic("rendezvous: hkdf extract: " + err.Error())
	}
	okm, err := hkdf.Expand(sha256.New, prk, labelSealedBox, chacha20poly1305.KeySize+chacha20poly1305.NonceSize)
	if err != nil {
		panic("rendezvous: hkdf expand: " + err.Error())
	}
	copy(key[:], okm[:chacha20poly1305.KeySize])
	copy(nonce[:], okm[chacha20poly1305.KeySize:])
	return key, nonce
}

// domainSealSig is the domain-separation label prefixed into the sealed-box signature so
// it can never be reused as a rendezvous or routing-envelope signature, all of which sign
// under the same identity key. Level-1 protocol constant. (Distinct from labelSealedBox,
// which separates the HKDF symmetric material, a different use.)
const domainSealSig = "nodenet/v1/sealed-box-sig"

// sealSigMsg builds the message the sender signs and the recipient verifies:
// domain || eph_pub || recipient_x_pub || timestamp || ct. Binding the ephemeral key and
// the recipient public key into the signature stops a box from being replayed against a
// different recipient or with a swapped ephemeral key; binding the timestamp makes the
// freshness window the recipient enforces tamper-proof; the domain label keeps the
// signature from being valid in any other context.
func sealSigMsg(ephPub, recipientXPub, ts, ct []byte) []byte {
	m := make([]byte, 0, len(domainSealSig)+len(ephPub)+len(recipientXPub)+len(ts)+len(ct))
	m = append(m, domainSealSig...)
	m = append(m, ephPub...)
	m = append(m, recipientXPub...)
	m = append(m, ts...)
	m = append(m, ct...)
	return m
}
