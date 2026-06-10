package rendezvous

import "errors"

// Sentinel errors. They are matched with errors.Is by callers; the verification and
// decode paths return one of these instead of panicking on bad input. Decode-level
// framing errors (a truncated box/frame, a malformed address list) surface as the
// underlying codec's sentinels (wire.ErrShortBuffer, transport.ErrBadAddr) rather
// than being re-wrapped here.
var (
	// ErrBadSignature means an Ed25519 signature did not verify: a sealed box that
	// was tampered with or sealed to a different recipient, or a handshake whose
	// signature does not match the claimed key.
	ErrBadSignature = errors.New("rendezvous: bad signature")

	// ErrWrongTarget means a Reply's ed_pub does not hash to the NodeID the Hello was
	// addressed to (DeriveID(ed_pub) != target). This is the anti-MITM check: a
	// forwarder cannot answer in R's place because it cannot produce R's key.
	ErrWrongTarget = errors.New("rendezvous: reply key does not match target")

	// ErrNonceMismatch means a Reply's nonce does not equal the Hello's nonce, so it
	// is not the answer to this handshake (a stale or replayed reply).
	ErrNonceMismatch = errors.New("rendezvous: reply nonce mismatch")

	// ErrExpired means a sealed box's authenticated timestamp lies outside the freshness
	// window the recipient allows (too old, or too far in the future for clock skew). It
	// is the first sealed-box anti-replay guard: a captured box re-sent after the window
	// is rejected.
	ErrExpired = errors.New("rendezvous: sealed box outside freshness window")

	// ErrReplay means a sealed box was already opened within the freshness window — a
	// replay caught by a ReplayCache. The window bounds the horizon; the cache closes the
	// within-window gap so a box opens at most once.
	ErrReplay = errors.New("rendezvous: sealed box replayed")
)
