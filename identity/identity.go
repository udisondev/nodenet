// Package identity holds the cryptographic identity of a nodenet node: a single
// random master-seed from which everything else is derived deterministically.
//
// From the 32-byte master-seed, HKDF with domain-separation labels expands two
// INDEPENDENT keypairs:
//
//   - Ed25519 — the long-lived signing identity ("who the node is"). It signs
//     the one-time TLS cert key, every routed message at origination, and the
//     rendezvous handshake and sealed-box bindings.
//   - static X25519 — the key-exchange key for the end-to-end layer (sealed-box).
//     It is never used by the transport's TLS (which runs its own ephemeral
//     ECDHE); keeping it separate is clean crypto hygiene — zero key reuse across
//     algorithms, one secret to back up, and the KEX key can rotate without
//     touching the identity.
//
// The node identifier is NodeID = BLAKE2b-256(ed_pub), the full 256-bit value
// that lives in kad as kad.ID. Hashing the key (rather than using it raw) gives
// the proof-of-work gate its target (pow counts the NodeID's leading zero bits)
// and hides the public key until first contact; the cost is that on seeing a
// NodeID you cannot verify signatures until you receive ed_pub and check
// DeriveID(ed_pub) == NodeID.
//
// This package is PURE crypto: it never touches the filesystem. Only the
// master-seed is the secret of record — persist it elsewhere (a node-layer
// seed-store, file 0600, ideally passphrase-encrypted); keys are recomputed from
// the seed at start. Inject the randomness source (New takes an io.Reader) so
// tests are deterministic.
//
// In the dependency DAG identity sits just above the kad leaf (identity -> kad).
package identity

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/udisondev/nodenet/kad"
	"golang.org/x/crypto/blake2b"
)

// SeedLen is the master-seed length in bytes. It is also the size of the Ed25519
// seed and the X25519 scalar that HKDF expands from it.
const SeedLen = 32

// Domain-separation labels for HKDF-Expand. They are level-1 protocol constants:
// changing a label re-derives a different keypair from the same seed, i.e. it
// changes the node's identity. Versioned so a future scheme can coexist.
const (
	labelEd25519 = "nodenet/v1/identity-ed25519"
	labelX25519  = "nodenet/v1/kex-x25519"
)

// Identity is a node's derived key material. The public parts (ed_pub, the
// X25519 public key, the NodeID) are computed once in the constructor and cached,
// so ID, EdPublic and KEXPublic never re-hash or re-derive.
type Identity struct {
	seed   [SeedLen]byte      // master-seed: the secret of record (for backup/persist)
	signer ed25519.PrivateKey // Ed25519 private (signing)
	edPub  ed25519.PublicKey  // Ed25519 public (DeriveID, peer verification)
	kex    *ecdh.PrivateKey   // static X25519 (e2e KEX)
	id     kad.ID             // BLAKE2b-256(edPub), computed once
}

// New reads a fresh SeedLen-byte master-seed from rand and derives the identity.
// Pass crypto/rand.Reader in production; pass a fixed reader in tests for
// determinism. It returns an error only if rand cannot supply SeedLen bytes.
func New(rand io.Reader) (*Identity, error) {
	var seed [SeedLen]byte
	if _, err := io.ReadFull(rand, seed[:]); err != nil {
		return nil, fmt.Errorf("identity: read master-seed: %w", err)
	}
	return FromSeed(seed), nil
}

// FromSeed derives the identity deterministically from a master-seed. The same
// seed always yields the same keys and NodeID — this is how a node restores its
// identity at start from the persisted seed.
//
// It does not return an error: HKDF over a fixed-length seed and the key
// constructors below cannot fail for SeedLen-byte inputs, so a failure here would
// be a programmer/runtime invariant violation, surfaced as a panic.
func FromSeed(seed [SeedLen]byte) *Identity {
	// One HKDF-Extract, then one Expand per key with a distinct label. The two
	// labels make the outputs independent: deriving the X25519 scalar reveals
	// nothing about the Ed25519 seed and vice versa.
	prk, err := hkdf.Extract(sha256.New, seed[:], nil)
	if err != nil {
		panic("identity: hkdf extract: " + err.Error())
	}
	edSeed, err := hkdf.Expand(sha256.New, prk, labelEd25519, ed25519.SeedSize)
	if err != nil {
		panic("identity: hkdf expand ed25519: " + err.Error())
	}
	xScalar, err := hkdf.Expand(sha256.New, prk, labelX25519, SeedLen)
	if err != nil {
		panic("identity: hkdf expand x25519: " + err.Error())
	}

	signer := ed25519.NewKeyFromSeed(edSeed)
	edPub := signer.Public().(ed25519.PublicKey)

	kex, err := ecdh.X25519().NewPrivateKey(xScalar)
	if err != nil {
		panic("identity: x25519 private key: " + err.Error())
	}

	return &Identity{
		seed:   seed,
		signer: signer,
		edPub:  edPub,
		kex:    kex,
		id:     DeriveID(edPub),
	}
}

// ID returns the node identifier, NodeID = BLAKE2b-256(ed_pub).
func (id *Identity) ID() kad.ID { return id.id }

// Sign returns the Ed25519 signature of msg under the identity key. Callers sign
// the one-time TLS cert key, the routing envelope at origination (once per
// message; the signature is verified at the terminal node, not per hop) and the
// rendezvous frames.
func (id *Identity) Sign(msg []byte) []byte { return ed25519.Sign(id.signer, msg) }

// EdPublic returns the Ed25519 public key. A peer needs it to verify signatures
// and to check DeriveID(ed_pub) == NodeID.
func (id *Identity) EdPublic() ed25519.PublicKey { return id.edPub }

// KEX returns the static X25519 private key for the end-to-end layer, used to
// compute the ECDH shared secret in sealed-box.
func (id *Identity) KEX() *ecdh.PrivateKey { return id.kex }

// KEXPublic returns the static X25519 public key (32 bytes) to advertise to peers
// for sealed-box e2e.
func (id *Identity) KEXPublic() [32]byte {
	var pub [32]byte
	copy(pub[:], id.kex.PublicKey().Bytes())
	return pub
}

// Seed returns a copy of the master-seed. It is the only secret that must be
// persisted (file I/O lives outside this package). Handle it as the node's
// identity forever: leaking it leaks the identity, losing it loses the identity.
func (id *Identity) Seed() [SeedLen]byte { return id.seed }

// DeriveID maps an Ed25519 public key to its NodeID = BLAKE2b-256(ed_pub). It is
// the canonical key->NodeID mapping: every layer that receives an ed_pub (TLS
// cert auth, routing contacts and message originators, rendezvous) checks
// DeriveID(ed_pub) against the claimed NodeID.
func DeriveID(edPub ed25519.PublicKey) kad.ID {
	return blake2b.Sum256(edPub)
}
