package routing

import (
	"crypto/ed25519"
	"time"

	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/transport"
)

// Capability is a bitfield of the roles a peer advertises about itself. A
// bitfield (not a slice or map) keeps a Contact flat and copy-cheap and tests a
// capability with one AND. These are level-3 self-reported hints (honor system):
// nothing security-critical may rest on a peer's claimed capability — admission
// PoW and signature checks are the load-bearing gates, not this.
type Capability uint32

const (
	// CanRelay marks a volunteer willing to relay packets (TURN-style) for peers
	// that cannot hole-punch.
	CanRelay Capability = 1 << iota
	// PublicAnchor marks a peer with a stable, directly-dialable address — an
	// "entry point" usable as a re-dial anchor in the connectivity floor.
	PublicAnchor
)

// Has reports whether c advertises every capability in f.
func (c Capability) Has(f Capability) bool { return c&f == f }

// Contact is one entry of the knowledge table: everything learned about a peer
// short of a live edge. The caller fills the exported fields; the table derives
// and owns subnet and lastSeen. It is a value type — Closest copies it into the
// caller's buffer — so it carries no pointer that must outlive the table; the
// Addrs slice header is copied, never its backing array.
//
// EdPub and XPub are stored as raw [32]byte arrays rather than the slice types
// crypto/ed25519 and crypto/ecdh use, so a Contact stays a flat value and Closest
// allocates nothing. Convert to ed25519.PublicKey only at verify time via
// EdPublic — off the hot path. Both are zero until learned: a NodeID can be known
// (e.g. as a routing hint) before its keys arrive.
type Contact struct {
	ID    kad.ID   // the peer's NodeID = BLAKE2b(ed_pub); the table key
	EdPub [32]byte // Ed25519 public key, zero until learned
	// XPub is the static X25519 public key (sealed-box), zero until learned. Unlike
	// EdPub it is not bound to the ID by anything on the wire, so the table accepts it
	// only via Knowledge.BindXPub from an authenticated channel — Observe ignores it.
	XPub  [32]byte
	Caps  Capability       // advertised roles (level-3 hint)
	Addrs []transport.Addr // where to reach the peer; the first IP-bearing one sets the subnet

	subnet    Subnet    // derived once on admission via the table's SubnetFunc
	hasSubnet bool      // whether subnet is meaningful (false for non-IP addresses)
	lastSeen  time.Time // refreshed by Observe; read by eviction and refresh
}

// EdPublic returns the contact's Ed25519 public key as the standard library type,
// for signature verification and the DeriveID(ed_pub) == ID check. It allocates,
// so it is for the verify path, not the routing hot path.
func (c Contact) EdPublic() ed25519.PublicKey {
	p := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(p, c.EdPub[:])
	return p
}

// LastSeen reports when the contact was last refreshed by a successful
// interaction, or the zero time if it has not been observed since admission.
func (c Contact) LastSeen() time.Time { return c.lastSeen }

// bindsID reports whether the contact self-certifies: its Ed25519 key, if present, must
// hash to its claimed NodeID (NodeID = BLAKE2b(ed_pub)). This is the DeriveID(ed_pub) ==
// ID check EdPublic refers to, and what makes the admission-PoW gate meaningful — without
// it a peer could pair an arbitrary or a victim's ID with an unrelated key. A keyless
// contact (EdPub still zero) trivially binds: it is an ID-only routing hint whose key is
// learned, and bound, later.
func (c Contact) bindsID() bool {
	return c.EdPub == [32]byte{} || identity.DeriveID(c.EdPub[:]) == c.ID
}
