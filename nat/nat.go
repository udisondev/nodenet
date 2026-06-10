// Package nat is the NAT-traversal layer: it gives a node behind NAT direct
// connectivity to peers instead of only outbound reachability to public ones, so
// that NAT nodes carry routing and forwarding like everyone else (the whole point
// of the overlay). It owns the pure logic and codecs; the I/O that actually opens
// holes and relays datagrams lives in the QUIC transport (it needs the shared
// socket), and the orchestration — routed signalling over the overlay, the
// Direct→Punch→Relay fallback — lives in the node, the same split routing uses.
//
// Three mechanisms, layered by cost:
//
//   - Reflexive learning: a node cannot see its own externally-visible address, so
//     it learns it from neighbours (each reports the address it saw a packet arrive
//     from). One report is not trusted; corroboration across distinct neighbours
//     confirms it (see Reflexive). Disagreement across neighbours is the signature
//     of a symmetric NAT, whose per-destination mapping defeats hole-punching.
//   - Hole-punching (DCUtR-style): two NAT peers, coordinated through any common
//     neighbour, fire packets at each other's reflexive address at once so both NAT
//     mappings open, then raise a QUIC connection over the direct path.
//   - Packet relay (last resort, for unpunchable pairs such as symmetric↔symmetric):
//     a volunteer forwards datagrams without terminating; the QUIC session stays
//     end-to-end, so the relay sees only ciphertext.
//
// Security levels (see the project's three-tier model): reflexive corroboration and
// the punch/relay choreography are level-3 policy — getting them wrong costs only
// the offender its own connectivity. The hard invariants stay where they already
// are: admission-PoW on every new edge (so a punched-in or relayed peer is no
// exception), per-IP rate limits, and session caps on a relay are level-2
// self-protection.
package nat

// Strategy is how a node attempts to reach a peer, tried cheapest first. The
// maintenance dialer and the rendezvous handoff pick a strategy per attempt and
// fall through to the next on failure.
type Strategy uint8

const (
	// Direct dials the peer's address straight — works for public peers and for
	// IPv6 without NAT.
	Direct Strategy = iota
	// Punch coordinates a simultaneous hole-punch through a common neighbour.
	Punch
	// Relay tunnels the QUIC session through a volunteer when a direct path cannot
	// be opened.
	Relay
)

// String renders the strategy for logs and diagnostics.
func (s Strategy) String() string {
	switch s {
	case Direct:
		return "direct"
	case Punch:
		return "punch"
	case Relay:
		return "relay"
	default:
		return "unknown"
	}
}
