package node

import (
	"net/netip"
	"time"

	"github.com/udisondev/nodenet/nat"
	"github.com/udisondev/nodenet/routing"
	"github.com/udisondev/nodenet/transport"
)

// plausibleReflexive reports whether addr is a believable externally-visible address for
// this node — a routable unicast IP. A neighbour's pong claims "I saw you at addr"; a
// hostile one could claim a loopback, multicast, broadcast, unspecified or link-local
// address to steer this node's coords/hole-punching at a bad target, so those are
// rejected. ipOnly marks a transport whose endpoints are real IP host:port pairs
// (transport.IPAddressed): there an endpoint that does not even parse is the same
// hostile garbage and is rejected fail-closed — fail-open would let colluding reporters
// confirm junk that bypasses the filter entirely. Only a non-IP transport (the
// in-memory hub), whose endpoints carry no IP to judge, passes unparsable ones; it has
// no reflexive semantics anyway. Level-2 self-protection.
func plausibleReflexive(addr transport.Addr, ipOnly bool) bool {
	ap, err := netip.ParseAddrPort(addr.Endpoint)
	if err != nil {
		return !ipOnly
	}
	ip := ap.Addr()
	return ip.IsGlobalUnicast() && !ip.IsLinkLocalUnicast()
}

// Hole-punch timing. The initiator and responder both fire a short burst of punch
// datagrams to open their NAT mappings before (and during) the QUIC handshake; the
// handshake's own retransmission absorbs the rest of the timing slack, so no tight
// SYNC round is needed. These are level-3 policy.
const (
	punchBurst   = 5
	punchSpacing = 50 * time.Millisecond

	// maxPunchCandidates caps how many distinct addresses one punch attempt — or one
	// concurrent-dial fan-out (dialAnyRaw) — spreads over. A peer advertises only a
	// handful of real candidates (a local and a reflexive address, maybe per family),
	// so this bounds how much a single Connect/ConnectAck/RelayBind can make this node
	// emit — defence in depth alongside the per-originator rate limit and the global
	// punchSem. Level-2 self-protection.
	maxPunchCandidates = 8

	// directDialTimeout bounds the optimistic direct dial in Connect: long enough for a
	// public peer's handshake, short enough that a NAT peer (which will not answer a
	// direct dial) falls through to the hole-punch quickly.
	directDialTimeout = 500 * time.Millisecond

	// punchTimeout and relayTimeout bound the punch and relay stages of the maintenance
	// dial cascade so a dial worker is not tied up indefinitely waiting on an overlay
	// round-trip that never answers. Each covers a routed signalling exchange plus the
	// punched/relayed handshake. Level-3 policy.
	punchTimeout = 5 * time.Second
	relayTimeout = 5 * time.Second
)

// strategyForCaps caps how far the maintenance dialer may escalate for a contact: a
// public anchor is directly dialable, so there is nothing to punch or relay; any other
// contact may be behind NAT, so the dialer is allowed the full Direct → Punch → Relay
// cascade.
func strategyForCaps(caps routing.Capability) nat.Strategy {
	if caps.Has(routing.PublicAnchor) {
		return nat.Direct
	}
	return nat.Relay
}

// punchCandidates deduplicates addrs and caps the result at maxPunchCandidates, so a
// Connect/ConnectAck/RelayBind carrying many (or repeated) addresses cannot make this
// node fan a punch burst — or a concurrent dial — out to an unbounded set, bounding the
// reflector surface. It never modifies the input; when there is more than one
// address it returns a fresh slice.
func punchCandidates(addrs []transport.Addr) []transport.Addr {
	if len(addrs) <= 1 {
		return addrs
	}
	seen := make(map[transport.Addr]struct{}, len(addrs))
	out := make([]transport.Addr, 0, min(len(addrs), maxPunchCandidates))
	for _, a := range addrs {
		if _, dup := seen[a]; dup {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
		if len(out) >= maxPunchCandidates {
			break
		}
	}
	return out
}
