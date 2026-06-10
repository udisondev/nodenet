package routing

import "github.com/udisondev/nodenet/kad"

// Kind is the outcome of a forwarding Decision.
type Kind uint8

const (
	// KindDrop: the packet goes no further — TTL exhausted, or a local optimum
	// that is not the target (a dead end greedy cannot escape; disjoint paths and
	// local repair are the network-level mitigations).
	KindDrop Kind = iota
	// KindDeliver: this node is the target; hand the payload up.
	KindDeliver
	// KindForward: send the frame on to NextHops, decremented to OutTTL.
	KindForward
)

// Decision is the pure result of greedy routing for one received message: what to
// do and, when forwarding, the ordered next-hop candidates and the TTL to stamp.
// NextHops ALIASES the caller's buf — it is valid until the next Decide on that buf.
type Decision struct {
	Kind   Kind
	OutTTL uint8
	// NextHops are the live edges strictly closer to the target than self, closest
	// first. The forwarder sends to the first; the rest are local-repair fallbacks
	// (try the next on a failed Send).
	NextHops []LiveEdge
}

// Decide is greedy routing as a pure function: given this node (self), a received
// message m, and the live-edge set e, it decides deliver / forward / drop. It does
// no I/O and touches no buffer — the dispatcher above checks origination-PoW and
// frame format, sends, and patches the TTL; Decide only answers "where next".
//
// It requests up to cap(buf) next-hop candidates from e and reuses buf for the
// result, so with a pre-sized buf it allocates nothing (the hot path runs it on
// every forwarded packet). Pass a buf with cap ≥ the desired number of local-repair
// fallbacks.
//
// The rules, in order:
//   - target == self → deliver (exact match is delivery; routing to an ID IS
//     reaching it).
//   - clamp TTL to MaxHops (level-2 self-protection), then a zero budget drops.
//   - among the live edges nearest the target, keep those NOT in the avoid-set and
//     strictly closer to the target than self (canonical greedy progress).
//   - any survive → forward with TTL-1; none → drop (local optimum / dead end).
func Decide(self kad.ID, m *Msg, e *Edges, buf []LiveEdge) Decision {
	if m.Target == self {
		return Decision{Kind: KindDeliver}
	}

	ttl := min(m.TTL, MaxHops) // level-2: clamp a hostile or mis-set hop budget
	if ttl == 0 {
		return Decision{Kind: KindDrop}
	}

	cands := e.Closest(m.Target, cap(buf), buf)
	// Filter in place: cands and out share buf, and out never outruns the read
	// cursor, so this allocates nothing.
	out := cands[:0]
	for _, c := range cands {
		if m.Avoid.Has(c.ID) {
			continue
		}
		if kad.DistanceCmp(m.Target, c.ID, self) < 0 {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return Decision{Kind: KindDrop}
	}
	return Decision{Kind: KindForward, OutTTL: ttl - 1, NextHops: out}
}
