package node

import "sync/atomic"

// Stats is a snapshot of a node's defensive drop counters. It exists for observability:
// under attack these rates spike, so an operator (or a test) can see a flood being shed
// instead of guessing. The counters are monotonic since start.
type Stats struct {
	DroppedSubPoW      uint64 // frames from a peer/originator below the PoW threshold
	DroppedStale       uint64 // routed frames outside the freshness window (replayed/old)
	DroppedBadSig      uint64 // routed frames whose originator signature did not verify
	DroppedRateLimited uint64 // control/amplifier frames shed by a rate limiter
	DroppedInboundFull uint64 // conns refused (and closed) because the inbound-edge cap is reached
	DroppedEdgeRefused uint64 // edges (in or out) refused by the application's WithEdgeAdmission policy
	DroppedMalformed   uint64 // unparseable frames from an unregistered conn (the conn is closed)
	DroppedDupInbound  uint64 // duplicate inbound conns for an already-edged peer (the conn is closed)

	// Inbound media-session admission refusals (per-session drops live in the
	// session's own MediaStats; these count whole sessions this node refused).
	DroppedMediaSubPoW  uint64 // inbound media sessions from a sub-PoW identity
	DroppedMediaConsent uint64 // inbound media sessions the consent gate refused (nil gate refuses all)
	DroppedMediaCap     uint64 // inbound media sessions past the session caps (per node / per IP) or unconsumed
}

// counters holds the live atomic drop counters. Increments happen on the dispatch
// goroutine (and, for media admission, the media gate goroutine); Stats may be
// read from any goroutine, so the fields are atomic.
type counters struct {
	subPoW      atomic.Uint64
	stale       atomic.Uint64
	badSig      atomic.Uint64
	rateLimited atomic.Uint64
	inboundFull atomic.Uint64
	edgeRefused atomic.Uint64
	malformed   atomic.Uint64
	dupInbound  atomic.Uint64

	mediaSubPoW  atomic.Uint64
	mediaConsent atomic.Uint64
	mediaCap     atomic.Uint64
}

func (c *counters) snapshot() Stats {
	return Stats{
		DroppedSubPoW:      c.subPoW.Load(),
		DroppedStale:       c.stale.Load(),
		DroppedBadSig:      c.badSig.Load(),
		DroppedRateLimited: c.rateLimited.Load(),
		DroppedInboundFull: c.inboundFull.Load(),
		DroppedEdgeRefused: c.edgeRefused.Load(),
		DroppedMalformed:   c.malformed.Load(),
		DroppedDupInbound:  c.dupInbound.Load(),

		DroppedMediaSubPoW:  c.mediaSubPoW.Load(),
		DroppedMediaConsent: c.mediaConsent.Load(),
		DroppedMediaCap:     c.mediaCap.Load(),
	}
}
