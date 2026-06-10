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
}

// counters holds the live atomic drop counters. Increments happen on the dispatch
// goroutine; Stats may be read from any goroutine, so the fields are atomic.
type counters struct {
	subPoW      atomic.Uint64
	stale       atomic.Uint64
	badSig      atomic.Uint64
	rateLimited atomic.Uint64
	inboundFull atomic.Uint64
}

func (c *counters) snapshot() Stats {
	return Stats{
		DroppedSubPoW:      c.subPoW.Load(),
		DroppedStale:       c.stale.Load(),
		DroppedBadSig:      c.badSig.Load(),
		DroppedRateLimited: c.rateLimited.Load(),
		DroppedInboundFull: c.inboundFull.Load(),
	}
}
