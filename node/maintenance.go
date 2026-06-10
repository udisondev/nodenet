package node

import (
	"cmp"
	"time"

	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/routing"
	"github.com/udisondev/nodenet/transport"
)

// Maintenance is the upkeep policy for both tables: how often the node scans its
// edges, how long an idle edge waits before a keepalive and before being declared
// dead, how often it self-looks-up, exchanges sibling sets and refreshes a stale
// knowledge bucket, and how it backs off re-dialing a peer that will not answer
// (with the ladder's exhaustion doubling as the knowledge table's lazy-purge
// signal). All of it is level-3 local policy — a deployer tunes it freely without
// splitting the network. Differentiated timeouts (siblings tighter than fingers)
// trade a little traffic for faster detection on the correctness-critical edges,
// per the connectivity model. The loop that acts on this policy is
// Node.maintainLoop (in node.go).
type Maintenance struct {
	Tick             time.Duration // base scan cadence (fill + keepalive sweep)
	KeepaliveSibling time.Duration // idle time before pinging a sibling edge
	KeepaliveFinger  time.Duration // idle time before pinging a finger edge (looser)
	DeadSibling      time.Duration // idle time before reaping a sibling edge
	DeadFinger       time.Duration // idle time before reaping a finger edge
	SelfLookup       time.Duration // how often to self-lookup for sibling discovery
	SiblingExchange  time.Duration // how often to exchange sibling sets
	BucketRefresh    time.Duration // how often to check for a stale knowledge bucket to refresh
	BucketStaleAfter time.Duration // how long a populated bucket may go unrefreshed
	DialTimeout      time.Duration // per-dial deadline
	BackoffBase      time.Duration // first re-dial delay after a failed dial
	BackoffMax       time.Duration // ceiling on the exponential backoff
	Dialers          int           // concurrent dial workers
}

// Knowledge-upkeep policy knobs (level-3, like the rest of Maintenance).
const (
	// markDeadFails is the least number of consecutive failed dials before an
	// unreachable contact may be purged from the knowledge table. The purge also
	// requires the backoff ladder to have reached its ceiling (see bumpBackoff), so
	// a transient outage shorter than the ladder never costs a verified contact.
	markDeadFails = 3

	// probesPerTick caps how many eviction probes (dials of a full bucket's
	// least-recently-seen incumbent) one maintenance tick may launch, so probing
	// never crowds the dial workers out of connectivity-floor fills.
	probesPerTick = 2

	// maxProbes bounds the pending probe-candidate set; a candidate arriving past
	// the bound is dropped (the next observation of that bucket re-surfaces it).
	maxProbes = 16
)

// DefaultMaintenance is the production policy: keepalive in the 15–25 s band the
// connectivity model calls for (siblings tighter), reap at three missed keepalives,
// periodic self-lookup and sibling exchange, exponential re-dial backoff.
func DefaultMaintenance() Maintenance {
	return Maintenance{
		Tick:             5 * time.Second,
		KeepaliveSibling: 15 * time.Second,
		KeepaliveFinger:  25 * time.Second,
		DeadSibling:      45 * time.Second,
		DeadFinger:       75 * time.Second,
		SelfLookup:       60 * time.Second,
		SiblingExchange:  30 * time.Second,
		BucketRefresh:    60 * time.Second,
		BucketStaleAfter: 15 * time.Minute,
		DialTimeout:      10 * time.Second,
		BackoffBase:      1 * time.Second,
		BackoffMax:       5 * time.Minute,
		Dialers:          4,
	}
}

// withDefaults fills any zero field from DefaultMaintenance, so WithMaintenance can
// take a partially-specified policy.
func (m Maintenance) withDefaults() Maintenance {
	d := DefaultMaintenance()
	m.Tick = cmp.Or(m.Tick, d.Tick)
	m.KeepaliveSibling = cmp.Or(m.KeepaliveSibling, d.KeepaliveSibling)
	m.KeepaliveFinger = cmp.Or(m.KeepaliveFinger, d.KeepaliveFinger)
	m.DeadSibling = cmp.Or(m.DeadSibling, d.DeadSibling)
	m.DeadFinger = cmp.Or(m.DeadFinger, d.DeadFinger)
	m.SelfLookup = cmp.Or(m.SelfLookup, d.SelfLookup)
	m.SiblingExchange = cmp.Or(m.SiblingExchange, d.SiblingExchange)
	m.BucketRefresh = cmp.Or(m.BucketRefresh, d.BucketRefresh)
	m.BucketStaleAfter = cmp.Or(m.BucketStaleAfter, d.BucketStaleAfter)
	m.DialTimeout = cmp.Or(m.DialTimeout, d.DialTimeout)
	m.BackoffBase = cmp.Or(m.BackoffBase, d.BackoffBase)
	m.BackoffMax = cmp.Or(m.BackoffMax, d.BackoffMax)
	m.Dialers = cmp.Or(m.Dialers, d.Dialers)
	return m
}

// dialTask is a request to open an edge to a known contact; dialOutcome is the
// dialer's report back to the loop, which owns the edge table writes and backoff.
// caps is the contact's capabilities: the winner is registered with them, and the
// dialer derives its escalation ceiling (Direct → Punch → Relay) from them — a public
// anchor is dialed directly only, any other contact may fall through to a hole-punch
// and then a relay (see strategyForCaps; deriving at the dial site keeps caps the
// single source of truth). probe marks an eviction probe: the dial answers "is this
// full bucket's least-recently-seen incumbent still alive?" — its outcome resolves the
// table's pending replacement (Confirm) instead of registering an edge.
type dialTask struct {
	id    kad.ID
	addr  transport.Addr
	caps  routing.Capability
	probe bool
}

type dialOutcome struct {
	id    kad.ID
	conn  transport.Conn
	caps  routing.Capability
	probe bool
	err   error
}

// backoffState tracks the exponential re-dial delay for one peer that failed to
// dial, so a flapping or unreachable peer is not hammered, and counts the
// consecutive failures toward the lazy knowledge purge.
type backoffState struct {
	delay  time.Duration
	nextAt time.Time
	fails  int
}

// fillWant maps the floor band to how many edges to add per tick — gentle near the
// target, aggressive when the node risks isolation.
func fillWant(p routing.Phase) int {
	switch p {
	case routing.PhaseNeedsFill:
		return 2
	case routing.PhaseUrgent:
		return 4
	case routing.PhaseCritical, routing.PhaseBootstrap:
		return 8
	default: // PhaseNormal
		return 0
	}
}

// pruneBackoff drops backoff entries whose delay window elapsed more than BackoffMax ago
// without a re-dial: a still-tracked candidate would have been retried at nextAt (and its
// entry refreshed), so an entry left this far past its window belongs to a peer that has
// dropped out of the knowledge table and is no longer a fill candidate. Forgetting it
// keeps the map bounded under churn of permanently-dead contacts.
func pruneBackoff(backoff map[kad.ID]backoffState, now time.Time, m Maintenance) {
	for id, bs := range backoff {
		if now.After(bs.nextAt.Add(m.BackoffMax)) {
			delete(backoff, id)
		}
	}
}

// bumpBackoff doubles the re-dial delay for a peer (capped), so an unreachable or
// flapping peer is tried less and less often. It reports the ladder exhausted —
// the lazy-purge signal — when this failure found the peer already waiting at the
// BackoffMax ceiling AND it has failed at least markDeadFails times in a row: the
// peer got the whole exponential horizon to come back and did not, so it is dead
// for the table's purposes, while a transient outage shorter than the ladder never
// costs a contact.
func bumpBackoff(backoff map[kad.ID]backoffState, id kad.ID, m Maintenance, now time.Time) bool {
	bs := backoff[id]
	exhausted := bs.delay >= m.BackoffMax && bs.fails+1 >= markDeadFails
	if bs.delay == 0 {
		bs.delay = m.BackoffBase
	} else {
		bs.delay *= 2
	}
	if bs.delay > m.BackoffMax {
		bs.delay = m.BackoffMax
	}
	bs.fails++
	bs.nextAt = now.Add(bs.delay)
	backoff[id] = bs
	return exhausted
}
