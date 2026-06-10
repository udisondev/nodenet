package nat

import (
	"sync"

	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/transport"
)

// Quorum is how many distinct neighbours must report the same externally-visible
// address before it can be treated as this node's confirmed reflexive address. Two is
// too few — a pair of colluding (or sybil) neighbours could confirm a bogus address and
// steer this node's hole-punching at a victim — so the bar is three, and (see
// topLocked) those three must also span at least two failure domains.
const Quorum = 3

// maxReports bounds the per-neighbour reports the consolidator holds. Reports come from
// pongs over edges this node keeps, so the live count is naturally small; the cap is a
// level-2 self-protection backstop against unbounded growth if an eviction is ever
// missed. It sits comfortably above any realistic live-edge degree.
const maxReports = 1024

// SubnetKey is an opaque, comparable failure-domain key for a reporting neighbour — a
// masked IP prefix the node layer computes from the neighbour's address. The zero key
// paired with hasSubnet == false means "no subnet info" (e.g. the in-memory transport).
// It is a plain array so it costs nothing to store and key on, and it keeps this package
// free of the routing/subnet machinery.
type SubnetKey = [16]byte

// reportEntry is one neighbour's latest report: the address it saw this node at, plus
// its own failure-domain key, used to require corroboration across independent subnets.
type reportEntry struct {
	addr      transport.Addr
	subnet    SubnetKey
	hasSubnet bool
}

// Reflexive consolidates the externally-visible addresses neighbours report seeing
// this node at (carried in pongs) into a confirmed reflexive address. It keeps the
// latest report per neighbour and confirms an address once Quorum distinct neighbours,
// spanning at least two failure domains, agree on it. When neighbours instead disagree
// it flags a symmetric NAT — a per-destination mapping that makes any single predicted
// address useless for hole-punching, so the node must fall back to a relay.
//
// It is safe for concurrent use: the dispatch loop records reports while other
// goroutines (coords, the dialer) read the consensus.
type Reflexive struct {
	mu      sync.Mutex
	reports map[kad.ID]reportEntry // latest report per neighbour
}

// NewReflexive returns an empty consolidator.
func NewReflexive() *Reflexive {
	return &Reflexive{reports: make(map[kad.ID]reportEntry)}
}

// Record stores addr as the latest address reporter saw this node arrive from, along
// with reporter's failure-domain key (subnet/hasSubnet), replacing any earlier report
// from the same neighbour. A zero addr is ignored.
func (r *Reflexive) Record(reporter kad.ID, subnet SubnetKey, hasSubnet bool, addr transport.Addr) {
	if addr == (transport.Addr{}) {
		return
	}
	r.mu.Lock()
	// Bound the map: a new reporter beyond the cap is ignored (existing reporters can
	// still update in place). Reporters track live edges, so honest operation stays well
	// under the cap; this only fires under pathological growth.
	if _, known := r.reports[reporter]; known || len(r.reports) < maxReports {
		r.reports[reporter] = reportEntry{addr: addr, subnet: subnet, hasSubnet: hasSubnet}
	}
	r.mu.Unlock()
}

// Remove drops a neighbour's report — called when its edge dies, so a departed neighbour
// no longer corroborates a reflexive address or lingers as stale evidence. It is a no-op
// if the neighbour had no report.
func (r *Reflexive) Remove(reporter kad.ID) {
	r.mu.Lock()
	delete(r.reports, reporter)
	r.mu.Unlock()
}

// Consensus returns the confirmed reflexive address, if one is established: an address
// at least Quorum distinct neighbours — spanning ≥2 failure domains — agree on. Until
// then the second result is false and the address should be treated as unknown.
func (r *Reflexive) Consensus() (transport.Addr, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	addr, _, confirmed := r.topLocked()
	if !confirmed {
		return transport.Addr{}, false
	}
	return addr, true
}

// Symmetric reports whether the neighbours' reports point at a symmetric NAT: at least
// Quorum neighbours have weighed in but no single address is backed by Quorum of them,
// so the mapping is varying per destination. A node that is symmetric cannot be
// hole-punched and must use a relay. This is a count-based disagreement test,
// independent of the subnet-diversity gate (which only governs positive confirmation):
// a single-subnet agreement is not "symmetric", it is merely unconfirmed.
func (r *Reflexive) Symmetric() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.reports) < Quorum {
		return false
	}
	_, agree, _ := r.topLocked()
	return agree < Quorum
}

// topLocked returns the most-reported address, how many neighbours back it, and whether
// that backing confirms the address: Quorum neighbours AND — when subnet info is present
// — at least two distinct subnets among them, so a single-subnet sybil cluster cannot
// confirm a bogus address. When no backing reporter carries subnet info (the in-memory
// transport), it falls back to the count alone. Caller holds r.mu.
//
// Ties resolve deterministically — map iteration order must never pick the winner. At
// equal counts a confirmed address beats an unconfirmed one (so a single-subnet cluster
// cannot displace a diverse quorum by levelling the score), and an exact tie goes to the
// lexicographically smaller address.
func (r *Reflexive) topLocked() (best transport.Addr, agree int, confirmed bool) {
	// The report set is small (bounded by live-edge degree), so a nested scan is cheaper
	// than allocating a counting map on this rarely-hot path.
	for _, e := range r.reports {
		n := 0
		var firstSub SubnetKey
		haveFirst, diverse, withSubnet := false, false, 0
		for _, o := range r.reports {
			if o.addr != e.addr {
				continue
			}
			n++
			if o.hasSubnet {
				withSubnet++
				if !haveFirst {
					firstSub, haveFirst = o.subnet, true
				} else if o.subnet != firstSub {
					diverse = true
				}
			}
		}
		conf := n >= Quorum && (withSubnet == 0 || diverse)
		switch {
		case n < agree:
			continue
		case n == agree && conf == confirmed && !addrLess(e.addr, best):
			continue
		case n == agree && conf != confirmed && !conf:
			continue
		}
		best, agree, confirmed = e.addr, n, conf
	}
	return best, agree, confirmed
}

// addrLess is the fixed total order used for the final tie-break in topLocked:
// by Net, then by Endpoint.
func addrLess(a, b transport.Addr) bool {
	if a.Net != b.Net {
		return a.Net < b.Net
	}
	return a.Endpoint < b.Endpoint
}
