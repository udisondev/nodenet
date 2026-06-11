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
//
// A confirmed address is reported even when some OTHER address has more reporters: a
// larger single-subnet (e.g. sybil) cluster cannot veto a genuine diverse quorum.
func (r *Reflexive) Consensus() (transport.Addr, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	bestConf, bestConfN, _, _ := r.topLocked()
	if bestConfN < Quorum {
		return transport.Addr{}, false
	}
	return bestConf, true
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
	_, _, _, topN := r.topLocked()
	return topN < Quorum
}

// topLocked aggregates the reports by address in one pass and returns two winners: the
// best CONFIRMED address with its backing count, and the overall most-reported address
// with its count. An address is confirmed by Quorum neighbours AND — when subnet info is
// present — at least two distinct subnets among them, so a single-subnet sybil cluster
// cannot confirm a bogus address; with no subnet info (the in-memory transport) it falls
// back to the count alone. Consensus uses the confirmed winner, Symmetric the overall
// count. Caller holds r.mu.
//
// Tracking the confirmed winner separately is what stops a larger unconfirmed cluster
// from vetoing a genuine diverse quorum. Ties resolve deterministically — map iteration
// order must never pick the winner — by the lexicographically smaller address. The single
// pass is O(reports) rather than the old all-pairs O(reports²), which mattered as the
// report set grew toward its cap on a path the dispatch decisions hit.
func (r *Reflexive) topLocked() (bestConf transport.Addr, bestConfN int, top transport.Addr, topN int) {
	type agg struct {
		n          int
		withSubnet int
		firstSub   SubnetKey
		haveFirst  bool
		diverse    bool
	}
	byAddr := make(map[transport.Addr]*agg, len(r.reports))
	for _, e := range r.reports {
		a := byAddr[e.addr]
		if a == nil {
			a = &agg{}
			byAddr[e.addr] = a
		}
		a.n++
		if e.hasSubnet {
			a.withSubnet++
			if !a.haveFirst {
				a.firstSub, a.haveFirst = e.subnet, true
			} else if e.subnet != a.firstSub {
				a.diverse = true
			}
		}
	}

	haveConf, haveTop := false, false
	for addr, a := range byAddr {
		if a.n > topN || (a.n == topN && (!haveTop || addrLess(addr, top))) {
			top, topN, haveTop = addr, a.n, true
		}
		conf := a.n >= Quorum && (a.withSubnet == 0 || a.diverse)
		if conf && (!haveConf || a.n > bestConfN || (a.n == bestConfN && addrLess(addr, bestConf))) {
			bestConf, bestConfN, haveConf = addr, a.n, true
		}
	}
	return bestConf, bestConfN, top, topN
}

// addrLess is the fixed total order used for the final tie-break in topLocked:
// by Net, then by Endpoint.
func addrLess(a, b transport.Addr) bool {
	if a.Net != b.Net {
		return a.Net < b.Net
	}
	return a.Endpoint < b.Endpoint
}
