package routing

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/transport"
)

const (
	// FillHysteresis is the margin below TargetEdges within which a node already in
	// the Normal band stays there, so a single edge lost at the boundary does not
	// flap the maintenance loop between Normal and NeedsFill.
	FillHysteresis = 4

	// LiveSubnetCap is how many live edges a single subnet may hold before
	// ReplacementFor stops drawing more candidates from it, steering fills toward
	// independent failure domains. Level-3 diversification policy.
	LiveSubnetCap = 2

	// InboundCap bounds how many inbound (peer-initiated) live edges a node holds. A
	// node registers an inbound edge on first sight so it can route back over the
	// channel a peer opened — the mechanism that makes a NAT node a full router — but
	// an unbounded count would let peers flood the table, so admissions stop here.
	// Level-2 self-protection. Self-maintained (outgoing) edges are never capped by it.
	InboundCap = 256

	// ControlBurst / ControlRate bound how fast a single edge may make this node do
	// work in response to its control frames (answer a ping, build a sibling/lookup
	// response). Each edge has a token bucket of ControlBurst tokens refilling at
	// ControlRate per second; a control frame that finds the bucket empty is dropped
	// unanswered. Legitimate control is sparse (keepalive every tens of seconds,
	// periodic exchange), so this never bites honest peers but caps a flood that would
	// otherwise be a per-edge CPU/reflection amplifier. Level-2 self-protection.
	ControlBurst = 32
	ControlRate  = 16

	// ForwardBurst / ForwardRate bound how fast a single edge may make this node process
	// and forward routed frames (TypeRoute and the routed control envelopes). Each edge
	// has its own token bucket; a routed frame arriving over an edge whose bucket is empty
	// is dropped before Decide. Forwarding is bounded ~MaxHops× per origination with no
	// fan-out, and an honest transit edge carries far less than this, so the cap never
	// bites real traffic — it caps an edge spewing routed frames to exhaust this node's
	// decode/verify/forward work or to drive the unsolicited-learning path. Set well above
	// honest per-edge transit. Level-2 self-protection.
	ForwardBurst = 1024
	ForwardRate  = 512
)

// Sentinel errors from AddEdge.
var (
	// ErrEdgeExists means a live edge to that NodeID is already registered.
	ErrEdgeExists = errors.New("routing: edge already exists")
	// ErrSelfEdge means the edge's peer is this node itself.
	ErrSelfEdge = errors.New("routing: edge to self")
	// ErrInboundFull means the inbound-edge cap (InboundCap) is reached, so this
	// peer-initiated edge is refused. Outgoing edges are never refused for this.
	ErrInboundFull = errors.New("routing: inbound edge cap reached")
)

// Phase is the connectivity-floor band a node's self-maintained degree sits in.
// The maintenance loop reads it to decide how urgently to fill; the bands and
// their hysteresis are the accounting, not the action.
type Phase uint8

const (
	// PhaseBootstrap: no self-maintained edges at all — a full re-bootstrap.
	PhaseBootstrap Phase = iota
	// PhaseCritical: at or below the hard floor KMin — emergency fill that may
	// displace everything; the node risks isolation.
	PhaseCritical
	// PhaseUrgent: at or below the low-water mark — fill urgently.
	PhaseUrgent
	// PhaseNeedsFill: below target — fill opportunistically.
	PhaseNeedsFill
	// PhaseNormal: at or above target — lazy maintenance.
	PhaseNormal
)

// String names the band for logs and errors.
func (p Phase) String() string {
	switch p {
	case PhaseBootstrap:
		return "bootstrap"
	case PhaseCritical:
		return "critical"
	case PhaseUrgent:
		return "urgent"
	case PhaseNeedsFill:
		return "needs-fill"
	case PhaseNormal:
		return "normal"
	}
	return "unknown"
}

// FloorStatus is the connectivity-floor accounting: the band plus the raw
// self-maintained (outgoing) edge count it was computed from. Only outgoing edges
// count — a node behind NAT cannot rely on inbound edges it did not initiate.
type FloorStatus struct {
	Phase    Phase
	OutEdges int
}

// LiveEdge is a live edge handed to the forwarder: the peer's NodeID and the Conn
// to send on.
type LiveEdge struct {
	ID   kad.ID
	Conn transport.Conn
}

// edgeRole classifies a live edge by its place in the neighbour set.
type edgeRole uint8

const (
	roleFinger  edgeRole = iota // best-effort reach (the default)
	roleSibling                 // among the s closest to self; correctness-critical
)

// Edges is the active set of live transport.Conn the overlay forwards over. It
// classifies edges into siblings (the s closest to self) and fingers, accounts the
// connectivity floor and diversification, and selects replacement candidates from
// knowledge — but it performs no I/O and runs no loop: the maintenance loop reads
// its accounting and acts. Read-dominated, so an RWMutex guards it.
type Edges struct {
	self    kad.ID
	subnetf SubnetFunc
	mu      sync.RWMutex
	byID    map[kad.ID]*edge
	list    []*edge // same edges as byID, in a flat slice the read paths scan
	// buckets indexes the same edges by common-prefix length with self, so Closest
	// (the forward hot path) walks only the closeness tiers that can hold a next-hop
	// instead of scanning the whole set — the same CPL-tiered walk Knowledge uses.
	buckets [BucketCount][]*edge
	out     int               // self-maintained (outgoing) edges; the floor counts these
	in      int               // inbound (peer-initiated) edges; capped by InboundCap
	subnets map[Subnet]uint16 // live-edge count per subnet, for diversification
	phase   Phase
}

type edge struct {
	conn      transport.Conn
	id        kad.ID
	outgoing  bool
	role      edgeRole
	subnet    Subnet
	hasSubnet bool
	caps      Capability
	lastSeen  atomic.Int64 // Unix-nanos; creation time, refreshed by Touch on any activity, read by Idle
	ctrl      TokenBucket // per-edge control-frame rate limiter (level-2)
	fwd       TokenBucket // per-edge routed-frame rate limiter (level-2, see ForwardBurst)
	idx       int         // this edge's position in Edges.list, for O(1) swap-removal
	bpos      int         // this edge's position in its CPL bucket, for O(1) swap-removal
}

// TokenBucket is the shared time-based rate limiter, re-exported from transport (the
// bottom package that needs it — the relay shaper and media receive budget meter with
// it there). The alias keeps the established routing.TokenBucket spelling for the
// per-edge and per-originator limiters above. It carries no clock — the caller passes
// now — and the zero value is a ready, full bucket; see transport.TokenBucket.
type TokenBucket = transport.TokenBucket

// NewEdges creates an empty live-edge set owned by self. subnetf must be the same
// derivation the knowledge table uses, so live-edge subnets and contact subnets
// are comparable; a nil subnetf defaults to NoSubnet.
func NewEdges(self kad.ID, subnetf SubnetFunc) *Edges {
	if subnetf == nil {
		subnetf = NoSubnet
	}
	return &Edges{self: self, subnetf: subnetf, byID: make(map[kad.ID]*edge), subnets: make(map[Subnet]uint16)}
}

// AddEdge registers a live edge over conn, last-seen as of now. outgoing marks a
// self-maintained edge (counted toward the connectivity floor); inbound edges are
// tracked and forwarded over but never counted, since a NAT node cannot
// re-establish them itself. It returns ErrEdgeExists if an edge to the peer is
// already registered, ErrSelfEdge for an edge to this node, or ErrInboundFull
// when an inbound edge would exceed InboundCap.
func (e *Edges) AddEdge(conn transport.Conn, outgoing bool, caps Capability, now time.Time) error {
	id := conn.Remote()
	if id == e.self {
		return ErrSelfEdge
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.byID[id]; ok {
		return ErrEdgeExists
	}
	if !outgoing && e.in >= InboundCap {
		return ErrInboundFull
	}
	ed := &edge{conn: conn, id: id, outgoing: outgoing, caps: caps}
	ed.lastSeen.Store(now.UnixNano())
	if s, ok := e.subnetf(conn.RemoteAddr()); ok {
		ed.subnet, ed.hasSubnet = s, true
		e.subnets[s]++
	}
	e.byID[id] = ed
	ed.idx = len(e.list)
	e.list = append(e.list, ed)
	bi := kad.CommonPrefixLen(e.self, id)
	ed.bpos = len(e.buckets[bi])
	e.buckets[bi] = append(e.buckets[bi], ed)
	if outgoing {
		e.out++
	} else {
		e.in++
	}
	e.reclassify()
	e.updatePhase()
	return nil
}

// RemoveEdge drops a dead or closed edge. It is the entry point the maintenance
// loop calls when the transport signals a failure.
func (e *Edges) RemoveEdge(id kad.ID) {
	e.mu.Lock()
	defer e.mu.Unlock()
	ed, ok := e.byID[id]
	if !ok {
		return
	}
	delete(e.byID, id)
	last := e.list[len(e.list)-1]
	last.idx = ed.idx
	e.list[ed.idx] = last
	e.list[len(e.list)-1] = nil // drop the duplicated pointer so it can be GC'd
	e.list = e.list[:len(e.list)-1]
	// Mirror the swap-removal in the CPL bucket index.
	bi := kad.CommonPrefixLen(e.self, id)
	bk := e.buckets[bi]
	lastb := bk[len(bk)-1]
	lastb.bpos = ed.bpos
	bk[ed.bpos] = lastb
	bk[len(bk)-1] = nil
	e.buckets[bi] = bk[:len(bk)-1]
	if ed.outgoing {
		e.out--
	} else {
		e.in--
	}
	if ed.hasSubnet {
		if e.subnets[ed.subnet] <= 1 {
			delete(e.subnets, ed.subnet)
		} else {
			e.subnets[ed.subnet]--
		}
	}
	e.reclassify()
	e.updatePhase()
}

// Conn returns the live edge to id, if one exists.
func (e *Edges) Conn(id kad.ID) (transport.Conn, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if ed, ok := e.byID[id]; ok {
		return ed.conn, true
	}
	return nil, false
}

// Touch refreshes the last-seen time of the edge to id to now, recording that
// activity (a received frame or a pong) proved it alive, and reports whether such
// an edge is registered. The report lets the per-frame dispatch path learn "known
// edge" from this one lookup under one lock instead of a separate Conn check — it
// runs on every received frame. The maintenance loop reads last-seen via Idle, so
// Touch is what keeps a busy edge from being needlessly keepalive-pinged.
//
// It runs under a read lock plus an atomic store, so the per-frame refresh never
// serialises with the other readers (Closest/Idle/Siblings): byID is mutated only
// under the write lock (AddEdge/RemoveEdge), so the lookup is safe under RLock, and
// lastSeen is an atomic the concurrent Idle reads with a matching atomic load.
func (e *Edges) Touch(id kad.ID, now time.Time) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if ed, ok := e.byID[id]; ok {
		ed.lastSeen.Store(now.UnixNano())
		return true
	}
	return false
}

// AllowControl consumes one control-rate token from the edge to id and reports whether
// the frame may be served. It is the level-2 throttle the dispatch loop applies to
// work-generating control frames (ping, sibling-set request, lookup answer) so one edge
// cannot make this node amplify on its behalf. The zero id marks a self-originated
// frame (it has no edge by construction) and passes uncharged; any other untracked id
// is a peer whose edge registration was refused — the inbound cap is the reachable
// case — and is denied, so the population past the cap cannot fall through to an
// unlimited budget. now is the dispatch clock, kept injectable for deterministic tests.
func (e *Edges) AllowControl(id kad.ID, now time.Time) bool {
	if id == (kad.ID{}) {
		return true // self-originated: no edge to charge
	}
	e.mu.RLock()
	ed, ok := e.byID[id]
	e.mu.RUnlock()
	if !ok {
		return false // unregistered peer (e.g. refused by InboundCap): no budget
	}
	// The edge pointer stays valid after RUnlock (we hold a reference); the bucket guards
	// itself, so this does not contend with the forwarding read path on e.mu.
	return ed.ctrl.Allow(now, ControlRate, ControlBurst)
}

// AllowForward consumes one routed-frame token from the edge to id and reports whether the
// frame may be processed and forwarded. It is the level-2 per-edge throttle the dispatch
// loop applies to the routed envelopes (TypeRoute and the routed control types) so one
// edge cannot flood this node's decode/verify/forward work or the unsolicited-learning
// path. The zero/untracked distinction mirrors AllowControl: a self-originated frame
// (zero id) passes uncharged, an unregistered peer is denied. The rates are the looser
// ForwardRate/ForwardBurst, since routed transit is legitimately denser than control.
// now is the dispatch clock.
func (e *Edges) AllowForward(id kad.ID, now time.Time) bool {
	if id == (kad.ID{}) {
		return true // self-originated: no edge to charge
	}
	e.mu.RLock()
	ed, ok := e.byID[id]
	e.mu.RUnlock()
	if !ok {
		return false // unregistered peer (e.g. refused by InboundCap): no budget
	}
	return ed.fwd.Allow(now, ForwardRate, ForwardBurst)
}

// Siblings appends the live sibling edges (the s closest to self) into buf and
// returns it — the peers the maintenance loop runs sibling-set exchange with. Pass
// a buf with capacity ≥ Siblings to avoid allocation.
func (e *Edges) Siblings(buf []LiveEdge) []LiveEdge {
	buf = buf[:0]
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, ed := range e.list {
		if ed.role == roleSibling {
			buf = append(buf, LiveEdge{ID: ed.id, Conn: ed.conn})
		}
	}
	return buf
}

// Conns appends every live edge — siblings and fingers, outgoing and inbound — into
// buf and returns it, for broadcasting a graceful-leave to all neighbours.
func (e *Edges) Conns(buf []LiveEdge) []LiveEdge {
	buf = buf[:0]
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, ed := range e.list {
		buf = append(buf, LiveEdge{ID: ed.id, Conn: ed.conn})
	}
	return buf
}

// Idle appends into buf the live edges that have seen no activity within their
// role's timeout as of now: siblings use sibTimeout, fingers fingerTimeout (a
// looser bound, since a stale finger costs latency, not correctness). It is the
// maintenance loop's input both for keepalive (a short timeout pair) and for
// dead-edge detection (a longer pair — last-seen does not advance until a pong
// arrives, so an edge that never answers eventually crosses the longer bound). Pass
// a buf sized to the live set to avoid allocation.
func (e *Edges) Idle(now time.Time, sibTimeout, fingerTimeout time.Duration, buf []LiveEdge) []LiveEdge {
	buf = buf[:0]
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, ed := range e.list {
		timeout := fingerTimeout
		if ed.role == roleSibling {
			timeout = sibTimeout
		}
		if now.Sub(time.Unix(0, ed.lastSeen.Load())) >= timeout {
			buf = append(buf, LiveEdge{ID: ed.id, Conn: ed.conn})
		}
	}
	return buf
}

// bucketWalkMin is the live-edge count above which Closest walks the CPL-indexed
// buckets instead of the flat list. The bucket walk skips the far-bucket majority of a
// large set, but it pays a fixed cost scanning empty bucket tiers (most of the 256
// prefix lengths are unpopulated); below this size the flat scan is cheaper than that
// fixed cost, so a small node's forward path stays fast.
const bucketWalkMin = Siblings

// Closest returns up to n live edges nearest target under the XOR metric, closest
// first, appended into buf — the next-hop input to greedy forwarding. Pass a buf
// with capacity ≥ n and it allocates nothing.
//
// For a large live set it walks the CPL-indexed buckets tiered off b = CPL(self,
// target), stopping once the unscanned buckets cannot beat the kept set — the same
// provably-equivalent walk Knowledge.Closest uses, so the result matches a full scan
// while skipping the far-bucket majority. For a small set it scans the flat list,
// which is cheaper than the bucket walk's fixed empty-tier overhead.
func (e *Edges) Closest(target kad.ID, n int, buf []LiveEdge) []LiveEdge {
	buf = buf[:0]
	if n <= 0 {
		return buf
	}
	e.mu.RLock()
	defer e.mu.RUnlock()

	if len(e.list) <= bucketWalkMin {
		for _, ed := range e.list {
			buf = insertClosestEdge(buf, LiveEdge{ID: ed.id, Conn: ed.conn}, target, n)
		}
		return buf
	}

	b := kad.CommonPrefixLen(e.self, target)
	if b < BucketCount {
		for _, ed := range e.buckets[b] {
			buf = insertClosestEdge(buf, LiveEdge{ID: ed.id, Conn: ed.conn}, target, n)
		}
	}
	// The >b tier all share exactly b bits with target; scan it only until bucket b
	// has filled buf with strictly-closer edges (the n-th shares more than b bits).
	if len(buf) < n || kad.CommonPrefixLen(target, buf[n-1].ID) <= b {
		for bi := b + 1; bi < BucketCount; bi++ {
			for _, ed := range e.buckets[bi] {
				buf = insertClosestEdge(buf, LiveEdge{ID: ed.id, Conn: ed.conn}, target, n)
			}
		}
	}
	// Buckets below b, descending: bucket bi yields edges sharing exactly bi bits with
	// target, so once the n-th kept edge shares strictly more, no smaller bucket wins.
	for bi := b - 1; bi >= 0; bi-- {
		if len(buf) == n && kad.CommonPrefixLen(target, buf[n-1].ID) > bi {
			break
		}
		for _, ed := range e.buckets[bi] {
			buf = insertClosestEdge(buf, LiveEdge{ID: ed.id, Conn: ed.conn}, target, n)
		}
	}
	return buf
}

// Status reports the connectivity-floor band and the self-maintained edge count.
func (e *Edges) Status() FloorStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return FloorStatus{Phase: e.phase, OutEdges: e.out}
}

// ReplacementFor selects up to want candidate contacts near target to dial as new
// edges, drawn from the knowledge table k, skipping peers already live, contacts
// with no dialable address (ID-only hints cannot become edges) and subnets already
// at LiveSubnetCap among the live edges — biasing fills toward independent failure
// domains. The subnet cap is a soft preference (level-3 policy, not a security
// invariant): when every dialable candidate sits in a saturated subnet — e.g. a
// single-subnet deployment where all peers share one /24 — it falls back to those
// candidates rather than starving the connectivity floor. It returns Contacts, not
// Conns: dialing them is the maintenance loop's job. For a dropped sibling, pass
// target = self; for a finger, pass the finger's keyspace target. k must share
// this set's SubnetFunc for the subnet comparison to be meaningful.
func (e *Edges) ReplacementFor(k *Knowledge, target kad.ID, want int, buf []Contact) []Contact {
	buf = buf[:0]
	if want <= 0 {
		return buf
	}
	cands := k.Closest(target, max(want*4, 16), nil)
	e.mu.RLock()
	defer e.mu.RUnlock()
	for i := range cands {
		c := cands[i]
		if len(c.Addrs) == 0 {
			continue
		}
		if _, live := e.byID[c.ID]; live {
			continue
		}
		if c.hasSubnet && e.subnets[c.subnet] >= LiveSubnetCap {
			continue
		}
		buf = append(buf, c)
		if len(buf) >= want {
			return buf
		}
	}
	if len(buf) > 0 {
		return buf
	}
	// Saturated-subnet fallback: nothing diverse is dialable, so connectivity beats
	// diversification. Every dialable non-live candidate skipped above is eligible now.
	for i := range cands {
		c := cands[i]
		if len(c.Addrs) == 0 {
			continue
		}
		if _, live := e.byID[c.ID]; live {
			continue
		}
		buf = append(buf, c)
		if len(buf) >= want {
			break
		}
	}
	return buf
}

// --- internal helpers (caller holds e.mu) ---

// reclassify marks the Siblings edges closest to self as siblings and the rest as
// fingers. It selects the closest set in a single pass (insertion into a fixed
// Siblings-wide buffer) and then labels — O(n·Siblings) over the live set, run on
// every add/remove, rather than the old all-pairs O(n²). The result is identical:
// XOR distance to self is a total order on distinct IDs, so the "closest Siblings"
// set is unambiguous.
func (e *Edges) reclassify() {
	var top [Siblings]*edge
	ntop := 0
	for _, ed := range e.list {
		ntop = insertClosestSibling(&top, ntop, ed, e.self)
	}
	for _, ed := range e.list {
		ed.role = roleFinger
	}
	for i := range ntop {
		top[i].role = roleSibling
	}
}

// insertClosestSibling keeps top[:n] the ≤Siblings edges nearest self, closest
// first, and returns the new count. It mirrors insertClosestEdge but over *edge
// with self as the target and a fixed Siblings capacity, so it allocates nothing.
func insertClosestSibling(top *[Siblings]*edge, n int, ed *edge, self kad.ID) int {
	if n < Siblings {
		top[n] = ed
		for i := n; i > 0; i-- {
			if kad.DistanceCmp(self, top[i].id, top[i-1].id) < 0 {
				top[i], top[i-1] = top[i-1], top[i]
			} else {
				break
			}
		}
		return n + 1
	}
	if kad.DistanceCmp(self, ed.id, top[Siblings-1].id) < 0 {
		top[Siblings-1] = ed
		for i := Siblings - 1; i > 0; i-- {
			if kad.DistanceCmp(self, top[i].id, top[i-1].id) < 0 {
				top[i], top[i-1] = top[i-1], top[i]
			} else {
				break
			}
		}
	}
	return n
}

// updatePhase recomputes the floor band from the outgoing count. The emergency
// bands react instantly; only the Normal/NeedsFill boundary has hysteresis.
func (e *Edges) updatePhase() {
	switch out := e.out; {
	case out == 0:
		e.phase = PhaseBootstrap
	case out <= KMin:
		e.phase = PhaseCritical
	case out <= LowWater:
		e.phase = PhaseUrgent
	case out >= TargetEdges:
		e.phase = PhaseNormal
	default:
		if e.phase == PhaseNormal && out >= TargetEdges-FillHysteresis {
			e.phase = PhaseNormal
		} else {
			e.phase = PhaseNeedsFill
		}
	}
}

// insertClosestEdge keeps buf the ≤n live edges nearest target, closest first.
// With cap(buf) ≥ n it allocates nothing.
func insertClosestEdge(buf []LiveEdge, le LiveEdge, target kad.ID, n int) []LiveEdge {
	if len(buf) < n {
		buf = append(buf, le)
		for i := len(buf) - 1; i > 0; i-- {
			if kad.DistanceCmp(target, buf[i].ID, buf[i-1].ID) < 0 {
				buf[i], buf[i-1] = buf[i-1], buf[i]
			} else {
				break
			}
		}
		return buf
	}
	if kad.DistanceCmp(target, le.ID, buf[n-1].ID) < 0 {
		buf[n-1] = le
		for i := n - 1; i > 0; i-- {
			if kad.DistanceCmp(target, buf[i].ID, buf[i-1].ID) < 0 {
				buf[i], buf[i-1] = buf[i-1], buf[i]
			} else {
				break
			}
		}
	}
	return buf
}
