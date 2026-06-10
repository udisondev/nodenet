// Package routing holds the two overlay tables of nodenet and nothing that
// acts on them. Routing is XOR/Kademlia: closeness is a long shared bit-prefix,
// and the overlay forwards ONLY over live edges, which is what turns a NAT node
// that dialed out into a full router rather than a leaf.
//
// # Two tables, two recovery models
//
// Knowledge is the cheap, soft-state k-bucket table: a lazily maintained pool of
// everything learned about peers short of a live connection. It is the candidate
// pool that feeds greedy routing and live-edge replacement. Edges is the active
// set of live transport.Conn — the small subset the overlay actually forwards
// over — split into siblings (the s closest to self, correctness-critical) and
// fingers (best-effort, O(log N) reach). Under churn the two recover differently:
// knowledge heals lazily (last-seen, refresh, opportunistic learning), live edges
// are maintained actively (replace a dropped sibling at once).
//
// # What lives here, and what does not
//
// Two kinds of thing, both PURE — no I/O, no goroutines, no timers. The tables are
// data structures fed events (Observe, MarkDead, AddEdge, RemoveEdge) that answer
// questions (Closest, Status, ReplacementFor). Beside them is the pure
// logic of forwarding: the routing-message codec (Msg, EncodeMsg/DecodeMsg,
// EncodeRouteFrame, SetTTL) and the greedy decision (Decide) — given a message and
// the live edges, decide deliver, forward, or drop, and to whom. The envelope is
// originator-signed (SignMsg/VerifySig; Fresh bounds the replay window): forwarders
// stay cheap — clamp TTL, check origination-PoW and freshness — and only a terminal
// or amplifying hop verifies the signature. Edges also carries the per-edge token
// buckets (AllowControl, AllowForward) the dispatch loop charges before answering
// control or forwarding routed frames (level-2 self-protection). Beside the data
// envelope sits the control-protocol codec (control.go): the keepalive ping/pong,
// routed lookups, neighbour-list responses, sibling-set requests, and graceful-leave
// frames the maintenance loop above exchanges to keep its live edges healthy under
// churn. None of it touches the network.
//
// What does NOT live here is the acting: the dispatch loop that reads frames and
// sends them on, origination and disjoint-path fan-out, the maintenance loop
// (failure detection, re-dial with backoff, self-lookup, sibling-set exchange,
// keepalive, graceful leave), and all dialing. Those live in the node runtime and
// call into this package. Time enters as an explicit now parameter on the mutating
// table methods, never time.Now() inside: a table stays a pure function of its
// inputs, so unit tests need no clock and the maintenance loop supplies the (real
// or fake-clock) time.
//
// # Eviction without I/O
//
// A full bucket cannot ping the incumbent it might evict — the table does no I/O.
// So Observe into a full bucket does not silently drop anyone: it stashes the
// newcomer in a replacement cache and returns the least-recently-seen incumbent as
// a probe candidate; the caller pings it and reports back via Confirm. An old
// verified contact is therefore never displaced by a flood of fresh IDs
// (level-2-adjacent anti-eviction-flooding).
//
// # Subnet diversity
//
// A cap on how many entries one subnet may hold (a /24 IPv4 or /64 IPv6) prices
// cheap Sybil clusters and keeps a node's live edges in independent failure
// domains (level-2-adjacent self-protection; the live-edge diversification reuses
// the same machinery). Because transport.Addr is opaque to the overlay — the
// in-memory transport's Endpoint is a hub name, not an IP — the subnet key is
// derived by an injected SubnetFunc the node layer supplies (SubnetFromHostPort
// for real addresses, NoSubnet for tests).
//
// # Connectivity-floor accounting
//
// Edges accounts a node's self-maintained outgoing degree against a target, a
// low-water mark, and a hard floor (= the disjoint-path count d), and reports the
// band via Status. The accounting lives here; the acting on it (when and what to
// dial) is the maintenance loop's job and is level-3 local policy.
//
// In the dependency DAG routing sits above the leaves it composes (routing ->
// kad, identity, wire, transport, pow). Read-dominated, so both tables are guarded
// by an RWMutex.
package routing

import "github.com/udisondev/nodenet/kad"

const (
	// BucketCount is the number of k-buckets: one per possible common-prefix
	// length with self, 0..IDBits-1. A contact lands in bucket
	// CommonPrefixLen(self, id); self itself (prefix == IDBits) is never stored.
	BucketCount = kad.IDBits // 256

	// K is the per-bucket capacity of the knowledge table (Kademlia's k). It is
	// level-3 local policy; a deployer may tune it without splitting the network.
	K = 20

	// Siblings is s: the number of closest-to-self live edges kept as the
	// correctness-critical neighbour set. Level-3 policy.
	Siblings = 16

	// TargetEdges is the desired count of self-maintained outgoing live edges
	// (normal operation, lazy maintenance). Level-3 policy.
	TargetEdges = 64

	// LowWater is the degree below which the maintenance loop should fill
	// urgently. Level-3 policy.
	LowWater = 8

	// KMin is the hard connectivity floor: the minimum number of
	// independently-failing self-maintained edges, set equal to the disjoint-path
	// count d so a node can always launch d paths from its first hop. Below it the
	// node risks its own isolation. Level-3 policy, but a structural one.
	KMin = 3
)
