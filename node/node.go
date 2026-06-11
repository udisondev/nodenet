// Package node is the runtime that composes nodenet into a working overlay member.
// It owns the identity, the two routing tables, and the transport, and it runs the
// single dispatch loop that turns received frames into deliveries and forwards. It
// is the top of the dependency DAG and the public entry point other libraries build
// on (github.com/udisondev/nodenet/node); it holds no subsystem logic of its own —
// the keyspace, codec, routing tables and greedy decision all live below it — only
// the wiring that makes them act.
//
// # Recursive greedy forwarding
//
// A routing message addressed to a NodeID converges to that node hop by hop over
// live edges: at each node the dispatch loop parses the frame, checks the
// origination proof-of-work, and asks routing.Decide for the next hop nearest the
// target. Forwarding is zero-copy — the transit frame travels on in the very buffer
// it arrived in, the only change a one-byte TTL decrement patched in place — which
// the transport's borrow-Send contract (Send does not take the buffer) makes
// possible. Because forwarding rides live edges, a NAT node that dialed out is a
// full router: it forwards over the same bidirectional edge it opened.
//
// # What lives here
//
// The dispatch loop, origination (Send), the control protocol (keepalive ping/pong,
// routed lookups, neighbour responses, sibling-set exchange, graceful leave), the
// maintenance loop that keeps the live-edge set healthy under churn (failure
// detection, re-dial with backoff, self-lookup, keepalive, connectivity-floor
// fill) and the knowledge table fresh (lazy purge of contacts that exhausted the
// re-dial backoff, eviction probes that let live newcomers displace dead incumbents
// in full buckets, periodic refresh of stale buckets), and the test harness.
// Reflexive-address consolidation from pongs is wired here too, and the rest of NAT
// traversal builds on it: the routed rendezvous handshake (Rendezvous),
// direct-channel establishment (Connect, HolePunch, SendDirect) and the relay
// signalling all run on this loop, guarded by the defensive gates (admission and
// origination PoW, envelope signatures, freshness, rate limits) whose drops Stats
// exposes. The dispatch loop is single-goroutine (one select over the transport's
// single Inbound channel), so its scratch buffers are reused across packets with no
// locks and no per-packet allocation; the maintenance loop runs alongside it and
// shares the tables through their own locks. The maintenance policy itself
// (intervals, timeouts, backoff) lives beside the Maintenance type in maintenance.go.
package node

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	mrand "math/rand/v2"
	"sync"
	"time"

	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/nat"
	"github.com/udisondev/nodenet/pow"
	"github.com/udisondev/nodenet/rendezvous"
	"github.com/udisondev/nodenet/routing"
	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/wire"
)

// ID re-exports kad.ID so callers of the public API can spell it node.ID without
// importing kad. The alias keeps the dependency one-way (node -> kad); the
// fundamental key type still lives at the bottom of the DAG.
type ID = kad.ID

// ErrUnroutable means Send found no live edge to launch a packet toward the target.
// It is the originator's view of an empty live-edge set, distinct from a packet that
// is launched and later dropped mid-overlay.
var ErrUnroutable = errors.New("node: no live edge toward target")

// ErrUnsupported means the operation needs a transport capability this transport does
// not provide — e.g. HolePunch on the in-memory transport, which has no NAT to punch.
var ErrUnsupported = errors.New("node: operation unsupported by transport")

// ErrPoWUnmet means a dialed peer's NodeID does not clear the PoW difficulty, so it is
// not taken as a live edge (level-2 admission-PoW). It lets a Connect/HolePunch caller
// tell "peer failed the work" apart from "could not reach the peer" (ErrUnroutable).
var ErrPoWUnmet = errors.New("node: peer does not meet PoW difficulty")

// ErrEdgeRefused means the application's own edge-admission policy
// (WithEdgeAdmission) refused the peer, so the dialed connection was closed
// instead of becoming a live edge. The peer was reachable and cleared every
// verifiable gate — this is a local choice, not a network failure.
var ErrEdgeRefused = errors.New("node: edge refused by local admission policy")

const (
	defaultInboundBuffer = 64 // delivered-message channel depth
	hopCandidates        = 8  // next-hop candidates Decide returns (greedy best + repair fallbacks)

	// defaultForwardSendDeadline caps a single forward send on the dispatch loop, so a
	// slow or hostile next-hop cannot freeze frame processing for the whole node. It is
	// generous (a genuinely stuck edge, not transient congestion, trips it) and matches
	// the QUIC transport's own default; its job is to keep forwarding bounded even when
	// the transport was configured with no send deadline (WithSendDeadline(0)), which
	// would otherwise let one stuck hop wedge the loop forever. level-2 self-protection.
	defaultForwardSendDeadline = 5 * time.Second

	// maxConcurrentPunch bounds the reactive punch bursts in flight at once. A punch is
	// spawned in response to an inbound Connect (origination-PoW gated) or RelayBind (over
	// a relay edge, NOT PoW gated), so without a cap a flood could spawn unbounded punch
	// goroutines and turn this node into a high-volume packet reflector. At the cap a
	// punch is dropped (best-effort; the peer retries or falls back to relay).
	maxConcurrentPunch = 32
)

// Inbound is one message delivered to this node because it is the target. Payload is
// a copy, owned by the receiver and safe to keep past the dispatch loop's Release of
// the underlying packet.
type Inbound struct {
	Originator kad.ID // DeriveID(originator ed_pub) — who sent it
	Payload    []byte
}

// RendezvousResult is the verified outcome of a rendezvous: the keys and coordinates
// of the target node R, authenticated against its NodeID. EdPub hashes to Target
// (the anti-MITM guarantee — a forwarder cannot answer in R's place), XPub is R's
// static X25519 public key for sealed-box e2e, and Addrs are R's coordinates. The
// direct-channel handoff (dialing or hole-punching to Addrs) is Connect's job; the
// result stops at the verified coordinates.
type RendezvousResult struct {
	Target kad.ID
	EdPub  [32]byte
	XPub   [32]byte
	Addrs  []transport.Addr
}

// pendingRzv is a rendezvous handshake awaiting its reply: the target it was sent to
// (so an arriving reply is verified against the right NodeID) and a buffered channel
// the dispatch loop hands the verified reply to.
type pendingRzv struct {
	target kad.ID
	ch     chan rendezvous.Reply
}

// Node is an overlay member: an identity, the knowledge and live-edge tables, a
// transport, and the dispatch loop that forwards over them.
type Node struct {
	id    *identity.Identity
	self  kad.ID
	edPub [32]byte // id.EdPublic() copied once, stamped into every originated message
	selfC routing.Contact // precomputed self-contact for lookup/sibling answers (its Addrs slice is reused, not reallocated per answer)

	t transport.Transport
	k *routing.Knowledge
	e *routing.Edges

	dmin    int                // origination-PoW difficulty enforced on every received packet
	subnetf routing.SubnetFunc // subnet derivation for the tables (nil → NoSubnet)
	deliver chan Inbound
	rand    io.Reader // randomness for rendezvous nonces (crypto/rand by default)

	// ipAddressed records that the transport's endpoints are real IP host:port pairs
	// (transport.IPAddressed). The reflexive-plausibility check is fail-closed there: a
	// peer-reported address that does not parse as an IP is rejected instead of waved
	// through, which only a non-IP transport (the in-memory hub) may do.
	ipAddressed bool

	// pending holds the rendezvous handshakes this node has originated and is awaiting
	// a reply for, keyed by the per-handshake nonce. The dispatch loop matches an
	// arriving (verified) reply to its waiter here; the Rendezvous caller registers and
	// removes its entry. Mutex-guarded because the two run on different goroutines.
	pendingMu sync.Mutex
	pending   map[[rendezvous.NonceLen]byte]pendingRzv

	// punchPending holds the hole-punch attempts this node has initiated and is
	// awaiting a ConnectAck for, keyed by the per-attempt nonce. The dispatch loop
	// matches an arriving ack here; HolePunch registers and removes its entry.
	punchMu      sync.Mutex
	punchPending map[[nat.NonceLen]byte]chan nat.Connect

	// relayPending holds the relay requests this node has sent to a volunteer and is
	// awaiting a grant for, keyed by nonce; the value receives the allocation address.
	// canRelay marks this node a relay volunteer (it advertises CanRelay and serves
	// relay requests) — only meaningful if the transport implements transport.Relayer.
	relayMu      sync.Mutex
	relayPending map[[nat.NonceLen]byte]chan transport.Addr
	canRelay     bool

	// relayBuf backs pickRelay's live-edge snapshot, reused across calls so the cold
	// dial path does not allocate a fresh slice every time. relayBufMu serialises the
	// concurrent dial paths (maintenance dialer, Connect) that call pickRelay.
	relayBufMu sync.Mutex
	relayBuf   []routing.LiveEdge

	// hopsBuf backs Decide's NextHops. The dispatch loop is single-goroutine, so it
	// is reused across handle calls without locking; Send must NOT touch it (it runs
	// on the caller's goroutine).
	hopsBuf []routing.LiveEdge

	// fwdDeadline caps a single forward send on the dispatch loop (see
	// defaultForwardSendDeadline). A non-positive value falls back to the transport's
	// own Send (and its global send deadline).
	fwdDeadline time.Duration

	// reflexive consolidates the externally-visible addresses neighbours report seeing
	// us at (learned from pongs) into a confirmed address once enough of them agree.
	// The dispatch loop records reports; coords and the dialer read the consensus. It
	// is internally synchronised.
	reflexive *nat.Reflexive

	// originLimit rate-limits work-generating routed messages (lookup answers, Connect
	// coord-disclosure, and folding a solicited neighbours response into knowledge) by their
	// authenticated originator, so the limit cannot be dodged by spreading a flood across
	// edges. Per-edge control (ping/siblings) stays on Edges.
	originLimit *originLimiter

	// pendingLookup is the set of correlation nonces for lookups/sibling requests this node
	// has sent and is still awaiting answers for, each mapped to its expiry. A TypeNeighbors
	// answer is folded into knowledge ONLY if its echoed nonce is here and unexpired — so an
	// off-path attacker who never saw the request cannot inject an unsolicited contact list
	// to poison the table. The maintenance goroutine registers nonces; the dispatch loop
	// checks (and prunes) them, so it is mutex-guarded. Entries are kept long enough for a
	// routed answer to return, then pruned. A nonce is NOT consumed on first match: one
	// request fans out to several edges and draws several answers, all legitimately solicited.
	pendingLookupMu sync.Mutex
	pendingLookup   map[[routing.LookupNonceLen]byte]int64 // nonce -> expiry (UnixNano)

	// probes is the bounded set of eviction-probe candidates: full-bucket incumbents
	// the knowledge table asked to have pinged (Observe returned ObserveNeedProbe)
	// before a stashed newcomer may displace them. observe (any goroutine) adds candidates,
	// the maintenance tick drains them into probe dials, so the set is mutex-guarded.
	probeMu sync.Mutex
	probes  map[kad.ID]struct{}

	// stats counts frames shed by the defensive checks (PoW, freshness, signature,
	// rate-limit, inbound-cap), for observability under attack. Read via Stats.
	stats counters

	// Media plane: mediaIn carries inbound sessions that passed the admission
	// gates (PoW, caps, consent) to the application; mediaConsent is the
	// application's accept/refuse callback (nil = refuse all, secure by
	// default); mediaSlots bounds admitted inbound sessions. Media sessions
	// are application-owned and live OUTSIDE the routing tables: they carry no
	// transit, count toward no floor, and their death never reaps an edge —
	// it only triggers an out-of-schedule liveness ping of the edge on the
	// same path (watchMedia).
	mediaIn      chan transport.MediaSession
	mediaConsent func(kad.ID) bool
	mediaSlots   *mediaSlots

	// edgeAdmission is the application's local edge-admission policy: consulted
	// with the authenticated NodeID of every peer about to become a live edge,
	// inbound and outbound alike. nil admits everyone. Level-3 local policy —
	// the verifiable gates (PoW, caps) run regardless and never defer to it.
	edgeAdmission func(kad.ID) bool

	// maintenance is the live-edge upkeep policy (intervals, timeouts, backoff). Run
	// starts the maintenance loop with it unless maintain is false.
	maintain    bool
	maintenance Maintenance

	// punchSem bounds concurrent reactive punch bursts (see maxConcurrentPunch). It is a
	// counting semaphore: a burst acquires a slot before spawning and releases it when
	// done; an acquire that would block is dropped instead.
	punchSem chan struct{}

	// runCtx is the lifetime of the dispatch loop, set by Run. Fire-and-forget work the
	// loop spawns (punch bursts in response to inbound Connect/RelayBind frames) watches
	// it so it stops at shutdown instead of outliving the node. It defaults to
	// context.Background() so handlers driven directly in tests (without Run) never see a
	// nil context. Read only from the dispatch goroutine, set once before the loop.
	runCtx context.Context
}

// Option configures a Node at construction.
type Option func(*Node)

// WithDmin sets the origination-PoW difficulty (leading zero bits a sender's NodeID
// must clear). It is a level-1 network constant whose value the deployer picks; tests
// use 0 (no work required).
func WithDmin(d int) Option { return func(n *Node) { n.dmin = d } }

// WithSubnetFunc sets the subnet derivation the routing tables use for diversity
// accounting. Default is routing.NoSubnet (the in-memory transport has no IPs).
func WithSubnetFunc(f routing.SubnetFunc) Option { return func(n *Node) { n.subnetf = f } }

// WithRand sets the randomness source for rendezvous nonces. Default is
// crypto/rand.Reader; a test can inject a deterministic reader. It does not affect
// any security-relevant key material (identities are derived from their seed).
func WithRand(r io.Reader) Option { return func(n *Node) { n.rand = r } }

// WithInboundBuffer sets the depth of the delivered-message channel.
func WithInboundBuffer(size int) Option {
	return func(n *Node) {
		if size > 0 {
			n.deliver = make(chan Inbound, size)
		}
	}
}

// WithMaintenance sets the live-edge maintenance policy and enables the maintenance
// loop. The zero fields of m fall back to DefaultMaintenance, so a caller can tune
// just the intervals it cares about.
func WithMaintenance(m Maintenance) Option {
	return func(n *Node) {
		n.maintain = true
		n.maintenance = m.withDefaults()
	}
}

// WithRelay marks this node a relay volunteer: it advertises the CanRelay capability
// to peers and serves relay requests (splicing a tunnel for two peers that cannot
// hole-punch). It has effect only if the transport implements transport.Relayer.
func WithRelay() Option { return func(n *Node) { n.canRelay = true } }

// WithForwardSendDeadline caps how long a single forward send may block on the
// dispatch loop before the next-hop edge is dropped and the next disjoint candidate
// tried — so a slow or hostile next-hop cannot freeze the whole node, even under a
// transport configured with no send deadline. A non-positive value falls back to the
// transport's own Send bound. The default is generous (defaultForwardSendDeadline).
func WithForwardSendDeadline(d time.Duration) Option {
	return func(n *Node) { n.fwdDeadline = d }
}

// boundedSender is the optional Conn capability the forward path uses to bound a
// single send independently of the transport's global send deadline. Both bundled
// transports implement it; a Conn that does not falls back to plain Send.
type boundedSender interface {
	SendBounded(p *transport.Packet, d time.Duration) error
}

// forwardSend sends pkt on the dispatch-loop forward path with a bounded budget, so a
// stuck next-hop cannot wedge the single dispatch loop. It uses the Conn's bounded
// send when available and a forward deadline is set; otherwise it falls back to Send
// (whose bound is then the transport's own send deadline). It borrows pkt like Send.
func (n *Node) forwardSend(c transport.Conn, pkt *transport.Packet) error {
	if n.fwdDeadline > 0 {
		if bs, ok := c.(boundedSender); ok {
			return bs.SendBounded(pkt, n.fwdDeadline)
		}
	}
	return c.Send(pkt)
}

// WithEdgeAdmission sets the application's policy gate for live edges: it is
// consulted with the authenticated NodeID of every peer about to become one —
// inbound on its first frame, outbound before registration (Connect,
// hole-punch, relay, the maintenance dialer) — and a false return refuses the
// edge: the connection is closed, an outbound attempt fails with
// ErrEdgeRefused, and the refusal is counted in Stats. The callback must be
// fast and non-blocking (it runs on the dispatch loop).
//
// This is level-3 local policy, NOT a security boundary: a refused peer can
// still route messages to this node through other forwarders (filter those by
// Inbound.Originator) and still learns whatever any overlay member can learn;
// security rests on the verifiable gates — PoW, signatures, caps, rate limits
// — which run regardless of this policy. Mind the cost of generosity in
// reverse, too: every refused peer is one fewer neighbour to route over, so a
// broad ban list narrows this node's own connectivity.
func WithEdgeAdmission(f func(remote ID) bool) Option {
	return func(n *Node) { n.edgeAdmission = f }
}

// WithMediaConsent sets the application's gate for inbound media sessions: it
// is called with the authenticated NodeID of each (PoW-cleared, within-caps)
// caller, and only a true return admits the session to InboundMedia. Without
// this option every inbound session is refused — secure by default; an
// application that takes calls must opt in. The callback runs on the media
// gate goroutine and must be fast and non-blocking (answering the human's
// "accept the call?" belongs in the application, on the already-admitted
// session). level-2 self-protection.
func WithMediaConsent(f func(remote ID) bool) Option {
	return func(n *Node) { n.mediaConsent = f }
}

// WithoutMaintenance disables the maintenance loop: the node forwards and answers
// control frames but does not dial, keepalive, self-lookup, or exchange on its own.
// Useful for tests that drive the topology by hand.
func WithoutMaintenance() Option {
	return func(n *Node) { n.maintain = false }
}

// New builds a Node over the given identity and transport. The transport's LocalID
// must match the identity's NodeID (the caller wires them together — e.g. via the
// in-memory hub). It creates the knowledge and live-edge tables and the delivery
// channel; start the loop with Run.
func New(id *identity.Identity, t transport.Transport, opts ...Option) *Node {
	n := &Node{
		id:          id,
		self:        id.ID(),
		t:           t,
		hopsBuf:     make([]routing.LiveEdge, 0, hopCandidates),
		fwdDeadline: defaultForwardSendDeadline,
		maintain:    true,
		maintenance: DefaultMaintenance(),
		runCtx:      context.Background(),
	}
	copy(n.edPub[:], id.EdPublic())
	for _, opt := range opts {
		opt(n)
	}
	if n.deliver == nil {
		n.deliver = make(chan Inbound, defaultInboundBuffer)
	}
	if n.rand == nil {
		n.rand = rand.Reader
	}
	// Default subnet diversity from the transport: an IP-based transport (QUIC) enables
	// SubnetFromHostPort so reflexive consensus and live-edge diversification are not
	// silently disabled when the caller did not set WithSubnetFunc. A non-IP transport
	// (the in-memory one) leaves it as NoSubnet, so the caps stay inert in tests. The
	// same capability makes the reflexive-plausibility check fail-closed (ipAddressed).
	if ip, ok := t.(transport.IPAddressed); ok && ip.IPAddressed() {
		n.ipAddressed = true
		if n.subnetf == nil {
			n.subnetf = routing.SubnetFromHostPort
		}
	}
	n.pending = make(map[[rendezvous.NonceLen]byte]pendingRzv)
	n.punchPending = make(map[[nat.NonceLen]byte]chan nat.Connect)
	n.relayPending = make(map[[nat.NonceLen]byte]chan transport.Addr)
	n.reflexive = nat.NewReflexive()
	n.originLimit = newOriginLimiter()
	n.pendingLookup = make(map[[routing.LookupNonceLen]byte]int64)
	n.probes = make(map[kad.ID]struct{})
	n.punchSem = make(chan struct{}, maxConcurrentPunch)
	n.mediaIn = make(chan transport.MediaSession, mediaInBuffer)
	n.mediaSlots = newMediaSlots()
	n.k = routing.NewKnowledge(n.self, n.subnetf, n.dmin)
	n.e = routing.NewEdges(n.self, n.subnetf)
	// Precompute the self-contact once: caps follow canRelay (set by opts above) and
	// the local address is stable after the transport is listening, so lookup/sibling
	// answers reuse it instead of allocating a fresh Addrs slice per response.
	var selfCaps routing.Capability
	if n.canRelay {
		selfCaps = routing.CanRelay
	}
	n.selfC = routing.Contact{ID: n.self, EdPub: n.edPub, Caps: selfCaps, Addrs: []transport.Addr{t.LocalAddr()}}
	return n
}

// Bootstrap seeds the knowledge table with starting contacts — the entry points and
// anchors the maintenance loop dials to climb off zero connectivity. It is the way
// in for a fresh node (and the test harness): without at least one dialable contact
// the fill loop has nowhere to begin. Each contact is observed as of now.
func (n *Node) Bootstrap(contacts []routing.Contact) {
	now := time.Now()
	for i := range contacts {
		n.observe(contacts[i], now)
	}
}

// ID returns this node's NodeID.
func (n *Node) ID() kad.ID { return n.self }

// Edges returns the live-edge table (the maintenance loop and tests wire edges here).
func (n *Node) Edges() *routing.Edges { return n.e }

// Knowledge returns the k-bucket knowledge table.
func (n *Node) Knowledge() *routing.Knowledge { return n.k }

// Deliveries is the stream of messages addressed to this node. The channel closes
// when the node's Run returns, so a consumer ranging it unblocks on shutdown.
func (n *Node) Deliveries() <-chan Inbound { return n.deliver }

// Reflexive returns this node's confirmed externally-visible address — the one
// enough distinct neighbours have agreed they saw it at — or the zero Addr until
// that corroboration arrives.
func (n *Node) Reflexive() transport.Addr {
	if addr, ok := n.reflexive.Consensus(); ok {
		return addr
	}
	return transport.Addr{}
}

// Stats returns a snapshot of this node's defensive drop counters.
func (n *Node) Stats() Stats { return n.stats.snapshot() }

// Run is the dispatch loop: it pulls every frame off the transport's single inbound
// stream and handles it, until ctx is cancelled or the transport closes its stream.
// It is single-goroutine by design — one goroutine, one select over the inbound
// stream — which is what lets handle reuse scratch buffers without locks. If
// maintenance is enabled it also starts the maintenance loop. Run returns ctx.Err()
// on cancellation and nil on a clean transport shutdown — and on EVERY exit path it
// first stops and waits out the maintenance loop and its dial workers, and cancels
// the fire-and-forget punch bursts (they watch the loop's context and wind down on
// their own), so its return is the node's end of life, not the start of a
// background leak.
func (n *Node) Run(ctx context.Context) error {
	// Everything the loop spawns watches this derived context, so a return caused by
	// the transport closing (not just by cancellation) still unwinds all of it.
	ctx, cancel := context.WithCancel(ctx)
	n.runCtx = ctx
	// Close the delivery channel when Run ends, so a consumer ranging Deliveries()
	// (the documented pattern) unblocks on shutdown instead of leaking its goroutine.
	// By LIFO this defer runs last — after the dispatch loop has exited (the only writer
	// to n.deliver) and after the maintenance/media goroutines are joined — so the close
	// never races a send.
	defer close(n.deliver)
	if n.maintain {
		maintDone := make(chan struct{})
		go func() {
			defer close(maintDone)
			n.maintainLoop(ctx)
		}()
		defer func() { <-maintDone }() // after cancel (LIFO), so the wait terminates
	}
	// The media gate runs beside the dispatch loop: inbound media sessions
	// surface on the transport's own channel, never on Inbound, so they get
	// their own consumer (and the dispatch loop never blocks on call
	// admission).
	if media, ok := n.t.(transport.Media); ok {
		gateDone := make(chan struct{})
		go func() {
			defer close(gateDone)
			n.mediaGate(ctx, media)
		}()
		defer func() { <-gateDone }()
	}
	defer cancel()
	in := n.t.Inbound()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case d, ok := <-in:
			if !ok {
				return nil
			}
			n.handle(d)
		}
	}
}

// admit reports whether a peer may be taken as a live edge: its NodeID must clear the
// PoW difficulty. The transport already bound NodeID = BLAKE2b(ed_pub) at
// authentication, so the leading-zero count of the NodeID is exactly the work the peer
// did — no separate challenge round is needed. level-2 self-protection: a sub-PoW
// identity cannot be wedged into the edge table.
func (n *Node) admit(id kad.ID) bool { return pow.Satisfies(id, n.dmin) }

// allowEdge applies the application's edge-admission policy (WithEdgeAdmission;
// nil admits everyone). Level-3 local policy: it complements the level-2 admit
// gate and never substitutes for it.
func (n *Node) allowEdge(id kad.ID) bool {
	return n.edgeAdmission == nil || n.edgeAdmission(id)
}

// verify checks a routed message's originator signature, counting a failure for
// observability. It is the single VerifySig site so every terminal/amplifying branch
// reports bad-signature drops uniformly.
func (n *Node) verify(typ wire.Type, m *routing.Msg) bool {
	if m.VerifySig(typ) {
		return true
	}
	n.stats.badSig.Add(1)
	return false
}

// allowOrigin applies the per-originator rate limit to a work-generating routed message,
// counting a shed frame for observability.
func (n *Node) allowOrigin(originator kad.ID, now time.Time) bool {
	if n.originLimit.allow(originator, now) {
		return true
	}
	n.stats.rateLimited.Add(1)
	return false
}

// lookupPendingTTL is how long a sent lookup/sibling request's correlation nonce stays
// valid for an answer to come back. A routed answer returns within a few overlay
// round-trips; past this the nonce is pruned, so even a nonce an on-path forwarder saw
// cannot be used to inject contacts indefinitely. Level-2 self-protection.
const lookupPendingTTL = 30 * time.Second

// newLookupNonce mints a fresh correlation nonce for a lookup/sibling request this node is
// about to send and remembers it (with an expiry) so the matching TypeNeighbors answer is
// accepted. It prunes expired nonces on the way in, keeping the set bounded by the request
// rate times the TTL. ok is false only if the randomness source fails.
func (n *Node) newLookupNonce() (nonce [routing.LookupNonceLen]byte, ok bool) {
	if _, err := io.ReadFull(n.rand, nonce[:]); err != nil {
		return nonce, false
	}
	nowN := time.Now().UnixNano()
	n.pendingLookupMu.Lock()
	for k, exp := range n.pendingLookup {
		if nowN >= exp {
			delete(n.pendingLookup, k)
		}
	}
	n.pendingLookup[nonce] = nowN + lookupPendingTTL.Nanoseconds()
	n.pendingLookupMu.Unlock()
	return nonce, true
}

// solicited reports whether nonce matches a lookup/sibling request this node sent and is
// still awaiting. It does NOT consume the nonce: one request fans out to several edges and
// draws several answers, all legitimately solicited until the nonce expires.
func (n *Node) solicited(nonce [routing.LookupNonceLen]byte, now time.Time) bool {
	n.pendingLookupMu.Lock()
	exp, ok := n.pendingLookup[nonce]
	n.pendingLookupMu.Unlock()
	return ok && now.UnixNano() < exp
}

// dropEdge removes a live edge and forgets any reflexive-address report the peer made:
// a dead neighbour must no longer corroborate (or stalely prop up) this node's notion of
// its own external address. It is the single edge-removal site the dispatch and
// maintenance paths funnel through.
//
// It also closes the transport.Conn before unregistering: otherwise the QUIC connection,
// its read-loop goroutine and (on the peer side) the inbound slot live on until the idle
// timeout — and on the in-memory transport, forever — as a zombie nothing reaps. Close is
// idempotent, so a Send-failure path that already closed the conn is unaffected. level-2
// self-protection. Conn takes its own RLock; dropEdge holds no edge lock here, and Close
// is idempotent, so the lookup-then-close is race-free.
func (n *Node) dropEdge(id kad.ID) {
	if c, ok := n.e.Conn(id); ok {
		_ = c.Close()
	}
	n.e.RemoveEdge(id)
	n.reflexive.Remove(id)
}

// observe is the node-side wrapper every knowledge insertion goes through: it folds
// the contact in and resolves the table's NeedProbe handoff (the table does no I/O,
// so the bucket-full eviction check lands here). An incumbent we hold a live edge to
// is confirmed alive on the spot — a frame on that edge refreshed it moments ago —
// anything else becomes a probe candidate for the maintenance loop to dial. This is
// what keeps the anti-eviction-flooding rule honest both ways: an old verified
// contact is displaced only after it really stopped answering, yet a dead one cannot
// pin its bucket shut against live newcomers forever.
func (n *Node) observe(c routing.Contact, now time.Time) {
	out, probe := n.k.Observe(c, now)
	if out != routing.ObserveNeedProbe {
		return
	}
	if _, live := n.e.Conn(probe); live {
		n.k.Confirm(probe, true, now)
		return
	}
	n.addProbe(probe)
}

// addProbe queues an eviction-probe candidate, deduplicated and bounded: past
// maxProbes the candidate is dropped — the next observation of that bucket simply
// re-surfaces its least-recently-seen incumbent.
func (n *Node) addProbe(id kad.ID) {
	n.probeMu.Lock()
	if len(n.probes) < maxProbes {
		n.probes[id] = struct{}{}
	}
	n.probeMu.Unlock()
}

// popProbe takes one pending probe candidate, in no particular order (probing is
// best-effort; any pending incumbent is as good a check as another).
func (n *Node) popProbe() (kad.ID, bool) {
	n.probeMu.Lock()
	defer n.probeMu.Unlock()
	for id := range n.probes {
		delete(n.probes, id)
		return id, true
	}
	return kad.ID{}, false
}

// handle processes one received frame: it refreshes the source edge's liveness,
// then dispatches by frame type. The data path (TypeRoute) and the other Msg-framed
// routed types (lookup/neighbours, rendezvous hello/reply, NAT connect/ack) share
// one greedy forward path; the per-edge control types (ping/pong/siblings/leave,
// relay request/grant/bind) act directly on the edge, and TypeApp hands its payload
// to the local application. It owns d.Pkt and Releases it exactly once (deferred) —
// the borrow-Send contract means forwarding does not consume the packet, so a
// single Release covers every path.
func (n *Node) handle(d transport.Delivery) {
	defer d.Pkt.Release()

	typ, payload, _, err := wire.ParseFrame(d.Pkt.Bytes())
	if err != nil {
		// A peer-initiated conn that is not yet a live edge and sends an unparseable
		// frame bypasses the admission block below, so it never reaches the PoW gate and,
		// left open, pins an inbound slot as an untracked zombie (invisible to reap).
		// Close it. Touch harmlessly refreshes an already-registered edge (a valid peer
		// may send a frame of a future version — do not tear a live edge for that) and
		// returns false for an unregistered conn, which we then close. level-2.
		if d.Conn != nil && !n.e.Touch(d.Conn.Remote(), time.Now()) {
			n.stats.malformed.Add(1)
			d.Conn.Close()
		}
		return
	}
	// A frame proves its edge alive. If the edge is already known, refresh it so a busy
	// edge is never needlessly keepalive-pinged; if this is the first frame over a
	// peer-initiated edge, register it (inbound, non-counted) so we can route back over
	// the channel the peer opened — the mechanism that makes a NAT node a full router.
	now := time.Now()
	var from kad.ID
	if d.Conn != nil {
		from = d.Conn.Remote()
		if !n.e.Touch(from, now) {
			if !n.admit(from) {
				// level-2 admission-PoW: a sub-threshold peer is refused outright — not
				// registered, and its frame is dropped (no forward/relay/rendezvous), so a
				// cheap identity gets neither an edge nor free transit through us.
				n.stats.subPoW.Add(1)
				d.Conn.Close()
				return
			}
			// Level-3 local policy: the application refused this peer as an
			// edge — closed and dropped exactly like a sub-PoW one. The
			// verifiable gates above already ran; nothing security-relevant
			// rests on this refusal.
			if !n.allowEdge(from) {
				n.stats.edgeRefused.Add(1)
				d.Conn.Close()
				return
			}
			if err := n.e.AddEdge(d.Conn, false, 0, now); err != nil {
				// Any registration failure leaves an untracked conn — no rate-limit
				// bucket, invisible to the keepalive/reap scan, serving free transit that
				// nothing ever reaps — so close it rather than fall through and serve the
				// frame on it. ErrInboundFull is the cap backstop; ErrEdgeExists is a
				// duplicate from a simultaneous reverse dial (the live edge already
				// registered between the Touch miss and here); ErrSelfEdge a self-loop.
				// All level-2 self-protection.
				if errors.Is(err, routing.ErrInboundFull) {
					n.stats.inboundFull.Add(1)
				} else {
					n.stats.dupInbound.Add(1)
				}
				d.Conn.Close()
				return
			}
		}
	}

	switch typ {
	case routing.TypeRoute, routing.TypeLookup, routing.TypeNeighbors,
		rendezvous.TypeHello, rendezvous.TypeReply,
		nat.TypeConnect, nat.TypeConnectAck:
		n.handleRouted(typ, from, payload, d.Pkt, now)
	case routing.TypePing:
		// Ping→pong is 1:1 and tiny (no amplification), and legitimate keepalive is
		// periodic, so it is not rate-limited here — a raw ping flood is a generic DoS for
		// the transport's per-IP cap, not this per-edge amplifier throttle.
		if d.Conn != nil {
			n.handlePing(d.Conn)
		}
	case routing.TypePong:
		if d.Conn != nil {
			n.handlePong(d.Conn, payload)
		}
	case routing.TypeSiblings:
		// level-2 rate-limit: a sibling-set request makes us build and send a (fat)
		// neighbours response — an amplifier — so throttle per edge; a flood is dropped.
		if d.Conn == nil {
			return
		}
		if n.e.AllowControl(from, now) {
			n.handleSiblings(d.Conn, payload)
		} else {
			n.stats.rateLimited.Add(1)
		}
	case routing.TypeLeave:
		if d.Conn != nil {
			n.dropEdge(d.Conn.Remote())
		}
	case nat.TypeRelayRequest:
		// level-2 rate-limit: a relay request makes us allocate a spliced session (two real
		// sockets) and fire an unsolicited bind at the callee — an amplifier — so throttle
		// per edge like a sibling request; a flood is dropped.
		if d.Conn == nil {
			return
		}
		if n.e.AllowControl(from, now) {
			n.handleRelayRequest(d.Conn, payload)
		} else {
			n.stats.rateLimited.Add(1)
		}
	case nat.TypeRelayGrant:
		n.handleRelayGrant(payload)
	case nat.TypeRelayBind:
		// level-2 rate-limit: a bind makes us fire a punch burst at an address taken
		// straight from the untrusted payload — a reflector — so throttle per edge
		// exactly like a relay request; a flood is dropped.
		if d.Conn == nil {
			return
		}
		if n.e.AllowControl(from, now) {
			n.handleRelayBind(payload)
		} else {
			n.stats.rateLimited.Add(1)
		}
	case TypeApp:
		// Application frame: point-to-point only, so it must arrive on a real edge
		// (from is then transport-authenticated). Copy the payload out so it survives
		// the deferred Release; hand off non-blocking for the same reason as TypeRoute —
		// a stalled local consumer must never wedge the node-wide dispatch loop.
		if d.Conn == nil {
			return
		}
		// level-2 per-edge rate-limit: app frames land in the same shared delivery
		// channel as routed deliveries, so throttle them per edge for parity — one edge
		// must not flood the channel and starve other edges' deliveries (cross-edge
		// fairness), nor make this node allocate a copy per frame without bound.
		if !n.e.AllowForward(from, now) {
			n.stats.rateLimited.Add(1)
			return
		}
		select {
		case n.deliver <- Inbound{Originator: from, Payload: append([]byte(nil), payload...)}:
		default:
		}
	}
}

// handleRouted runs the shared greedy path for the Msg-framed types: check
// origination-PoW, decide, and either forward zero-copy or act on delivery by type.
// from is the edge the frame arrived on (zero for a self-originated frame); a forward
// never goes back over it, so a packet cannot bounce straight back the way it came —
// the loop an inbound edge to the sender would otherwise allow.
func (n *Node) handleRouted(typ wire.Type, from kad.ID, payload []byte, pkt *transport.Packet, now time.Time) {
	m, err := routing.DecodeMsg(payload)
	if err != nil {
		return
	}

	// level-2 per-edge rate-limit: throttle routed frames by the edge they arrived on, so
	// one edge cannot flood this node's decode/verify/forward work or the unsolicited-
	// learning path. Keyed on the arriving edge (already transport-authenticated), so it
	// costs no signature check on the hot path; a self-originated frame (from == zero, no
	// edge) is never charged. Spreading a flood across many edges runs into the transport's
	// per-IP/inbound caps.
	if !n.e.AllowForward(from, now) {
		n.stats.rateLimited.Add(1)
		return
	}

	// level-2 origination-PoW: a sender's NodeID = BLAKE2b(ed_pub) must clear the
	// difficulty, so sub-threshold originators die at the first honest hop.
	originator := identity.DeriveID(m.EdPub[:])
	if !pow.Satisfies(originator, n.dmin) {
		return
	}

	// level-2 freshness: drop a replayed-stale packet at every hop (forward and terminal).
	// This is a plain time comparison, no crypto, so it stays on the forward hot path; the
	// timestamp is signed, so a forger cannot refresh a captured packet without breaking
	// the signature the terminal then checks.
	if !m.Fresh(now, routing.MaxEnvelopeAge) {
		n.stats.stale.Add(1)
		return
	}

	dec := routing.Decide(n.self, &m, n.e, n.hopsBuf)
	if dec.Kind == routing.KindForward {
		// Zero-copy: decrement the hop budget in place and send the same buffer on.
		// Local repair: a failed send means the edge died between Decide and now
		// (a race the transport has not yet signalled), so drop it and fall to the
		// next candidate with the SAME buffer — borrow-Send leaves pkt ours, so a
		// retry costs no copy. If every candidate fails the packet is dropped (the
		// deferred Release), and disjoint paths cover the gap.
		routing.SetTTL(payload, dec.OutTTL)
		for _, hop := range dec.NextHops {
			if hop.ID == from {
				continue // never forward back over the edge it arrived on
			}
			// Bounded send: a stuck next-hop must not freeze the dispatch loop. A failed
			// (or timed-out) send drops the edge and falls to the next disjoint candidate
			// with the SAME buffer (borrow-Send leaves pkt ours, so the retry costs no copy).
			if err := n.forwardSend(hop.Conn, pkt); err == nil {
				break
			}
			n.dropEdge(hop.ID)
		}
		return
	}

	// Terminal hop: either we are the target (KindDeliver) or greedy can get no
	// closer (KindDrop). What that means depends on the type. Acting on or amplifying
	// for the originator is gated on its envelope signature (level-2): a forwarder skips
	// this verify (hot path), but a node that delivers, answers, or learns pays it, so a
	// forged EdPub cannot spoof an originator or turn this node into a reflector. Hello
	// and Reply carry their own inner signatures (verified below), so they are exempt here.
	switch typ {
	case routing.TypeRoute:
		if dec.Kind == routing.KindDeliver {
			if !n.verify(typ, &m) {
				return // unauthenticated originator — refuse delivery and learning
			}
			// Copy the payload out so it survives the deferred Release. The hand-off is
			// non-blocking: the dispatch loop is single-goroutine and also forwards and
			// answers control for the whole node, so a slow or stalled local consumer must
			// never wedge it (a node-wide head-of-line stall). A full channel drops the
			// message — the overlay is best-effort, like every other send on this loop.
			select {
			case n.deliver <- Inbound{Originator: originator, Payload: append([]byte(nil), m.Payload...)}:
			default:
			}
			// Opportunistic learning: a delivered packet's originator is a live,
			// reachable peer worth remembering (its address arrives later via a
			// neighbours response).
			n.observe(routing.Contact{ID: originator, EdPub: m.EdPub}, now)
		}
		// A data packet that dead-ends short of its target is simply dropped.
	case routing.TypeLookup:
		// The closest node routing reaches answers — whether the lookup landed on its
		// exact target (KindDeliver) or hit a greedy dead-end nearest it (KindDrop, the
		// usual terminal, since a self-lookup carries self in the avoid-set so it never
		// routes home). Verify before answering: a spoofed originator must not make us
		// emit a (fat) Neighbors response routed to a forged address (reflection).
		if !n.verify(typ, &m) {
			return
		}
		// level-2 rate-limit: throttle answers per authenticated originator so a lookup
		// flood cannot make this node a CPU/bandwidth amplifier — keyed on the originator
		// (not the arriving edge) so it cannot be dodged by spreading across edges.
		if !n.allowOrigin(originator, now) {
			return
		}
		// A well-formed lookup carries exactly the correlation nonce; echo it in the answer.
		if len(m.Payload) != routing.LookupNonceLen {
			return
		}
		var nonce [routing.LookupNonceLen]byte
		copy(nonce[:], m.Payload)
		// Stack-backed: Siblings closest plus self fit in cbuf, so the answer's contact
		// list and the self append both avoid a heap allocation (cs does not escape —
		// sendNeighbors only reads it).
		var cbuf [routing.Siblings + 1]routing.Contact
		cs := n.k.Closest(m.Target, routing.Siblings, cbuf[:0])
		cs = append(cs, n.selfContact())
		n.sendNeighbors(originator, cs, nil, nonce)
	case routing.TypeNeighbors:
		if dec.Kind == routing.KindDeliver {
			if !n.verify(typ, &m) {
				return // unauthenticated contact list — do not fold it into knowledge
			}
			// level-2 solicitation gate: fold a neighbours response into knowledge ONLY if
			// it echoes the nonce of a lookup/sibling request this node actually sent and is
			// still awaiting. The nonce is fresh crypto-random the originator kept, so an
			// off-path attacker who never saw the request cannot forge an answer the table
			// accepts — closing unsolicited contact-list poisoning. (An on-path forwarder of
			// our request can see the nonce; that narrow surface is the accepted residual,
			// and the per-originator rate-limit below bounds a replay flood from it.)
			if len(m.Payload) < routing.LookupNonceLen {
				return
			}
			var nonce [routing.LookupNonceLen]byte
			copy(nonce[:], m.Payload[:routing.LookupNonceLen])
			if !n.solicited(nonce, now) {
				n.stats.rateLimited.Add(1)
				return
			}
			if !n.allowOrigin(originator, now) {
				return
			}
			cs, err := routing.DecodeNeighbors(m.Payload[routing.LookupNonceLen:])
			if err != nil {
				return
			}
			// Knowledge.Observe enforces the key↔ID binding (NodeID = BLAKE2b(ed_pub)),
			// so a forged contact in this untrusted list — an arbitrary or a victim's ID
			// paired with an unrelated key — is refused entry, while keyless ID-only
			// hints and validly-bound contacts are folded in (PoW-gated). A keyless hint
			// binds to ANY ID trivially, so we strip its addresses before learning it:
			// otherwise an attacker could seed "some real peer's ID → attacker address".
			// A keyed contact's address is kept (its key proves the ID, and a dial is still
			// mutual-TLS verified to that ID, so a wrong address only fails closed).
			for i := range cs {
				if cs[i].EdPub == ([32]byte{}) {
					cs[i].Addrs = nil
				}
				n.observe(cs[i], now)
			}
		}
		// A neighbours response that cannot route all the way back is dropped.
	case rendezvous.TypeHello:
		if dec.Kind == routing.KindDeliver {
			// Authenticate the originator BEFORE charging the rate limit: the
			// per-originator bucket is keyed on the envelope identity, so a forged
			// m.EdPub (with no private key to sign) must not create a bucket — that
			// would both bypass the throttle (a fresh forged originator each time) and
			// flood the bucket map. Verify mirrors nat.TypeConnect; handleHello's inner
			// VerifyHello stays as the target-binding gate.
			if !n.verify(typ, &m) {
				return
			}
			// level-2 rate-limit: answering a hello costs an Ed25519 verify, an Ed25519
			// reply signature and a 3-path routed reply disclosing this node's
			// coordinates — the same work and disclosure a Connect costs — so throttle
			// per authenticated originator like nat.TypeConnect. A signed hello replays
			// freely inside the freshness window; the throttle caps what that buys.
			if !n.allowOrigin(originator, now) {
				return
			}
			n.handleHello(originator, m.EdPub, m.Payload, now)
		}
		// A hello that dead-ends short of R is dropped; disjoint paths cover the gap.
	case rendezvous.TypeReply:
		if dec.Kind == routing.KindDeliver {
			n.handleReply(m.Payload)
		}
	case nat.TypeConnect:
		if dec.Kind == routing.KindDeliver {
			// The envelope signature is the ONLY authentication a Connect carries (its
			// address hints are not separately signed), so verify before punching toward
			// them — this binds the hint addresses to the originator's identity, closing
			// third-party injection of a victim's address as a punch target.
			if !n.verify(typ, &m) {
				return
			}
			// level-2 rate-limit: answering discloses this node's coordinates (its
			// external address) and fires a punch, so throttle per authenticated
			// originator — this caps cheap mass deanonymization (NodeID→IP) and reflector
			// abuse. Single disclosure to a legitimate initiator is inherent to the
			// routed-handshake design and accepted as residual (full metadata privacy is
			// out of scope).
			if !n.allowOrigin(originator, now) {
				return
			}
			n.handleConnect(originator, m.Payload)
		}
		// A connect that dead-ends short of the peer is dropped; the initiator times out.
	case nat.TypeConnectAck:
		if dec.Kind == routing.KindDeliver {
			if !n.verify(typ, &m) {
				return
			}
			n.handleConnectAck(m.Payload)
		}
	}
}

// handleHello answers a rendezvous Hello that reached us as its target: verify it was
// signed by its originator for delivery to us, learn the originator's keys/coordinates
// opportunistically, and route a signed Reply back carrying our own. originEdPub is
// the originator key from the routing envelope (already PoW-checked by handleRouted);
// VerifyHello checks the hello signature against it and against our own NodeID, so a
// forwarder cannot have forged a hello addressed elsewhere.
func (n *Node) handleHello(originator kad.ID, originEdPub [32]byte, payload []byte, now time.Time) {
	h, err := rendezvous.DecodeHello(payload)
	if err != nil {
		return
	}
	if err := rendezvous.VerifyHello(n.self, originEdPub, &h); err != nil {
		return
	}
	// Opportunistic learning: the originator is a reachable peer that just told us its
	// e2e key and coordinates. The hello signature covers XPub, so it may be bound.
	n.observe(routing.Contact{ID: originator, EdPub: originEdPub, Addrs: h.Addrs}, now)
	n.k.BindXPub(originator, h.XPub)

	rep := rendezvous.Reply{XPub: n.id.KEXPublic(), Addrs: n.coords(), Nonce: h.Nonce}
	rendezvous.SignReply(n.id, &rep)
	out, err := rendezvous.MarshalReply(&rep)
	if err != nil {
		return
	}
	// Route the reply back to the originator by its NodeID, greedily like any message.
	_ = n.originate(originator, rendezvous.TypeReply, out)
}

// handleReply matches a rendezvous Reply that reached us to the handshake we are
// awaiting, verifies it against that handshake's target (the anti-MITM check), and
// hands it to the waiting Rendezvous caller. It runs on the dispatch goroutine and
// must never block: the waiter's channel is buffered and the send is non-blocking, and
// a reply with no matching pending entry (unknown or already-answered nonce) or one
// that fails verification (a forwarder's forgery) is silently dropped.
func (n *Node) handleReply(payload []byte) {
	rep, err := rendezvous.DecodeReply(payload)
	if err != nil {
		return
	}
	n.pendingMu.Lock()
	pr, ok := n.pending[rep.Nonce]
	n.pendingMu.Unlock()
	if !ok {
		return
	}
	if err := rendezvous.VerifyReply(pr.target, rep.Nonce, &rep); err != nil {
		return
	}
	select {
	case pr.ch <- rep:
	default:
	}
}

// handlePing answers a keepalive over conn with a pong that echoes the address the
// pinger was seen arriving from, so the pinger can learn its reflexive address.
// Best-effort (sendFrame): a dead edge is the maintenance loop's problem.
func (n *Node) handlePing(conn transport.Conn) {
	n.sendFrame(conn, func(dst []byte) (int, error) {
		return routing.EncodePongFrame(dst, conn.RemoteAddr())
	})
}

// handlePong records, against the reporting neighbour, the reflexive address it said it
// saw us at; the consolidator confirms it once enough distinct neighbours in independent
// subnets agree. (Edge liveness was already refreshed by handle's Touch.) Two guards keep
// a hostile neighbour from poisoning the reflexive address: the reported address must be
// a plausible external endpoint (a routable unicast IP, not loopback/multicast/etc), and
// the reporter is tagged with its own subnet so a single-subnet sybil cluster cannot
// reach the diversity-gated quorum.
func (n *Node) handlePong(conn transport.Conn, payload []byte) {
	addr, err := routing.DecodePong(payload)
	if err != nil || !plausibleReflexive(addr, n.ipAddressed) {
		return
	}
	var key nat.SubnetKey
	hasSubnet := false
	if n.subnetf != nil {
		if s, ok := n.subnetf(conn.RemoteAddr()); ok {
			key, hasSubnet = nat.SubnetKey(s), true
		}
	}
	n.reflexive.Record(conn.Remote(), key, hasSubnet, addr)
}

// handleSiblings answers a sibling-set exchange request over conn with the contacts
// we hold nearest ourselves — the neighbourhood a nearby peer most wants to learn —
// plus ourselves. It replies straight over the edge (one hop), not routed, echoing the
// request's correlation nonce so the requester accepts the answer.
func (n *Node) handleSiblings(conn transport.Conn, payload []byte) {
	nonce, err := routing.DecodeSiblings(payload)
	if err != nil {
		return
	}
	// Stack-backed (Siblings closest + self), as in the lookup answer path above.
	var cbuf [routing.Siblings + 1]routing.Contact
	cs := n.k.Closest(n.self, routing.Siblings, cbuf[:0])
	cs = append(cs, n.selfContact())
	n.sendNeighbors(conn.Remote(), cs, conn, nonce)
}

// sendNeighbors emits a TypeNeighbors message carrying cs to target, echoing the request's
// correlation nonce so the requester accepts it. If direct is non-nil the message goes
// straight over that edge (a per-edge response, TTL 1); otherwise it is routed greedily
// over the closest live edge toward target, with local-repair fallback. Either way it is
// best-effort — control traffic the maintenance loop will repeat.
func (n *Node) sendNeighbors(target kad.ID, cs []routing.Contact, direct transport.Conn, nonce [routing.LookupNonceLen]byte) {
	p := transport.Get()
	defer p.Release()

	ttl := uint8(routing.MaxHops)
	if direct != nil {
		ttl = 1
	}
	w, err := routing.EncodeNeighborsFrame(p.Buf(), n.id, n.edPub, target, ttl, time.Now(), nonce, cs)
	if err != nil {
		return
	}
	p.SetLen(w)

	if direct != nil {
		_ = direct.Send(p)
		return
	}
	var hopBuf [routing.KMin]routing.LiveEdge
	hops := n.e.Closest(target, routing.KMin, hopBuf[:0])
	for _, hop := range hops {
		if err := hop.Conn.Send(p); err == nil {
			break
		}
		n.dropEdge(hop.ID)
	}
}

// selfContact is this node's own knowledge entry — NodeID, Ed25519 key, and the
// address peers dial it at — so a neighbours response lets the recipient reach us
// directly.
func (n *Node) selfContact() routing.Contact { return n.selfC }

// Send originates a routing message toward target along up to d (= routing.KMin)
// disjoint paths: it picks the d closest live edges as distinct first hops and sends
// one copy down each, every copy carrying the OTHER first hops in its avoid-set so the
// branches steer apart in the middle and reconverge near the target.
//
// It returns ErrUnroutable if there is no live edge to launch from and the encode error
// if the payload does not fit a frame; otherwise nil. The disjoint copies are dispatched
// concurrently (see originate), so the call does not block on any one (possibly
// congested) socket and a single failing first hop does not sink the request — the
// surviving paths still carry it. Because origination never blocks, Send takes no
// context — there is nothing for one to cancel; SendDirect and Connect, which do block
// on the network, are the ctx-aware calls.
func (n *Node) Send(target kad.ID, payload []byte) error {
	return n.originate(target, routing.TypeRoute, payload)
}

// TypeApp is the application frame carried point-to-point over a direct edge. It is
// never routed: the dispatch loop delivers its payload to the local application via
// Deliveries(), attributing it to the edge's transport-authenticated remote — the
// edge itself is end-to-end encrypted and bound to the peer's NodeID, so no envelope
// or signature is needed. Type values below 64 are reserved for the core protocol;
// applications embedding nodenet speak their own protocol inside TypeApp payloads.
const TypeApp wire.Type = 64

// SendDirect sends an application payload to target over a direct edge: the live
// edge to target if one is up, otherwise Connect (rendezvous, then direct dial /
// hole-punch / relay). Unlike Send, the bytes never transit other nodes — this is
// the conversation path; Send remains the small-control / presence path.
//
// On the remote side the payload surfaces on Deliveries(), same as Send. Like every
// overlay path it is best-effort (a stalled remote consumer drops), so an application
// that needs reliability must acknowledge and retry at its own layer.
func (n *Node) SendDirect(ctx context.Context, target kad.ID, payload []byte) error {
	conn, ok := n.e.Conn(target)
	if !ok {
		var err error
		if conn, err = n.Connect(ctx, target); err != nil {
			// Simultaneous connect: while this dial was in flight the peer's own dial
			// may have landed first, making ours the duplicate register rejects. Any
			// live edge to the target serves equally — re-check before giving up.
			if conn, ok = n.e.Conn(target); !ok {
				return err
			}
		}
	}
	p := transport.Get()
	defer p.Release()
	f, err := wire.EncodeFrame(p.Buf(), TypeApp, payload)
	if err != nil {
		return err
	}
	p.SetLen(len(f))
	if err := conn.Send(p); err != nil {
		// The edge died between lookup and send; drop it so maintenance replaces it.
		n.dropEdge(conn.Remote())
		return err
	}
	return nil
}

// originate launches a routed message of frame type typ toward target along up to d
// (= routing.KMin) disjoint first hops, each copy carrying the other first hops in its
// avoid-set. It is the shared origination path behind Send (TypeRoute) and the rendezvous
// handshake (TypeHello/TypeReply).
//
// The disjoint copies are independent by design, so they must not be serialised behind
// each other's blocking network Send: a single slow or congested first-hop socket would
// otherwise delay launching every other path and block the caller. Each copy is a distinct
// frame (its own avoid-set), so originate encodes each into its own pooled buffer here on
// the caller's goroutine (cheap, in-memory, reusing one avoid scratch), then hands that
// buffer to a goroutine that owns it: borrow-Send copies it into the edge synchronously and
// the goroutine Releases it via defer once Send returns, dropping the edge on failure. The
// caller's latency is thus one encode pass, not the sum of d network writes.
//
// It returns ErrUnroutable when there is no live edge to launch from and the encode error
// when the payload does not fit a frame; a per-hop send failure is handled in the
// background (the edge is dropped, the other paths still carry the message), so
// origination over a non-empty edge set returns nil.
func (n *Node) originate(target kad.ID, typ wire.Type, payload []byte) error {
	var hopBuf [routing.KMin]routing.LiveEdge
	hops := n.e.Closest(target, routing.KMin, hopBuf[:0])
	if len(hops) == 0 {
		return ErrUnroutable
	}

	// Sign once: the signature covers the frame type, target, EdPub and payload, all
	// identical across the disjoint copies (only the avoid-set differs, which is not
	// signed), so the same signature is stamped into every copy.
	var tmpl routing.Msg
	tmpl.Target, tmpl.EdPub, tmpl.Payload = target, n.edPub, payload
	routing.SignMsg(n.id, typ, &tmpl, time.Now())
	sig, sent := tmpl.Sig, tmpl.Sent

	var avoidBuf [routing.KMin * kad.IDLen]byte
	for i := range hops {
		p := transport.Get()
		msg := routing.Msg{
			Target:  target,
			TTL:     routing.MaxHops,
			EdPub:   n.edPub,
			Sent:    sent,
			Avoid:   otherHops(avoidBuf[:0], hops, i),
			Payload: payload,
			Sig:     sig,
		}
		w, err := routing.EncodeMsgFrame(p.Buf(), typ, &msg)
		if err != nil {
			p.Release()
			return err // payload too large; same outcome for every copy
		}
		p.SetLen(w)
		hop := hops[i]
		go func() {
			defer p.Release()
			if hop.Conn.Send(p) != nil {
				n.dropEdge(hop.ID)
			}
		}()
	}
	return nil
}

// Rendezvous discovers and authenticates the keys and coordinates of the node R with
// NodeID target. It originates a signed Hello routed to target, waits for R's signed
// Reply (routed back), verifies it (BLAKE2b(ed_pub_R) == target and the signature, so
// no forwarder on the path can answer in R's place), and returns R's verified keys and
// coordinates. The exchanged coordinates are where the two peers would then open a
// DIRECT channel via hole-punching — Connect runs that handoff; Rendezvous returns
// once the coordinates are verified.
//
// It blocks until the reply arrives or ctx is done (caller sets the timeout). It
// returns ErrUnroutable if there is no live edge to launch the hello from, or ctx.Err()
// on timeout/cancel. The learned contact is folded into the knowledge table.
func (n *Node) Rendezvous(ctx context.Context, target kad.ID) (RendezvousResult, error) {
	var nonce [rendezvous.NonceLen]byte
	if _, err := io.ReadFull(n.rand, nonce[:]); err != nil {
		return RendezvousResult{}, err
	}

	h := rendezvous.Hello{XPub: n.id.KEXPublic(), Addrs: n.coords(), Nonce: nonce}
	rendezvous.SignHello(n.id, target, &h)
	payload, err := rendezvous.MarshalHello(&h)
	if err != nil {
		return RendezvousResult{}, err
	}

	ch := make(chan rendezvous.Reply, 1)
	n.pendingMu.Lock()
	n.pending[nonce] = pendingRzv{target: target, ch: ch}
	n.pendingMu.Unlock()
	defer func() {
		n.pendingMu.Lock()
		delete(n.pending, nonce)
		n.pendingMu.Unlock()
	}()

	if err := n.originate(target, rendezvous.TypeHello, payload); err != nil {
		return RendezvousResult{}, err
	}

	select {
	case rep := <-ch:
		// The reply signature covers XPub (verified in handleReply), so it may be bound.
		n.observe(routing.Contact{ID: target, EdPub: rep.EdPub, Addrs: rep.Addrs}, time.Now())
		n.k.BindXPub(target, rep.XPub)
		return RendezvousResult{Target: target, EdPub: rep.EdPub, XPub: rep.XPub, Addrs: rep.Addrs}, nil
	case <-ctx.Done():
		return RendezvousResult{}, ctx.Err()
	}
}

// coords are this node's own rendezvous coordinates: the address peers dial it at,
// plus its reflexive (externally-visible) address once enough distinct neighbours
// have corroborated one. These are the candidates a peer dials or hole-punches toward.
func (n *Node) coords() []transport.Addr {
	addrs := []transport.Addr{n.t.LocalAddr()}
	if r := n.Reflexive(); r != (transport.Addr{}) {
		addrs = append(addrs, r)
	}
	return addrs
}

// holePunchRaw runs the hole-punch orchestration and returns the raw authenticated edge
// to target, without registering it. It routes a Connect to target over the overlay (any
// common neighbour forwards it), waits for target's ConnectAck carrying its reflexive
// candidates, then both sides punch their NAT mappings open and this node — the
// initiator, hence the dialer — raises the QUIC connection over the direct path. hints
// are extra candidate addresses (e.g. from a prior rendezvous) tried alongside the ones
// target returns.
//
// It blocks until the edge is up or ctx is done. It returns ErrUnroutable if there is
// no live edge to route the Connect over or no candidate could be dialed, ctx.Err() on
// timeout, or ErrUnsupported if the transport cannot punch (the in-memory transport).
func (n *Node) holePunchRaw(ctx context.Context, target kad.ID, hints []transport.Addr) (transport.Conn, error) {
	puncher, ok := n.t.(transport.Puncher)
	if !ok {
		return nil, ErrUnsupported
	}

	var nonce [nat.NonceLen]byte
	if _, err := io.ReadFull(n.rand, nonce[:]); err != nil {
		return nil, err
	}
	c := nat.Connect{Nonce: nonce, Addrs: n.coords()}
	payload, err := nat.MarshalConnect(&c)
	if err != nil {
		return nil, err
	}

	ch := make(chan nat.Connect, 1)
	n.punchMu.Lock()
	n.punchPending[nonce] = ch
	n.punchMu.Unlock()
	defer func() {
		n.punchMu.Lock()
		delete(n.punchPending, nonce)
		n.punchMu.Unlock()
	}()

	if err := n.originate(target, nat.TypeConnect, payload); err != nil {
		return nil, err
	}

	select {
	case ack := <-ch:
		// Our own hints (knowledge/rendezvous) go first: the ack's list is peer-
		// controlled, so when the candidate cap cuts, it must not be able to evict
		// them. punchCandidates dedupes and caps the combined list once, for the
		// punch and the dial alike.
		candidates := make([]transport.Addr, 0, len(hints)+len(ack.Addrs))
		candidates = append(candidates, hints...)
		candidates = append(candidates, ack.Addrs...)
		candidates = punchCandidates(candidates)
		n.burstPunch(ctx, puncher, candidates)
		return n.dialAnyRaw(ctx, target, candidates)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// HolePunch opens a direct edge to target across NATs and registers it as an outgoing
// live edge. See holePunchRaw for the orchestration; the resulting edge passes the
// admission-PoW check before it is taken.
func (n *Node) HolePunch(ctx context.Context, target kad.ID, hints []transport.Addr) (transport.Conn, error) {
	conn, err := n.holePunchRaw(ctx, target, hints)
	if err != nil {
		return nil, err
	}
	return n.register(conn, 0, time.Now())
}

// Connect establishes a direct, authenticated live edge to target — the rendezvous →
// direct-channel handoff. An edge that already exists (the target connected to us
// first, or simultaneous Connects crossed) is returned as is — it is authenticated to
// the same NodeID, so a rendezvous would prove nothing new and a duplicate dial would
// only be folded back into it. Otherwise it discovers and verifies target's
// coordinates via rendezvous (so the edge it opens is to the real target,
// BLAKE2b(ed_pub) == target), then opens the edge: a quick direct dial for a publicly
// reachable peer, falling back to a hole-punch for a peer behind NAT. It returns the
// live edge, ErrUnroutable if no candidate could be reached, or ctx.Err() on timeout.
func (n *Node) Connect(ctx context.Context, target kad.ID) (transport.Conn, error) {
	if conn, ok := n.e.Conn(target); ok {
		return conn, nil
	}
	res, err := n.Rendezvous(ctx, target)
	if err != nil {
		return nil, err
	}
	// A short direct attempt: it succeeds at once for a public peer (or IPv6), and
	// fails fast for one behind NAT, where a hole-punch (or relay) is the real path.
	dctx, dcancel := context.WithTimeout(ctx, directDialTimeout)
	conn, err := n.dialAny(dctx, target, res.Addrs)
	dcancel()
	if err == nil {
		return conn, nil
	}
	// Hole-punch — unless our own NAT is symmetric, which no single predicted address
	// can punch, so we go straight to a relay. Like dialContact, keep the most
	// meaningful cause as the cascade falls through: ErrUnsupported (no Puncher) leaves
	// the direct dial's error in place rather than masking it.
	if !n.reflexive.Symmetric() {
		conn, perr := n.HolePunch(ctx, target, res.Addrs)
		if perr == nil {
			return conn, nil
		}
		if !errors.Is(perr, ErrUnsupported) {
			err = perr
		}
	}
	// A spent deadline surfaces as such — the doc promises ctx.Err() on timeout, and a
	// relay attempt on a dead context could only fail more confusingly.
	if cerr := ctx.Err(); cerr != nil {
		return nil, cerr
	}
	// Relay (last resort): tunnel through a volunteer we have an edge to. With no
	// volunteer, return the cascade's last meaningful error (the direct dial's, or the
	// punch's — e.g. ErrPoWUnmet from register), not a blanket ErrUnroutable.
	if relay, ok := n.pickRelay(target); ok {
		return n.requestRelay(ctx, target, relay)
	}
	return nil, err
}

// OpenMedia opens a media session to target — the foundation of a call. The
// session rides the path of the live overlay edge to target: if one is up, its
// observed address is dialed directly (same socket, same 4-tuple, the NAT
// mapping already proven); otherwise the full Connect cascade runs first
// (rendezvous → direct dial / hole-punch / relay) and the session follows the
// edge it established. The session is OWNED BY THE CALLER: close it when the
// call ends; its life never touches the edge tables. Re-establishing after
// path death (ErrMediaClosed) is a fresh OpenMedia. Several sessions to one
// peer are legal — open a second over a better path, switch, close the old
// one (make-before-break).
//
// It returns ErrUnsupported if the transport has no media capability,
// transport.ErrMediaUnsupported if the PEER has none (the edge keeps working —
// fall back to overlay messaging), or the Connect cascade's error when no path
// exists. A media dial that fails toward a live edge's own address is treated
// as a liveness signal about that edge: the edge is pinged out of schedule, so
// a dead path is reaped and re-dialed instead of being trusted again.
func (n *Node) OpenMedia(ctx context.Context, target kad.ID) (transport.MediaSession, error) {
	media, ok := n.t.(transport.Media)
	if !ok {
		return nil, ErrUnsupported
	}
	conn, ok := n.e.Conn(target)
	if !ok {
		var err error
		if conn, err = n.Connect(ctx, target); err != nil {
			// Simultaneous connect: the peer's own dial may have landed while
			// ours was in flight — any live edge serves (see SendDirect).
			if conn, ok = n.e.Conn(target); !ok {
				return nil, err
			}
		}
	}
	sess, err := media.OpenMedia(ctx, target, conn.RemoteAddr())
	if err != nil {
		// The anti-zombie coupling: the edge's table entry said this address
		// is alive, the media dial says otherwise. Ping the edge NOW (not at
		// the next keepalive tick): a dead conn fails the send and is dropped
		// on the spot, so the next attempt re-runs the Connect cascade instead
		// of trusting a zombie. A peer that merely lacks media support, or a
		// dial the caller cancelled, says nothing about the edge.
		if !errors.Is(err, transport.ErrMediaUnsupported) && ctx.Err() == nil {
			n.ping(conn)
		}
		return nil, err
	}
	n.watchMedia(sess, nil)
	return sess, nil
}

// InboundMedia is the stream of inbound media sessions that passed the
// admission gates: PoW, the session caps, and the application's consent
// callback (WithMediaConsent — without it everything is refused). The
// application owns each session it takes and must Close it. The channel
// drains shut when the node's Run ends (on a transport without media it never
// yields and never closes).
func (n *Node) InboundMedia() <-chan transport.MediaSession { return n.mediaIn }

// mediaGate is the inbound-call admission goroutine: it consumes the
// transport's raw inbound sessions, applies the gates, and hands survivors to
// the application. On shutdown it closes whatever the application left
// unclaimed — so no session's goroutines outlive the node's run — and then
// closes the application's channel (it is the sole writer), so a consumer
// ranging InboundMedia unblocks when the node stops.
func (n *Node) mediaGate(ctx context.Context, media transport.Media) {
	defer func() {
		n.drainMediaIn()
		close(n.mediaIn)
	}()
	in := media.InboundMedia()
	for {
		select {
		case <-ctx.Done():
			return
		case s, ok := <-in:
			if !ok {
				return
			}
			n.admitMedia(s)
		}
	}
}

// admitMedia runs one inbound session through the admission gates and either
// announces it to the application or closes it, counting why.
func (n *Node) admitMedia(s transport.MediaSession) {
	// level-2 admission-PoW: an inbound media connection is a NEW admission
	// point; without the check a call would be a way around the Sybil speed
	// bump every edge pays.
	if !n.admit(s.Remote()) {
		n.stats.mediaSubPoW.Add(1)
		_ = s.Close()
		return
	}
	// level-2 session caps (per node and per authenticated peer identity): bound
	// what a flood of PoW-valid identities can pin — goroutines, pooled buffers, the
	// consent callback's attention. Reserved before consent so a flood cannot spam
	// the application's callback either. The per-peer key is the NodeID, not the
	// transport IP, so many distinct peers reaching us through one relay (sharing its
	// IP) are not collapsed into a single per-relay cap.
	peer := s.Remote().String()
	if !n.mediaSlots.reserve(peer) {
		n.stats.mediaCap.Add(1)
		_ = s.Close()
		return
	}
	// The watcher releases the slot when the session ends, however it ends.
	n.watchMedia(s, func() { n.mediaSlots.release(peer) })
	// level-2 consent: nil gate = refuse all, secure by default.
	if n.mediaConsent == nil || !n.mediaConsent(s.Remote()) {
		n.stats.mediaConsent.Add(1)
		_ = s.Close()
		return
	}
	select {
	case n.mediaIn <- s:
	default:
		// The application is not consuming admitted sessions; refuse rather
		// than queue unboundedly (bounded queues everywhere).
		n.stats.mediaCap.Add(1)
		_ = s.Close()
	}
}

// drainMediaIn closes admitted sessions the application never claimed, run at
// shutdown so their goroutines unwind with the node.
func (n *Node) drainMediaIn() {
	for {
		select {
		case s := <-n.mediaIn:
			_ = s.Close()
		default:
			return
		}
	}
}

// watchMedia couples one session's end to the overlay's liveness: when the
// session dies — the application closed it, the peer did, or the path idled
// out — the watcher runs release (an inbound session's admission slot; nil for
// an outbound one) and pings the overlay edge on the same path out of
// schedule. An idle-death is the strongest available hint that the edge's NAT
// path is dead too: the ping either proves the edge alive (a pong refreshes
// it) or fails/times out into the reap path, so the next Connect builds a
// fresh path instead of returning a zombie edge. After a deliberate local
// close the ping is one spare frame on a healthy edge — harmless.
func (n *Node) watchMedia(s transport.MediaSession, release func()) {
	go func() {
		<-s.Closed()
		if release != nil {
			release()
		}
		if conn, ok := n.e.Conn(s.Remote()); ok {
			n.ping(conn)
		}
	}()
}

// pickRelay finds a CanRelay volunteer this node has a live edge to (so the relay can
// reach both this node and, over its own edge, the callee). It returns the relay's
// NodeID and whether one was found.
func (n *Node) pickRelay(target kad.ID) (kad.ID, bool) {
	n.relayBufMu.Lock()
	defer n.relayBufMu.Unlock()
	// Reuse the snapshot buffer instead of allocating one per call. The snapshot is
	// taken under the edges lock (released inside Conns), then knowledge.Get runs
	// outside it — keeping the edges→knowledge lock order the rest of the node uses.
	n.relayBuf = n.e.Conns(n.relayBuf[:0])
	for _, le := range n.relayBuf {
		if le.ID == target {
			continue
		}
		if c, ok := n.k.Get(le.ID); ok && c.Caps.Has(routing.CanRelay) {
			return le.ID, true
		}
	}
	return kad.ID{}, false
}

// requestRelayRaw asks relayID to splice a tunnel to target, then dials target through
// the allocation the relay grants and returns the raw edge without registering it. The
// resulting edge is a normal authenticated QUIC connection (to target's NodeID, not the
// relay's); the relay only forwards ciphertext.
func (n *Node) requestRelayRaw(ctx context.Context, target, relayID kad.ID) (transport.Conn, error) {
	relayConn, ok := n.e.Conn(relayID)
	if !ok {
		return nil, ErrUnroutable
	}
	var nonce [nat.NonceLen]byte
	if _, err := io.ReadFull(n.rand, nonce[:]); err != nil {
		return nil, err
	}
	ch := make(chan transport.Addr, 1)
	n.relayMu.Lock()
	n.relayPending[nonce] = ch
	n.relayMu.Unlock()
	defer func() {
		n.relayMu.Lock()
		delete(n.relayPending, nonce)
		n.relayMu.Unlock()
	}()

	n.sendFrame(relayConn, func(dst []byte) (int, error) {
		return nat.EncodeRelayRequestFrame(dst, nonce, target)
	})

	select {
	case allocAddr := <-ch:
		return n.dialAnyRaw(ctx, target, []transport.Addr{allocAddr})
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// requestRelay tunnels through relayID to target and registers the resulting edge as an
// outgoing live edge (after the admission-PoW check).
func (n *Node) requestRelay(ctx context.Context, target, relayID kad.ID) (transport.Conn, error) {
	conn, err := n.requestRelayRaw(ctx, target, relayID)
	if err != nil {
		return nil, err
	}
	return n.register(conn, 0, time.Now())
}

// dialContact opens an outgoing edge to a known knowledge contact for the maintenance
// dialer, escalating Direct → Punch → Relay until one path connects — the same cascade
// node.Connect runs on demand, but driven autonomously under churn and without a
// rendezvous round-trip (the contact and its address are already known). The contact's
// capabilities cap the escalation (strategyForCaps): a public anchor is dialed directly
// only, any other contact may fall through to punch and relay. It returns the raw
// (unregistered) edge; the maintenance loop owns the edge-table write, so the winner is
// registered there with the contact's capabilities. The transport's lack of
// Puncher/Relayer (the in-memory one) makes the punch/relay stages no-ops, degrading
// cleanly to a direct dial.
func (n *Node) dialContact(ctx context.Context, task dialTask) (transport.Conn, error) {
	strategy := strategyForCaps(task.caps)
	// Direct: patient for a public anchor (it should answer), fail-fast for a NAT peer
	// that will not, so the cascade reaches the punch quickly.
	ddl := n.maintenance.DialTimeout
	if strategy >= nat.Punch {
		ddl = directDialTimeout
	}
	dctx, cancel := context.WithTimeout(ctx, ddl)
	conn, err := n.t.Dial(dctx, task.id, task.addr)
	cancel()
	if err == nil {
		return conn, nil
	}
	if strategy < nat.Punch {
		return nil, err
	}

	hints := []transport.Addr{task.addr}
	// Punch — unless our own NAT is symmetric, which no single predicted address can
	// punch, so we skip straight to relay. ErrUnsupported (no Puncher) leaves the direct
	// error in place rather than masking it.
	if !n.reflexive.Symmetric() {
		pctx, pcancel := context.WithTimeout(ctx, punchTimeout)
		conn, perr := n.holePunchRaw(pctx, task.id, hints)
		pcancel()
		if perr == nil {
			return conn, nil
		}
		if !errors.Is(perr, ErrUnsupported) {
			err = perr
		}
	}
	if strategy < nat.Relay {
		return nil, err
	}

	// Relay (last resort): tunnel through a volunteer we have an edge to.
	if relay, ok := n.pickRelay(task.id); ok {
		rctx, rcancel := context.WithTimeout(ctx, relayTimeout)
		conn, rerr := n.requestRelayRaw(rctx, task.id, relay)
		rcancel()
		if rerr == nil {
			return conn, nil
		}
		err = rerr
	}
	return nil, err
}

// handleRelayRequest serves a relay request over conn (R side): if this node is a relay
// volunteer and has an edge to the callee, it allocates a spliced session and tells the
// requester where to dial (a grant) and the callee where to register (a bind). The
// session reclaims itself when idle, so there is nothing to track here.
func (n *Node) handleRelayRequest(conn transport.Conn, payload []byte) {
	if !n.canRelay {
		return
	}
	relayer, ok := n.t.(transport.Relayer)
	if !ok {
		return
	}
	nonce, target, err := nat.DecodeRelayRequest(payload)
	if err != nil {
		return
	}
	calleeConn, ok := n.e.Conn(target)
	if !ok {
		return // cannot reach the callee to bind it
	}
	callerAddr, calleeAddr, _, err := relayer.AllocateRelay()
	if err != nil {
		return
	}
	n.sendFrame(conn, func(dst []byte) (int, error) {
		return nat.EncodeRelayGrantFrame(dst, nonce, callerAddr)
	})
	n.sendFrame(calleeConn, func(dst []byte) (int, error) {
		return nat.EncodeRelayBindFrame(dst, calleeAddr)
	})
}

// handleRelayGrant matches a grant to the relay request this node is awaiting and hands
// the allocation address to the waiting requestRelay caller.
func (n *Node) handleRelayGrant(payload []byte) {
	nonce, addr, err := nat.DecodeRelayGrant(payload)
	if err != nil {
		return
	}
	n.relayMu.Lock()
	ch, ok := n.relayPending[nonce]
	n.relayMu.Unlock()
	if !ok {
		return
	}
	select {
	case ch <- addr:
	default:
	}
}

// handleRelayBind tells this node (the callee) where the relay expects it: it punches
// toward the allocation address to register with the relay and open its NAT mapping, so
// the relayed connection's handshake gets through. The inbound edge then surfaces
// normally over Inbound.
func (n *Node) handleRelayBind(payload []byte) {
	addr, err := nat.DecodeRelayBind(payload)
	if err != nil {
		return
	}
	if puncher, ok := n.t.(transport.Puncher); ok {
		n.punchAsync(puncher, []transport.Addr{addr})
	}
}

// sendFrame encodes a control frame with enc into a pooled packet and sends it on conn
// (borrow-Send; we Release). Best-effort: a dead edge is the maintenance loop's problem.
func (n *Node) sendFrame(conn transport.Conn, enc func([]byte) (int, error)) {
	p := transport.Get()
	defer p.Release()
	w, err := enc(p.Buf())
	if err != nil {
		return
	}
	p.SetLen(w)
	_ = conn.Send(p)
}

// handleConnect answers a hole-punch request that reached us: route a ConnectAck back
// with our own coordinates, and punch toward the initiator's candidates so its dial
// gets through our NAT. It runs on the dispatch goroutine, so the punching (which
// sleeps between datagrams) is offloaded to its own goroutine.
func (n *Node) handleConnect(originator kad.ID, payload []byte) {
	c, err := nat.DecodeConnect(payload)
	if err != nil {
		return
	}
	ack := nat.Connect{Nonce: c.Nonce, Addrs: n.coords()}
	out, err := nat.MarshalConnect(&ack)
	if err != nil {
		return
	}
	_ = n.originate(originator, nat.TypeConnectAck, out)

	if puncher, ok := n.t.(transport.Puncher); ok {
		n.punchAsync(puncher, c.Addrs)
	}
}

// handleConnectAck matches an ack to the hole-punch this node is awaiting and hands the
// peer's candidates to the waiting HolePunch caller. Non-blocking: an ack with no
// matching pending nonce (unknown or already-answered) is dropped.
func (n *Node) handleConnectAck(payload []byte) {
	ack, err := nat.DecodeConnect(payload)
	if err != nil {
		return
	}
	n.punchMu.Lock()
	ch, ok := n.punchPending[ack.Nonce]
	n.punchMu.Unlock()
	if !ok {
		return
	}
	select {
	case ch <- ack:
	default:
	}
}

// punchAsync fires a punch burst in the background, bounded by punchSem so a flood of
// inbound Connect/RelayBind frames cannot spawn unbounded punch goroutines or make this
// node a high-volume reflector. When the cap is reached the punch is dropped — best-effort,
// the peer retries or falls back to relay. The burst watches runCtx so it stops at
// shutdown.
func (n *Node) punchAsync(p transport.Puncher, addrs []transport.Addr) {
	select {
	case n.punchSem <- struct{}{}:
		go func() {
			defer func() { <-n.punchSem }()
			n.burstPunch(n.runCtx, p, addrs)
		}()
	default: // at the concurrency cap: drop this punch
	}
}

// burstPunch fires punchBurst datagrams at each candidate, spaced out so the mapping is
// opened and kept fresh across the window the peer's handshake needs — but not after
// the LAST volley: in holePunchRaw the burst runs synchronously before the dial, so a
// trailing sleep would be dead latency on the connection-establishment path. Best-effort:
// a dead candidate just fails to punch. It honours ctx so a burst spawned in response to
// an inbound frame stops at node shutdown instead of outliving the loop.
func (n *Node) burstPunch(ctx context.Context, p transport.Puncher, addrs []transport.Addr) {
	addrs = punchCandidates(addrs)
	for i := range punchBurst {
		for j := range addrs {
			_ = p.PunchTo(addrs[j])
		}
		if i == punchBurst-1 {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(punchSpacing):
		}
	}
}

// dialAnyRaw dials every candidate concurrently and returns the first edge that
// authenticates as target, cancelling the rest; extra winners are closed. Concurrency
// matters because a NAT peer advertises an un-dialable internal address alongside its
// reflexive one, and serial dialing would stall on the dead candidate's handshake
// timeout. It does NOT admit or register the edge — that is the caller's step (register,
// or the maintenance loop), so this is the shared transport-level dial behind every
// outbound path.
func (n *Node) dialAnyRaw(ctx context.Context, target kad.ID, addrs []transport.Addr) (transport.Conn, error) {
	// The list can come from the peer (a ConnectAck's or rendezvous reply's addresses),
	// so dedupe and cap it like a punch burst: one hostile peer must not make this node
	// spawn a dial goroutine (and handshake) per address it cares to list — nor scan a
	// victim's addresses on its behalf. Level-2 self-protection.
	addrs = punchCandidates(addrs)
	if len(addrs) == 0 {
		return nil, ErrUnroutable
	}
	dctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		conn transport.Conn
		err  error
	}
	ch := make(chan result, len(addrs))
	for i := range addrs {
		addr := addrs[i]
		go func() {
			conn, err := n.t.Dial(dctx, target, addr)
			ch <- result{conn, err}
		}()
	}

	var winner transport.Conn
	var lastErr error = ErrUnroutable
	for range addrs {
		r := <-ch
		if r.err != nil {
			lastErr = r.err
			continue
		}
		if winner == nil {
			winner = r.conn
			cancel() // stop the remaining dials
		} else {
			_ = r.conn.Close() // a second candidate also connected; keep one
		}
	}
	if winner == nil {
		return nil, lastErr
	}
	return winner, nil
}

// dialAny dials target's candidates and registers the winner as an outgoing live edge —
// the on-demand outbound path for Connect and the relay/punch wrappers.
func (n *Node) dialAny(ctx context.Context, target kad.ID, addrs []transport.Addr) (transport.Conn, error) {
	conn, err := n.dialAnyRaw(ctx, target, addrs)
	if err != nil {
		return nil, err
	}
	return n.register(conn, 0, time.Now())
}

// register applies the admission-PoW check (level-2), adds the authenticated conn as an
// outgoing live edge tagged with caps (so a public anchor counts toward the floor's
// anchor diversity), and folds the now-reachable peer into knowledge. A duplicate is
// resolved, not failed: if a live edge to the peer already exists — the peer connected
// first, or two sides crossed simultaneous dials — the fresh conn is closed and the
// existing edge returned, since every caller wants "an edge to target", not this
// particular conn. On rejection it closes the conn and returns ErrPoWUnmet
// (sub-threshold peer) or the AddEdge error (self, or the duplicate vanished mid-race).
// It is the single edge-registration site shared by the on-demand Connect path and the
// maintenance dialer.
func (n *Node) register(conn transport.Conn, caps routing.Capability, now time.Time) (transport.Conn, error) {
	target := conn.Remote()
	if !n.admit(target) {
		_ = conn.Close()
		return nil, ErrPoWUnmet
	}
	// Level-3 local policy (WithEdgeAdmission): the application refuses this
	// peer as an edge; the dialed connection is closed, never registered.
	if !n.allowEdge(target) {
		_ = conn.Close()
		n.stats.edgeRefused.Add(1)
		return nil, ErrEdgeRefused
	}
	if err := n.e.AddEdge(conn, true, caps, now); err != nil {
		_ = conn.Close()
		if errors.Is(err, routing.ErrEdgeExists) {
			if existing, ok := n.e.Conn(target); ok {
				return existing, nil
			}
		}
		return nil, err
	}
	// Opportunistic learning: a reached peer is a reachable contact.
	n.observe(routing.Contact{ID: target}, now)
	return conn, nil
}

// otherHops appends every hop except the one at index except into dst and returns it
// as an avoid-set — the disjoint-path siblings a copy must steer around. dst is a
// stack buffer, so this allocates nothing.
func otherHops(dst []byte, hops []routing.LiveEdge, except int) routing.AvoidSet {
	for j := range hops {
		if j != except {
			id := hops[j].ID
			dst = append(dst, id[:]...)
		}
	}
	return routing.AvoidSet(dst)
}

// maintainLoop is the maintenance goroutine for both tables: a single select over a
// few tickers, the dial-result channel, and ctx. Each tick is a no-op when the
// topology is healthy (Normal phase, no idle edges, no probes), so the loop
// re-blocks and a fake-clock test settles. It owns the backoff and pending maps (no
// other goroutine touches them) and delegates blocking dials — fills and eviction
// probes alike — to a small worker pool so a slow dial never stalls keepalive. On
// shutdown it announces a graceful leave.
func (n *Node) maintainLoop(ctx context.Context) {
	m := n.maintenance

	req := make(chan dialTask, m.Dialers)
	res := make(chan dialOutcome, m.Dialers)
	var workers sync.WaitGroup
	for range m.Dialers {
		workers.Go(func() { n.dialWorker(ctx, req, res) })
	}

	tick := time.NewTicker(m.Tick)
	selfLookup := time.NewTicker(m.SelfLookup)
	sibExchange := time.NewTicker(m.SiblingExchange)
	refresh := time.NewTicker(m.BucketRefresh)
	defer tick.Stop()
	defer selfLookup.Stop()
	defer sibExchange.Stop()
	defer refresh.Stop()

	// rng drives the bucket-refresh target choice (a random ID inside the stale
	// bucket's range). Seeded from self so a fake-clock test is deterministic; it
	// guards no secret, so a predictable sequence is fine.
	rng := mrand.New(mrand.NewPCG(
		binary.LittleEndian.Uint64(n.self[0:8]),
		binary.LittleEndian.Uint64(n.self[8:16]),
	))

	backoff := make(map[kad.ID]backoffState)
	pending := make(map[kad.ID]bool) // dials in flight, so we never queue a peer twice

	for {
		select {
		case <-ctx.Done():
			n.gracefulLeave()
			// The workers exit on the same ctx; wait them out, then close any conn
			// still parked in the result buffer — a dial that won its race with
			// shutdown would otherwise leak a live conn nobody registers.
			workers.Wait()
			for {
				select {
				case out := <-res:
					if out.conn != nil {
						_ = out.conn.Close()
					}
				default:
					return
				}
			}
		case <-tick.C:
			now := time.Now()
			n.keepaliveAndReap(now, m)
			pruneBackoff(backoff, now, m)
			n.fill(now, backoff, pending, req)
			n.drainProbes(now, pending, req) // after fill: floor dials outrank probes
		case <-selfLookup.C:
			n.selfLookup()
		case <-sibExchange.C:
			n.siblingExchange()
		case <-refresh.C:
			// Kademlia bucket refresh: look up a random ID inside the most-stale
			// populated bucket's range; the answer folds fresh contacts into exactly
			// the region that has gone quiet — the knowledge table's only proactive
			// upkeep (everything else it learns is opportunistic).
			if target, ok := n.k.RefreshTarget(time.Now(), m.BucketStaleAfter, rng); ok {
				n.lookupTowards(target)
			}
		case out := <-res:
			now := time.Now()
			delete(pending, out.id)
			if out.probe {
				// An eviction probe resolves the table's pending replacement: a dead
				// incumbent is evicted (the stashed newcomer takes its slot), a live
				// one is kept and the newcomer stays in the cache. The probe edge
				// itself is not wanted — fill chooses edges by its own policy.
				if out.err != nil {
					n.k.Confirm(out.id, false, now)
				} else {
					n.k.Confirm(out.id, true, now)
					_ = out.conn.Close()
				}
				continue
			}
			if out.err != nil {
				if bumpBackoff(backoff, out.id, m, now) {
					// Lazy purge: the peer failed the whole backoff horizon, so it is
					// dead for the table's purposes — stop re-dialing it and stop
					// handing it out in lookup answers. If it ever comes back it
					// re-enters through opportunistic learning like any newcomer.
					delete(backoff, out.id)
					n.k.MarkDead(out.id)
				}
				continue
			}
			delete(backoff, out.id)
			// register applies the admission-PoW check and adds the outgoing edge (it
			// closes the conn on rejection — sub-threshold peer, or already an edge).
			_, _ = n.register(out.conn, out.caps, now)
		}
	}
}

// drainProbes turns pending eviction-probe candidates into probe dials, at most
// probesPerTick per tick and only with workers to spare — probing serves table
// hygiene and must never crowd out connectivity-floor fills. A candidate that became
// a live edge meanwhile is confirmed alive for free; one that left the table or has
// no dialable address is dropped (an unverifiable incumbent must NOT be evicted
// blind, or a flood of newcomers could displace old verified contacts — the
// anti-eviction-flooding rule); one with a fill dial already in flight waits for the
// next tick — a failed fill dial only bumps backoff and never resolves the table's
// pending replacement, so the probe itself must still run.
func (n *Node) drainProbes(now time.Time, pending map[kad.ID]bool, req chan<- dialTask) {
	for queued := 0; queued < probesPerTick; {
		id, ok := n.popProbe()
		if !ok {
			return
		}
		if _, live := n.e.Conn(id); live {
			n.k.Confirm(id, true, now)
			continue
		}
		c, ok := n.k.Get(id)
		if !ok || len(c.Addrs) == 0 {
			// An eviction candidate we cannot dial cannot be probed for liveness, so
			// confirm it dead: it is evicted and a freshest fitting (keyed, dialable)
			// newcomer is promoted in its place. Leaving it would pin a bucket slot
			// with an undialable incumbent and starve real replacements.
			n.k.Confirm(id, false, now)
			continue
		}
		if pending[id] {
			n.addProbe(id) // a dial is in flight; retry next tick
			return
		}
		select {
		case req <- dialTask{id: c.ID, addr: c.Addrs[0], caps: c.Caps, probe: true}:
			pending[id] = true
			queued++
		default:
			n.addProbe(id) // workers busy; retry next tick
			return
		}
	}
}

// dialWorker dials the contacts the loop hands it and reports each outcome back. It runs
// the Direct → Punch → Relay cascade (dialContact) so a NAT peer is reached autonomously
// under churn, not just public ones. A blocking dial here never stalls the maintenance
// select; the cascade's per-stage timeouts bound how long a worker is tied up.
func (n *Node) dialWorker(ctx context.Context, req <-chan dialTask, res chan<- dialOutcome) {
	for {
		select {
		case <-ctx.Done():
			return
		case task := <-req:
			conn, err := n.dialContact(ctx, task)
			if ctx.Err() != nil {
				// Shutdown raced the dial. The select below picks at random between a
				// free result buffer and the cancelled ctx, so close a won conn here
				// deterministically (the loop's shutdown drain is the backstop).
				if conn != nil {
					conn.Close()
				}
				return
			}
			select {
			case res <- dialOutcome{id: task.id, conn: conn, caps: task.caps, probe: task.probe, err: err}:
			case <-ctx.Done():
				if conn != nil {
					conn.Close()
				}
				return
			}
		}
	}
}

// fill tops up the live-edge set toward the connectivity floor: it reads the floor
// band, decides how many edges to add this tick, and hands the nearest knowledge
// contacts (not already live, not backing off, with a dialable address) to the dial
// workers. ReplacementFor already biases toward independent subnets.
func (n *Node) fill(now time.Time, backoff map[kad.ID]backoffState, pending map[kad.ID]bool, req chan<- dialTask) {
	want := fillWant(n.e.Status().Phase)
	if want == 0 {
		return
	}
	// Pull extra candidates so peers already pending/backing off can be skipped.
	var cbuf [32]routing.Contact
	cands := n.e.ReplacementFor(n.k, n.self, want+len(pending)+8, cbuf[:0])
	queued := 0
	for i := range cands {
		c := cands[i]
		if pending[c.ID] || len(c.Addrs) == 0 {
			continue
		}
		// The application's edge policy would refuse this peer at register;
		// skip it here so the dial workers never waste a cascade on it.
		if !n.allowEdge(c.ID) {
			continue
		}
		if bs, ok := backoff[c.ID]; ok && now.Before(bs.nextAt) {
			continue
		}
		select {
		case req <- dialTask{id: c.ID, addr: c.Addrs[0], caps: c.Caps}:
			pending[c.ID] = true
			queued++
		default:
			return // workers busy; the next tick tries again
		}
		if queued >= want {
			return
		}
	}
}

// keepaliveAndReap reaps edges that have gone silent past the dead threshold, then
// pings those merely idle past the keepalive threshold. Reaping first means a
// just-removed edge is not also pinged. last-seen only advances on a received frame
// or pong, so an edge that stops answering keeps aging until it crosses the dead
// bound and is dropped — the maintenance-side failure detector that complements the
// transport's own signal.
func (n *Node) keepaliveAndReap(now time.Time, m Maintenance) {
	// Sized for the whole live set — self-maintained edges (~TargetEdges) plus up to
	// InboundCap peer-initiated ones — so the scan never overflows to the heap. The old
	// 2*TargetEdges (128) sat below InboundCap (256).
	var buf [routing.TargetEdges + routing.InboundCap]routing.LiveEdge
	for _, le := range n.e.Idle(now, m.DeadSibling, m.DeadFinger, buf[:0]) {
		n.dropEdge(le.ID)
	}
	for _, le := range n.e.Idle(now, m.KeepaliveSibling, m.KeepaliveFinger, buf[:0]) {
		n.ping(le.Conn)
	}
}

// ping sends a keepalive over conn; a send error means the edge is already gone, so
// it is dropped at once (the transport's own failure signal, faster than the dead
// timeout).
func (n *Node) ping(conn transport.Conn) {
	p := transport.Get()
	defer p.Release()
	w, err := routing.EncodePingFrame(p.Buf())
	if err != nil {
		return
	}
	p.SetLen(w)
	if conn.Send(p) != nil {
		n.dropEdge(conn.Remote())
	}
}

// fanout sends the frame in src to every edge concurrently — each on its own goroutine
// with its own pooled copy of the bytes — so one slow or congested socket never
// serialises the rest. (Each Send is bounded per edge by the transport, but a serial
// loop would still sum those bounds.) Each goroutine Releases its copy once its
// borrow-Send returns and drops the edge on failure — the same fast failure signal used
// elsewhere. src stays the caller's to reuse and Release: the copies are made
// synchronously here, before any goroutine starts.
//
// If wait, fanout blocks until every send completes — for graceful leave, where the
// frames must reach the wire before the node stops. Otherwise it returns once the copies
// are made and lets the sends finish in the background, so a maintenance tick (selfLookup,
// siblingExchange) is never held on the loop goroutine behind a blocking socket.
func (n *Node) fanout(edges []routing.LiveEdge, src *transport.Packet, wait bool) {
	b := src.Bytes()
	var wg sync.WaitGroup
	for _, le := range edges {
		p := transport.Get()
		copy(p.Buf(), b)
		p.SetLen(len(b))
		send := func() {
			defer p.Release()
			// Bounded send: a stalled neighbour must not wedge the fan-out. With wait=true
			// (graceful leave at shutdown) an unbounded Send would hang wg.Wait() forever
			// and Run would never return; the per-send bound caps the whole fan-out.
			if n.forwardSend(le.Conn, p) != nil {
				n.dropEdge(le.ID)
			}
		}
		if wait {
			wg.Go(send)
		} else {
			go send()
		}
	}
	if wait {
		wg.Wait()
	}
}

// lookupTowards originates a lookup toward target over the live edges closest to
// it, with self in the avoid-set so the request never routes home — it terminates
// at the node nearest target, who answers with the contacts around that region;
// the response refills this node's knowledge there. Self-lookup (target = self,
// sibling discovery) and bucket refresh (target = a random ID in a stale bucket's
// range) are the two callers.
func (n *Node) lookupTowards(target kad.ID) {
	var hopBuf [routing.KMin]routing.LiveEdge
	hops := n.e.Closest(target, routing.KMin, hopBuf[:0])
	if len(hops) == 0 {
		return
	}
	// Carry a correlation nonce so the routed neighbours answer can echo it and we accept
	// only an answer to this request we made.
	nonce, ok := n.newLookupNonce()
	if !ok {
		return
	}
	p := transport.Get()
	defer p.Release()
	msg := routing.Msg{Target: target, TTL: routing.MaxHops, EdPub: n.edPub, Avoid: routing.AvoidSet(n.self[:]), Payload: nonce[:]}
	routing.SignMsg(n.id, routing.TypeLookup, &msg, time.Now())
	w, err := routing.EncodeLookupFrame(p.Buf(), &msg)
	if err != nil {
		return
	}
	p.SetLen(w)
	n.fanout(hops, p, false)
}

// selfLookup is the sibling-discovery lookup: toward this node's own ID, so the
// answer carries the contacts around its keyspace, refilling thin sibling
// knowledge under churn.
func (n *Node) selfLookup() { n.lookupTowards(n.self) }

// siblingExchange asks each live sibling for its sibling set; the overlapping
// neighbourhoods of nearby nodes make this a cheap way to learn newcomers and agree
// on the local keyspace (a lean stabilization, not a presence layer). Responses
// arrive as TypeNeighbors and land in the knowledge table.
func (n *Node) siblingExchange() {
	var buf [routing.Siblings]routing.LiveEdge
	sibs := n.e.Siblings(buf[:0])
	if len(sibs) == 0 {
		return
	}
	// One nonce for the fan-out: every sibling echoes it, and the pending entry accepts the
	// several answers it draws (it is not consumed on first match).
	nonce, ok := n.newLookupNonce()
	if !ok {
		return
	}
	p := transport.Get()
	defer p.Release()
	w, err := routing.EncodeSiblingsFrame(p.Buf(), nonce)
	if err != nil {
		return
	}
	p.SetLen(w)
	n.fanout(sibs, p, false)
}

// gracefulLeave tells every live neighbour the node is shutting down, so they drop
// the edge and replace it proactively instead of waiting for a timeout. Best-effort:
// it runs as the node stops, so a failed send (the edge already gone) is ignored.
func (n *Node) gracefulLeave() {
	var buf [routing.TargetEdges + routing.InboundCap]routing.LiveEdge
	conns := n.e.Conns(buf[:0])
	if len(conns) == 0 {
		return
	}
	p := transport.Get()
	defer p.Release()
	w, err := routing.EncodeLeaveFrame(p.Buf())
	if err != nil {
		return
	}
	p.SetLen(w)
	// Fan out so a slow neighbour does not serialise shutdown (latency = max, not sum),
	// but wait: a graceful leave is only useful if the frames reach the wire before the
	// node stops.
	n.fanout(conns, p, true)
}
