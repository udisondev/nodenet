package mem

import (
	"bytes"
	"fmt"
	"sync"
	"time"

	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/transport"
)

// defaultInbound is the inbound channel capacity a Hub gives each transport. A
// small buffer lets a test Send then read on one goroutine without deadlock and
// bounds how far a fast sender runs ahead of a slow receiver (backpressure).
const defaultInbound = 16

// Hub is the shared in-memory fabric N transports attach to — the stand-in for
// "the network". It resolves Dial targets and is safe for concurrent use. It has
// no dependence on wall-clock or real I/O.
type Hub struct {
	mu        sync.Mutex
	byID      map[kad.ID]*memTransport
	byAddr    map[transport.Addr]*memTransport
	inbuf     int
	sendBound time.Duration            // >0 caps a blocked deliver (mirrors QUIC's send deadline); 0 = unbounded
	blocked   map[[2]kad.ID]bool       // partitioned NodeID pairs; traffic between them is blackholed
	links     map[[2]kad.ID]*linkModel // DIRECTED media link models, keyed (from, to)
	noMedia   map[kad.ID]bool          // nodes flagged as not supporting media (older peers)
}

// HubOption configures a Hub at construction.
type HubOption func(*Hub)

// WithInboundBuffer sets the inbound channel capacity each transport on the Hub
// gets. The default is 16. Zero makes inbound unbuffered, so every Send blocks
// until a receiver takes the frame.
func WithInboundBuffer(n int) HubOption {
	return func(h *Hub) { h.inbuf = n }
}

// WithSendBound caps how long a Send may block on a backpressured (full,
// undrained) inbound channel before it returns ErrConnClosed, mirroring the QUIC
// transport's send deadline so a stalled neighbour cannot wedge a sender forever.
// The default is 0 (unbounded — the historical behaviour). Under testing/synctest
// the bound runs on the fake clock, so it stays deterministic. The fast path (room
// in the channel) never arms a timer, so a set bound costs nothing when traffic flows.
func WithSendBound(d time.Duration) HubOption {
	return func(h *Hub) { h.sendBound = d }
}

// NewHub creates an empty Hub.
func NewHub(opts ...HubOption) *Hub {
	h := &Hub{
		byID:    make(map[kad.ID]*memTransport),
		byAddr:  make(map[transport.Addr]*memTransport),
		inbuf:   defaultInbound,
		blocked: make(map[[2]kad.ID]bool),
		links:   make(map[[2]kad.ID]*linkModel),
		noMedia: make(map[kad.ID]bool),
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// New creates a transport bound to id and reachable at addr, registered with the
// Hub. It is the per-node constructor a test calls once per node. It returns an
// error if id or addr is already registered.
func (h *Hub) New(id kad.ID, addr transport.Addr) (transport.Transport, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.byAddr[addr]; ok {
		return nil, fmt.Errorf("mem: addr %s already registered", addr)
	}
	if _, ok := h.byID[id]; ok {
		return nil, fmt.Errorf("mem: id %s already registered", id)
	}
	t := &memTransport{
		hub:     h,
		id:      id,
		addr:    addr,
		in:      make(chan transport.Delivery, h.inbuf),
		inMedia: make(chan transport.MediaSession, inMediaBuffer),
		done:    make(chan struct{}),
	}
	h.byID[id] = t
	h.byAddr[addr] = t
	return t, nil
}

// lookup resolves a dial target by address.
func (h *Hub) lookup(addr transport.Addr) (*memTransport, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	t, ok := h.byAddr[addr]
	return t, ok
}

// remove deregisters a transport (called from its Close), so a later Dial to its
// address returns ErrNoRoute. It also drops every per-node soft state the Hub holds
// for the departing identity — partitions, directed link profiles, the media-support
// flag — so a re-registration of the same NodeID starts from a clean slate instead of
// silently inheriting a dead node's partition or link model. remove runs only on
// Close, so the linear scans of the (small) partition/link maps are off any hot path.
func (h *Hub) remove(t *memTransport) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.byID, t.id)
	delete(h.byAddr, t.addr)
	delete(h.noMedia, t.id)
	for k := range h.blocked {
		if k[0] == t.id || k[1] == t.id {
			delete(h.blocked, k)
		}
	}
	for k := range h.links {
		if k[0] == t.id || k[1] == t.id {
			delete(h.links, k)
		}
	}
}

// Partition blackholes all communication between NodeIDs a and b in BOTH
// directions — the in-memory stand-in for a network partition: existing edges stay
// objects but any frame Sent between them is silently dropped, and a fresh Dial
// between them fails with ErrNoRoute (a real partition breaks the handshake too).
// It is the churn primitive the cluster harness uses to test topology recovery (a
// partition that later Heals, an edge that goes dark so keepalive must detect it
// dead). Deterministic: nothing is timed or random. Call Heal to restore the link.
func (h *Hub) Partition(a, b kad.ID) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.blocked[pairKey(a, b)] = true
}

// Heal removes a partition between a and b, restoring delivery between them.
func (h *Hub) Heal(a, b kad.ID) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.blocked, pairKey(a, b))
}

// isBlocked reports whether traffic between sender and receiver is partitioned. It
// is consulted on every Send; with no active partition the map is empty, so the
// check is a single lock and a miss.
func (h *Hub) isBlocked(sender, receiver kad.ID) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.blocked[pairKey(sender, receiver)]
}

// SetLinkProfile installs the media link model for the DIRECTED path from →
// to: every media datagram travelling that direction runs through it (loss,
// jitter, reorder, shaper queue, MTU), while the reverse direction and all
// overlay frames stay untouched. Deterministic: the model draws from a PRNG
// seeded with the profile's Seed and all delays run on the test's clock.
// Calling it again replaces the model (fresh PRNG and shaper state).
func (h *Hub) SetLinkProfile(from, to kad.ID, p LinkProfile) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.links[[2]kad.ID{from, to}] = newLinkModel(p)
}

// link returns the media link model for the directed path, or nil for an
// ideal (unmodelled) link. Consulted by session pumps per datagram.
func (h *Hub) link(from, to kad.ID) *linkModel {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.links[[2]kad.ID{from, to}]
}

// SetMediaSupport flags whether the node registered as id supports media
// sessions; the default is supported. An OpenMedia toward a flagged-off peer
// fails with ErrMediaUnsupported — the deterministic stand-in for an older
// node that does not speak the media protocol, whose overlay edges keep
// working untouched.
func (h *Hub) SetMediaSupport(id kad.ID, supported bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if supported {
		delete(h.noMedia, id)
		return
	}
	h.noMedia[id] = true
}

// mediaSupported reports whether the node registered as id accepts media.
func (h *Hub) mediaSupported(id kad.ID) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return !h.noMedia[id]
}

// pairKey normalises an unordered NodeID pair into a comparable map key, so a
// partition blocks both directions with one entry.
func pairKey(a, b kad.ID) [2]kad.ID {
	if bytes.Compare(a[:], b[:]) <= 0 {
		return [2]kad.ID{a, b}
	}
	return [2]kad.ID{b, a}
}
