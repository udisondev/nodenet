package mem

import (
	"bytes"
	"fmt"
	"sync"

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
	mu      sync.Mutex
	byID    map[kad.ID]*memTransport
	byAddr  map[transport.Addr]*memTransport
	inbuf   int
	blocked map[[2]kad.ID]bool // partitioned NodeID pairs; traffic between them is blackholed
}

// HubOption configures a Hub at construction.
type HubOption func(*Hub)

// WithInboundBuffer sets the inbound channel capacity each transport on the Hub
// gets. The default is 16. Zero makes inbound unbuffered, so every Send blocks
// until a receiver takes the frame.
func WithInboundBuffer(n int) HubOption {
	return func(h *Hub) { h.inbuf = n }
}

// NewHub creates an empty Hub.
func NewHub(opts ...HubOption) *Hub {
	h := &Hub{
		byID:    make(map[kad.ID]*memTransport),
		byAddr:  make(map[transport.Addr]*memTransport),
		inbuf:   defaultInbound,
		blocked: make(map[[2]kad.ID]bool),
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
		hub:  h,
		id:   id,
		addr: addr,
		in:   make(chan transport.Delivery, h.inbuf),
		done: make(chan struct{}),
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
// address returns ErrNoRoute.
func (h *Hub) remove(t *memTransport) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.byID, t.id)
	delete(h.byAddr, t.addr)
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

// pairKey normalises an unordered NodeID pair into a comparable map key, so a
// partition blocks both directions with one entry.
func pairKey(a, b kad.ID) [2]kad.ID {
	if bytes.Compare(a[:], b[:]) <= 0 {
		return [2]kad.ID{a, b}
	}
	return [2]kad.ID{b, a}
}
