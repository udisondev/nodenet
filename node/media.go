package node

import (
	"sync"
)

// Media-session admission policy. The session itself is transport business
// (transport.MediaSession); what lives here is the node's gate in front of
// inbound sessions — the same three-layer stance as everywhere else: an
// inbound media connection is a NEW admission point, so it pays the same
// admission proof-of-work as an edge (level-2 — without it a call would be a
// way around the Sybil speed bump), the application must consent to it
// explicitly (level-2, secure by default: no consent gate means refuse all),
// and the session caps bound what a flood of PoW-valid identities can pin
// (level-2; the numbers are tunable).
const (
	// maxMediaSessions caps concurrently-admitted INBOUND media sessions.
	// Outbound sessions are this node's own doing and are not capped here.
	maxMediaSessions = 16

	// maxMediaPerPeer caps admitted inbound sessions per authenticated source
	// identity (NodeID), so one peer cannot hold every slot. Keying on the NodeID
	// rather than the transport IP keeps the cap meaningful when many distinct
	// peers reach this node through one relay (they share the relay's IP but not
	// their NodeID) — a per-IP key would there collapse into a per-relay cap.
	maxMediaPerPeer = 4

	// mediaInBuffer is the depth of the gated inbound-session channel the
	// application reads (Node.InboundMedia). An admitted session the
	// application leaves unclaimed past this is refused like any other
	// overflow — bounded queues everywhere.
	mediaInBuffer = 8
)

// mediaSlots is the bounded accounting of admitted inbound media sessions:
// a node-wide count and a per-identity count. Reserve before announcing a session,
// release when it ends; both are cheap and mutex-guarded (the media gate and
// the per-session watchers run on different goroutines).
type mediaSlots struct {
	mu      sync.Mutex
	count   int
	perPeer map[string]int // keyed by the authenticated NodeID, not the transport IP
}

func newMediaSlots() *mediaSlots {
	return &mediaSlots{perPeer: make(map[string]int)}
}

// reserve takes one slot for a session from peer (the authenticated NodeID key; an
// empty key disables per-peer accounting). It reports false — and takes nothing —
// past either cap. level-2 self-protection.
func (m *mediaSlots) reserve(peer string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.count >= maxMediaSessions {
		return false
	}
	if peer != "" && m.perPeer[peer] >= maxMediaPerPeer {
		return false
	}
	m.count++
	if peer != "" {
		m.perPeer[peer]++
	}
	return true
}

// release returns a reserved slot. Call it exactly once per successful
// reserve, when the session ends.
func (m *mediaSlots) release(peer string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.count--
	if peer == "" {
		return
	}
	if m.perPeer[peer] <= 1 {
		delete(m.perPeer, peer)
	} else {
		m.perPeer[peer]--
	}
}
