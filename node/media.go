package node

import (
	"net"
	"sync"

	"github.com/udisondev/nodenet/transport"
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

	// maxMediaPerIP caps admitted inbound sessions per source IP, so one host
	// cannot hold every slot. Inert on a transport whose endpoints carry no
	// IP (the in-memory one), like the other subnet-keyed caps.
	maxMediaPerIP = 4

	// mediaInBuffer is the depth of the gated inbound-session channel the
	// application reads (Node.InboundMedia). An admitted session the
	// application leaves unclaimed past this is refused like any other
	// overflow — bounded queues everywhere.
	mediaInBuffer = 8
)

// mediaSlots is the bounded accounting of admitted inbound media sessions:
// a node-wide count and a per-host count. Reserve before announcing a session,
// release when it ends; both are cheap and mutex-guarded (the media gate and
// the per-session watchers run on different goroutines).
type mediaSlots struct {
	mu    sync.Mutex
	count int
	perIP map[string]int
}

func newMediaSlots() *mediaSlots {
	return &mediaSlots{perIP: make(map[string]int)}
}

// reserve takes one slot for a session from host (empty host = no per-IP
// accounting, the non-IP-transport case). It reports false — and takes
// nothing — past either cap. level-2 self-protection.
func (m *mediaSlots) reserve(host string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.count >= maxMediaSessions {
		return false
	}
	if host != "" && m.perIP[host] >= maxMediaPerIP {
		return false
	}
	m.count++
	if host != "" {
		m.perIP[host]++
	}
	return true
}

// release returns a reserved slot. Call it exactly once per successful
// reserve, when the session ends.
func (m *mediaSlots) release(host string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.count--
	if host == "" {
		return
	}
	if m.perIP[host] <= 1 {
		delete(m.perIP, host)
	} else {
		m.perIP[host]--
	}
}

// mediaHost extracts the per-IP accounting key from a session's remote
// address: the host part of an ip:port endpoint. ipOnly marks an IP-based
// transport (transport.IPAddressed); on any other transport — or for an
// endpoint that does not parse — the key is empty and the per-IP cap stays
// inert, exactly like the subnet-diversity caps on the in-memory transport.
func mediaHost(addr transport.Addr, ipOnly bool) string {
	if !ipOnly {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.Endpoint)
	if err != nil {
		return ""
	}
	return host
}
