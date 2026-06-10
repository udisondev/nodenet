// Package nattest is an in-process NAT emulator for deterministic hole-punching and
// relay tests. transport/mem cannot model NAT (it has no addresses and no firewall),
// so these tests run the real QUIC transport over a fake net.PacketConn instead of a
// real UDP socket: quic.Transport.Conn is a net.PacketConn, so a NAT-emulating one
// drops in unchanged (quic.ListenPacketConn is the seam).
//
// A Fabric is the shared "internet": a switch that routes datagrams between endpoints
// by address, with no real sockets. An endpoint is either Public (a fixed, directly
// reachable address — an entry point, coordinator, or relay) or BehindNAT (an
// internal address fronted by a NAT box that rewrites the source on the way out and
// filters inbound on the way in). The NAT's two axes match the STUN taxonomy:
//
//   - Mapping: does the external port depend only on the internal endpoint
//     (Independent — a cone NAT, punchable) or also on the destination (Dependent —
//     a symmetric NAT, whose per-destination port defeats a single predicted address)?
//   - Filter: which inbound senders a mapping admits — anyone (FullCone), any IP we
//     have sent to (AddrRestricted), or only the exact IP:port we have sent to
//     (AddrPortRestricted).
//
// Mappings idle out after TTL (0 = never), which is how the keepalive tests show that
// traffic keeps a NAT hole open. Everything is real-time (real QUIC runs underneath),
// so these tests live behind a build tag and run less often than the synctest suite.
package nattest

import (
	"net"
	"time"
)

// Mapping is how a NAT chooses the external port for an outbound flow.
type Mapping uint8

const (
	// Independent reuses one external port for all destinations (cone NAT): the
	// reflexive address a node learns from one peer is valid for every peer, so
	// hole-punching works.
	Independent Mapping = iota
	// Dependent allocates a fresh external port per destination (symmetric NAT): the
	// reflexive address learned from one peer is wrong for another, so a single
	// predicted address cannot be punched and the pair must relay.
	Dependent
)

// Filter is which inbound senders a NAT mapping admits.
type Filter uint8

const (
	// FullCone admits any sender once the mapping exists.
	FullCone Filter = iota
	// AddrRestricted admits a sender whose IP the node has sent to through the mapping.
	AddrRestricted
	// AddrPortRestricted admits only the exact IP:port the node has sent to.
	AddrPortRestricted
)

// NAT configures a NAT box fronting an internal endpoint.
type NAT struct {
	ExtIP   string        // external IP the NAT presents, e.g. "200.0.0.1"
	Mapping Mapping       // port-allocation behaviour
	Filter  Filter        // inbound admission behaviour
	TTL     time.Duration // mapping idle lifetime; 0 = never expires
}

// RestrictedConeNAT is the common punchable case: one external port for all peers,
// admitting only addresses the node has sent to.
func RestrictedConeNAT(extIP string) NAT {
	return NAT{ExtIP: extIP, Mapping: Independent, Filter: AddrPortRestricted}
}

// SymmetricNAT is the unpunchable case: a fresh external port per destination, so a
// reflexive address learned from one peer does not apply to another.
func SymmetricNAT(extIP string) NAT {
	return NAT{ExtIP: extIP, Mapping: Dependent, Filter: AddrPortRestricted}
}

// timeoutError is a net.Error reporting a read deadline elapsed; quic-go treats a
// Timeout()==true error as recoverable rather than a dead socket.
type timeoutError struct{}

func (timeoutError) Error() string   { return "nattest: i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

var _ net.Error = timeoutError{}

// resolveUDP parses a "host:port" into a *net.UDPAddr, propagating the error (no
// Must-style panic: Fabric's constructors return it to the caller).
func resolveUDP(addr string) (*net.UDPAddr, error) { return net.ResolveUDPAddr("udp", addr) }
