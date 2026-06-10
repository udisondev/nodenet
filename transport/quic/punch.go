package quic

import (
	"net"
	"net/netip"

	"github.com/udisondev/nodenet/transport"
)

var _ transport.Puncher = (*quicTransport)(nil)

// punchMagic is the payload of a NAT-punch datagram. Its first byte has the top two
// bits clear (0x00), which is how quic-go tells a non-QUIC packet from a QUIC one and
// routes it to ReadNonQUICPacket instead of a connection — so a punch shares the QUIC
// socket and 4-tuple without disturbing live connections. The rest is a small fixed
// tag; the content is irrelevant, the datagram's only job is to open the NAT mapping.
var punchMagic = []byte{0x00, 0x6e, 0x70, 0x01} // 0x00, "np", v1

// PunchTo sends one raw punch datagram to addr over the shared QUIC socket. It opens
// this node's NAT mapping toward addr (and, on a restricted NAT, the inbound
// permission for addr) so a coordinated peer's QUIC handshake can get through. It is
// best-effort: a single datagram may be lost, so callers burst a few.
//
// It refuses to punch toward anything that is not a literal, routable unicast IP:port.
// The endpoint is an attacker-influenced string (it rides in a Connect/RelayBind), so it
// is parsed with netip.ParseAddrPort — which accepts ONLY an ip:port literal and does NO
// DNS — closing two hazards at once: a hostname would otherwise trigger a DNS lookup to
// an attacker-chosen name (and resolve to an attacker-chosen IP), and a non-unicast
// address (loopback, multicast, broadcast, unspecified, link-local) would make this node
// a reflector toward local services or a broadcast amplifier. Level-2 self-protection.
// Public and private unicast — the legitimate hole-punch candidates, including same-LAN
// ones — are allowed.
func (t *quicTransport) PunchTo(addr transport.Addr) error {
	ap, ok := punchTarget(addr.Endpoint)
	if !ok {
		return transport.ErrNoRoute
	}
	if _, err := t.tr.WriteTo(punchMagic, net.UDPAddrFromAddrPort(ap)); err != nil {
		return transport.ErrConnClosed
	}
	return nil
}

// punchTarget parses endpoint as a literal ip:port (no DNS) and reports whether it is a
// punchable destination. ok is false for a hostname, a malformed string, or a
// non-routable-unicast IP.
func punchTarget(endpoint string) (netip.AddrPort, bool) {
	ap, err := netip.ParseAddrPort(endpoint)
	if err != nil {
		return netip.AddrPort{}, false
	}
	return ap, punchable(ap.Addr())
}

// punchable reports whether ip is a routable unicast host. It allows global and private
// unicast (the real hole-punch candidates) and rejects loopback, multicast, the IPv4
// limited broadcast, the unspecified address, and link-local. netip.Addr.IsGlobalUnicast
// already returns true for private addresses and false for loopback, multicast, the
// unspecified address, link-local unicast and the IPv4 limited broadcast; the explicit
// link-local and broadcast checks restate the two exclusions the reflector hazard hinges
// on, so they hold even if the stdlib predicate changes.
func punchable(ip netip.Addr) bool {
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsLinkLocalUnicast() {
		return false
	}
	return !(ip.Is4() && ip.As4() == [4]byte{255, 255, 255, 255})
}

// punchDrainLoop reads and discards inbound non-QUIC (punch) datagrams so quic-go's
// small non-QUIC queue cannot fill and back-pressure. The punches have already done
// their job at the NAT by the time they arrive here; their content is not needed. It
// exits when the transport's context is cancelled (Close).
func (t *quicTransport) punchDrainLoop() {
	defer t.wg.Done()
	buf := make([]byte, len(punchMagic)+64)
	for {
		if _, _, err := t.tr.ReadNonQUICPacket(t.ctx, buf); err != nil {
			return // context cancelled or transport closed
		}
	}
}
