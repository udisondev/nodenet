package routing

import (
	"net/netip"

	"github.com/udisondev/nodenet/transport"
)

// Subnet is an opaque, comparable, allocation-free subnet identifier: a masked
// /24 (IPv4) or /64 (IPv6) prefix. Sixteen bytes hold either — a v4 prefix in its
// IPv4-in-IPv6 form, a v6 prefix masked to its high 64 bits — so the two never
// collide and a Subnet can key a map directly. The zero Subnet means "no subnet"
// and is paired with ok == false from a SubnetFunc.
type Subnet [16]byte

// SubnetFunc derives the diversity key of a transport address. ok == false means
// the address carries no usable subnet (a hostname, or the in-memory transport's
// hub name), in which case the diversity caps simply do not apply to it. It is
// injected because transport.Addr is opaque to the overlay: the node layer knows
// the address formats and wires the right derivation (SubnetFromHostPort for real
// addresses, NoSubnet for deterministic tests).
type SubnetFunc func(transport.Addr) (Subnet, bool)

// SubnetFromHostPort derives a /24 or /64 subnet key from an addr whose Endpoint
// is a "host:port" string with a literal IP (the QUIC transport's form). It is
// the one untrusted-input decoder in this package — it parses an
// externally-influenced string — so it never panics: anything it cannot parse as
// an ip:port, including a hostname, yields ok == false.
func SubnetFromHostPort(addr transport.Addr) (Subnet, bool) {
	ap, err := netip.ParseAddrPort(addr.Endpoint)
	if err != nil {
		return Subnet{}, false
	}
	ip := ap.Addr()
	switch {
	case ip.Is4(), ip.Is4In6():
		b := ip.As16() // ::ffff:a.b.c.d — distinct from any native v6 prefix
		b[15] = 0      // mask the host byte of the v4 part → /24
		return Subnet(b), true
	case ip.Is6():
		b := ip.As16()
		for i := 8; i < 16; i++ {
			b[i] = 0 // zero the low 64 bits → /64
		}
		return Subnet(b), true
	default:
		return Subnet{}, false
	}
}

// NoSubnet always reports "no subnet". It is the SubnetFunc for the in-memory
// transport, whose addresses are hub names with no IP, so the diversity caps are
// inert under it — exactly what deterministic tests want unless they opt into a
// synthetic subnet function of their own.
func NoSubnet(transport.Addr) (Subnet, bool) { return Subnet{}, false }
