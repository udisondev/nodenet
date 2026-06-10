package quic

import (
	"testing"
)

// TestPunchTarget: a punch target must be a literal, routable unicast
// ip:port. Hostnames are refused outright (so a hostile candidate cannot trigger a DNS
// lookup to an attacker-chosen name), and loopback/multicast/broadcast/unspecified/
// link-local are refused (so the node cannot be turned into a reflector). Public and
// private (LAN) unicast — the legitimate hole-punch candidates — are allowed.
func TestPunchTarget(t *testing.T) {
	cases := []struct {
		endpoint string
		want     bool
	}{
		{"203.0.113.7:443", true},       // public unicast
		{"192.168.1.10:5000", true},     // private LAN unicast (valid same-LAN candidate)
		{"10.0.0.5:1234", true},         // private unicast
		{"[2001:db8::1]:443", true},     // global IPv6 unicast
		{"127.0.0.1:80", false},         // loopback
		{"[::1]:80", false},             // IPv6 loopback
		{"0.0.0.0:1", false},            // unspecified
		{"[::]:1", false},               // IPv6 unspecified
		{"255.255.255.255:9", false},    // limited broadcast
		{"224.0.0.1:9", false},          // multicast
		{"[ff02::1]:9", false},          // IPv6 multicast
		{"169.254.1.1:9", false},        // IPv4 link-local
		{"[fe80::1]:9", false},          // IPv6 link-local
		{"evil.example.com:443", false}, // hostname — must NOT be resolved (no DNS)
		{"localhost:443", false},        // hostname — no DNS
		{"not-an-addr", false},          // malformed
		{"", false},                     // empty
	}
	for _, tc := range cases {
		if _, got := punchTarget(tc.endpoint); got != tc.want {
			t.Errorf("punchTarget(%q) ok = %v, want %v", tc.endpoint, got, tc.want)
		}
	}
}
