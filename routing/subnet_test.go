package routing

import (
	"testing"

	"github.com/udisondev/nodenet/transport"
)

func quic(endpoint string) transport.Addr { return transport.Addr{Net: "quic", Endpoint: endpoint} }

func TestSubnetFromHostPort(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		wantOK   bool
	}{
		{"ipv4", "192.0.2.7:443", true},
		{"ipv4 other host same /24", "192.0.2.200:1", true},
		{"ipv6", "[2001:db8::1]:443", true},
		{"hostname not ip", "example.com:443", false},
		{"no port", "192.0.2.7", false},
		{"garbage", "not-an-address", false},
		{"empty", "", false},
		{"mem hub name", "node-3", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := SubnetFromHostPort(quic(tt.endpoint))
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
		})
	}
}

func TestSubnetMasking(t *testing.T) {
	// Two IPv4 hosts in the same /24 share a subnet; a third /24 differs.
	a, ok := SubnetFromHostPort(quic("192.0.2.7:1"))
	if !ok {
		t.Fatal("192.0.2.7 not parsed")
	}
	b, _ := SubnetFromHostPort(quic("192.0.2.250:9"))
	if a != b {
		t.Fatalf("same /24 gave different keys: %x vs %x", a, b)
	}
	c, _ := SubnetFromHostPort(quic("192.0.3.7:1"))
	if a == c {
		t.Fatalf("different /24 gave same key: %x", a)
	}

	// Two IPv6 hosts in the same /64 share a subnet; a different /64 differs.
	d, ok := SubnetFromHostPort(quic("[2001:db8:0:1::5]:1"))
	if !ok {
		t.Fatal("ipv6 not parsed")
	}
	e, _ := SubnetFromHostPort(quic("[2001:db8:0:1:ffff::9]:2"))
	if d != e {
		t.Fatalf("same /64 gave different keys: %x vs %x", d, e)
	}
	f, _ := SubnetFromHostPort(quic("[2001:db8:0:2::5]:1"))
	if d == f {
		t.Fatalf("different /64 gave same key: %x", d)
	}

	// A v4-in-v6 prefix must not collide with a native v6 prefix.
	if a == d {
		t.Fatalf("v4 and v6 keys collided")
	}
}

func TestNoSubnet(t *testing.T) {
	if _, ok := NoSubnet(quic("192.0.2.7:443")); ok {
		t.Fatal("NoSubnet reported a subnet")
	}
	if _, ok := NoSubnet(transport.Addr{Net: "mem", Endpoint: "node-1"}); ok {
		t.Fatal("NoSubnet reported a subnet")
	}
}
