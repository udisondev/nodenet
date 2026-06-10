package nat

import (
	"testing"

	"github.com/udisondev/nodenet/transport"
)

func TestConnectRoundTrip(t *testing.T) {
	cases := []Connect{
		{Nonce: [NonceLen]byte{1, 2, 3}},
		{
			Nonce: [NonceLen]byte{9},
			Addrs: []transport.Addr{
				{Net: "quic", Endpoint: "200.0.0.1:40001"},
				{Net: "quic", Endpoint: "[2001:db8::1]:4242"},
			},
		},
	}
	for _, c := range cases {
		b, err := MarshalConnect(&c)
		if err != nil {
			t.Fatalf("MarshalConnect: %v", err)
		}
		got, err := DecodeConnect(b)
		if err != nil {
			t.Fatalf("DecodeConnect: %v", err)
		}
		if got.Nonce != c.Nonce {
			t.Fatalf("nonce = %v, want %v", got.Nonce, c.Nonce)
		}
		if len(got.Addrs) != len(c.Addrs) {
			t.Fatalf("naddrs = %d, want %d", len(got.Addrs), len(c.Addrs))
		}
		for i := range got.Addrs {
			if got.Addrs[i] != c.Addrs[i] {
				t.Fatalf("addr[%d] = %v, want %v", i, got.Addrs[i], c.Addrs[i])
			}
		}
	}
}

func TestDecodeConnectShort(t *testing.T) {
	// Fewer than NonceLen bytes must error, not panic.
	if _, err := DecodeConnect([]byte{1, 2, 3}); err == nil {
		t.Fatal("DecodeConnect of a truncated buffer should fail")
	}
}
