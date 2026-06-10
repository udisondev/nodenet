package nat

import (
	"testing"

	"github.com/udisondev/nodenet/transport"
)

// BenchmarkEncodeConnect targets 0 allocs/op: encoding writes in place into a caller
// buffer, the control-plane equivalent of the data path's zero-alloc framing.
func BenchmarkEncodeConnect(b *testing.B) {
	c := Connect{
		Nonce: [NonceLen]byte{1, 2, 3, 4},
		Addrs: []transport.Addr{
			{Net: "quic", Endpoint: "200.0.0.1:40001"},
			{Net: "quic", Endpoint: "198.51.100.7:5555"},
		},
	}
	buf := make([]byte, connectLen(&c))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := EncodeConnect(buf, &c); err != nil {
			b.Fatal(err)
		}
	}
}
