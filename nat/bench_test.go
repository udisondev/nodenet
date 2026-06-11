package nat

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/udisondev/nodenet/kad"
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

// BenchmarkReflexiveConsensus measures the consensus read as the report set grows
// toward its cap. The aggregation is one pass O(reports) (was all-pairs O(reports²)),
// so ns/op grows far slower than quadratically with N. Worst case for the old scan:
// every reporter on the same address.
func BenchmarkReflexiveConsensus(b *testing.B) {
	for _, n := range []int{64, 256, 1024} {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			r := NewReflexive()
			same := addr("203.0.113.7:4242")
			for i := range n {
				var rep kad.ID
				binary.BigEndian.PutUint64(rep[:], uint64(i+1))
				r.Record(rep, sub(byte(i)), true, same)
			}
			b.ReportAllocs()
			for b.Loop() {
				r.Consensus()
			}
		})
	}
}
