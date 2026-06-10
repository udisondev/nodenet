package transport

import (
	"bytes"
	"slices"
	"testing"
)

// FuzzParseAddr feeds the single-address decoder arbitrary bytes: it must never
// panic, and whatever it accepts must survive a re-encode round-trip — the
// re-encoding parses back to the identical Addr and is consumed exactly. (The
// re-encoding is not compared to the input bytes: varints have non-minimal
// spellings the stdlib decoder accepts, so the canonical form may be shorter.)
func FuzzParseAddr(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0})
	f.Add(AppendAddr(nil, Addr{Net: "mem", Endpoint: "node-7"}))
	f.Add(AppendAddr(nil, Addr{Net: "quic", Endpoint: "203.0.113.4:443"}))
	f.Add([]byte{5, 'a', 'b'})
	f.Add(bytes.Repeat([]byte{0xff}, 10))
	f.Fuzz(func(t *testing.T, b []byte) {
		a, n, err := ParseAddr(b)
		if err != nil {
			if a != (Addr{}) || n != 0 {
				t.Fatalf("ParseAddr(%x) = %+v, n=%d alongside err %v; want zero values", b, a, n, err)
			}
			return
		}
		if n < MinAddrWireLen || n > len(b) {
			t.Fatalf("ParseAddr(%x) consumed n=%d of %d bytes", b, n, len(b))
		}
		enc := AppendAddr(nil, a)
		if len(enc) != AddrWireLen(a) {
			t.Fatalf("re-encode of %+v is %d bytes, AddrWireLen = %d", a, len(enc), AddrWireLen(a))
		}
		a2, n2, err := ParseAddr(enc)
		if err != nil || a2 != a || n2 != len(enc) {
			t.Fatalf("re-parse of %+v = %+v, n=%d, err=%v", a, a2, n2, err)
		}
	})
}

// FuzzParseAddrs is the same contract for the counted-list decoder: no panics on
// arbitrary input, and an accepted list re-encodes and re-parses to itself.
func FuzzParseAddrs(f *testing.F) {
	f.Add([]byte{0})
	f.Add(AppendAddrs(nil, []Addr{{Net: "mem", Endpoint: "a"}, {Net: "quic", Endpoint: "h:1"}}))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0x0f})
	f.Add([]byte{2, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		addrs, n, err := ParseAddrs(b)
		if err != nil {
			if addrs != nil || n != 0 {
				t.Fatalf("ParseAddrs(%x) = %+v, n=%d alongside err %v; want zero values", b, addrs, n, err)
			}
			return
		}
		if n < 1 || n > len(b) {
			t.Fatalf("ParseAddrs(%x) consumed n=%d of %d bytes", b, n, len(b))
		}
		enc := AppendAddrs(nil, addrs)
		if len(enc) != AddrsWireLen(addrs) {
			t.Fatalf("re-encode of %+v is %d bytes, AddrsWireLen = %d", addrs, len(enc), AddrsWireLen(addrs))
		}
		addrs2, n2, err := ParseAddrs(enc)
		if err != nil || !slices.Equal(addrs2, addrs) || n2 != len(enc) {
			t.Fatalf("re-parse of %+v = %+v, n=%d, err=%v", addrs, addrs2, n2, err)
		}
	})
}
