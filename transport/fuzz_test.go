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

// FuzzParseMediaFrame feeds the media-frame splitter arbitrary bytes: it must
// never panic, reject only the empty frame, and whatever it accepts must
// re-encode (PutMediaFrame) byte-identically — the format has exactly one
// spelling, so the round-trip is exact.
func FuzzParseMediaFrame(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add([]byte{16, 'o', 'p', 'u', 's'})
	f.Add(bytes.Repeat([]byte{0xff}, MaxMediaDatagram+1))
	f.Fuzz(func(t *testing.T, b []byte) {
		ch, payload, err := ParseMediaFrame(b)
		if err != nil {
			if len(b) != 0 {
				t.Fatalf("ParseMediaFrame(%x) err = %v on a non-empty frame", b, err)
			}
			if ch != 0 || payload != nil {
				t.Fatalf("ParseMediaFrame error alongside non-zero results (%d, %x)", ch, payload)
			}
			return
		}
		if len(payload) != len(b)-1 {
			t.Fatalf("payload len = %d, want %d", len(payload), len(b)-1)
		}
		enc := make([]byte, MediaFrameLen(len(payload)))
		n, err := PutMediaFrame(enc, ch, payload)
		if err != nil || n != len(b) {
			t.Fatalf("PutMediaFrame = (%d, %v), want (%d, nil)", n, err, len(b))
		}
		if !bytes.Equal(enc[:n], b) {
			t.Fatalf("re-encode %x != input %x", enc[:n], b)
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
