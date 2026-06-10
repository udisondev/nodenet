package routing

import (
	"bytes"
	"testing"

	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/transport"
)

// FuzzSubnetFromHostPort asserts the one untrusted-string decoder in routing is
// robust: it must never panic on arbitrary input, and whenever it accepts an
// address the derived key must be deterministic (re-deriving the same address
// yields the same key).
func FuzzSubnetFromHostPort(f *testing.F) {
	f.Add("192.0.2.7:443")
	f.Add("[2001:db8::1]:443")
	f.Add("example.com:80")
	f.Add("node-3")
	f.Add("")
	f.Add(":::::")
	f.Add("999.999.999.999:0")

	f.Fuzz(func(t *testing.T, endpoint string) {
		addr := transport.Addr{Net: "quic", Endpoint: endpoint}
		got, ok := SubnetFromHostPort(addr)
		if !ok {
			if got != (Subnet{}) {
				t.Fatalf("ok == false but key is non-zero: %x", got)
			}
			return // rejecting unparseable input is fine; not panicking is the point
		}
		again, ok2 := SubnetFromHostPort(addr)
		if !ok2 || again != got {
			t.Fatalf("non-deterministic derivation: %x (ok %v) != %x", got, ok2, again)
		}
	})
}

// FuzzDecodeMsg asserts the routing-message decoder is robust against untrusted
// input: it must never panic on arbitrary bytes, and any message it accepts must
// re-encode and decode back to the same value (stable round-trip).
func FuzzDecodeMsg(f *testing.F) {
	seed := func(m *Msg) []byte {
		buf := make([]byte, msgLen(m))
		n, err := EncodeMsg(buf, m)
		if err != nil {
			f.Fatalf("seed EncodeMsg: %v", err)
		}
		return buf[:n]
	}
	f.Add(seed(&Msg{Target: fill(1), TTL: 16, EdPub: fill32(2)}))
	f.Add(seed(&Msg{Target: fill(3), TTL: 9, EdPub: fill32(4), Avoid: avoidOf(fill(5), fill(6)), Payload: []byte("payload")}))
	f.Add([]byte{})
	f.Add([]byte{0x00})

	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := DecodeMsg(b) // must never panic
		if err != nil {
			return
		}
		buf := make([]byte, msgLen(&m))
		n, err := EncodeMsg(buf, &m)
		if err != nil {
			t.Fatalf("re-encode of decoded msg: %v", err)
		}
		m2, err := DecodeMsg(buf[:n])
		if err != nil {
			t.Fatalf("re-decode: %v", err)
		}
		if m2.Target != m.Target || m2.TTL != m.TTL || m2.EdPub != m.EdPub ||
			m2.Sent != m.Sent || m2.Sig != m.Sig ||
			!bytes.Equal(m2.Avoid, m.Avoid) || !bytes.Equal(m2.Payload, m.Payload) {
			t.Fatal("round-trip mismatch after decode")
		}
	})
}

// FuzzDecodeNeighbors asserts the contact-list decoder is robust against untrusted
// input: it must never panic, never let a hostile count drive an absurd allocation
// (the count guard), and any list it accepts must re-encode and decode back equal.
func FuzzDecodeNeighbors(f *testing.F) {
	seed := func(cs []Contact) []byte {
		buf := make([]byte, neighborsLen(cs))
		n, err := EncodeNeighbors(buf, cs)
		if err != nil {
			f.Fatalf("seed EncodeNeighbors: %v", err)
		}
		return buf[:n]
	}
	f.Add(seed(nil))
	f.Add(seed([]Contact{{ID: fill(1), EdPub: fill32(2), XPub: fill32(3), Caps: PublicAnchor}}))
	f.Add(seed([]Contact{{ID: fill(4), Addrs: []transport.Addr{{Net: "quic", Endpoint: "h:1"}, {Net: "mem", Endpoint: "n"}}}}))
	// Multiple contacts with and without addresses, to exercise the shared backing
	// slice/string across contact boundaries.
	f.Add(seed([]Contact{
		{ID: fill(5), Addrs: []transport.Addr{{Net: "quic", Endpoint: "a:1"}}},
		{ID: fill(6), EdPub: fill32(7)},
		{ID: fill(8), Addrs: []transport.Addr{{Net: "mem", Endpoint: "b"}, {Net: "quic", Endpoint: "c:2"}}},
	}))
	f.Add([]byte{})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0x0f}) // huge declared count

	f.Fuzz(func(t *testing.T, b []byte) {
		cs, err := DecodeNeighbors(b) // must never panic
		if err != nil {
			return
		}
		buf := make([]byte, neighborsLen(cs))
		n, err := EncodeNeighbors(buf, cs)
		if err != nil {
			t.Fatalf("re-encode of decoded neighbors: %v", err)
		}
		cs2, err := DecodeNeighbors(buf[:n])
		if err != nil {
			t.Fatalf("re-decode: %v", err)
		}
		if !contactsEqual(cs2, cs) {
			t.Fatal("round-trip mismatch after decode")
		}
	})
}

// FuzzDecodePong asserts the reflexive-address decoder never panics on arbitrary
// bytes, rejects trailing bytes after the address (the payload is exactly one
// address), and round-trips any address it accepts.
func FuzzDecodePong(f *testing.F) {
	seed := func(a transport.Addr) []byte { return transport.AppendAddr(nil, a) }
	f.Add(seed(transport.Addr{Net: "quic", Endpoint: "192.0.2.7:443"}))
	f.Add(seed(transport.Addr{}))
	f.Add([]byte{})
	f.Add([]byte{0xff})

	f.Fuzz(func(t *testing.T, b []byte) {
		a, err := DecodePong(b) // must never panic
		if err != nil {
			return
		}
		enc := transport.AppendAddr(nil, a)
		if _, err := DecodePong(append(enc, 0x00)); err == nil {
			t.Fatal("accepted a payload with a trailing byte")
		}
		a2, err := DecodePong(enc)
		if err != nil {
			t.Fatalf("re-decode: %v", err)
		}
		if a2 != a {
			t.Fatal("round-trip mismatch after decode")
		}
	})
}

// FuzzDecodeSiblings asserts the sibling-request nonce decoder never panics on arbitrary
// bytes and round-trips any payload it accepts (a payload of the wrong length is rejected).
func FuzzDecodeSiblings(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	f.Add([]byte{})
	f.Add([]byte{0xff})
	f.Add(make([]byte, LookupNonceLen+1))

	f.Fuzz(func(t *testing.T, b []byte) {
		nonce, err := DecodeSiblings(b) // must never panic
		if err != nil {
			return
		}
		if len(b) != LookupNonceLen {
			t.Fatalf("accepted a %d-byte payload, want only %d", len(b), LookupNonceLen)
		}
		if [LookupNonceLen]byte(b) != nonce {
			t.Fatal("decoded nonce does not match input")
		}
	})
}

// idFromChunk reads the 32-byte ID at chunk index ci out of raw, zero-padding a
// short or absent tail. It turns a flat fuzz byte string into a stream of NodeIDs.
func idFromChunk(raw []byte, ci int) kad.ID {
	var id kad.ID
	off := ci * 32
	if off < len(raw) {
		copy(id[:], raw[off:])
	}
	return id
}

// closestFullRef is the reference selection: the straightforward full scan of every
// bucket the optimized Knowledge.Closest replaced. The parity fuzz pins the two to
// identical output so the bucket-locality walk can never silently drop or reorder a
// contact.
func closestFullRef(k *Knowledge, target kad.ID, n int) []Contact {
	if n <= 0 {
		return nil
	}
	buf := make([]Contact, 0, n)
	for bi := range k.buckets {
		es := k.buckets[bi].entries
		for i := range es {
			buf = insertClosest(buf, es[i], target, n)
		}
	}
	return buf
}

// FuzzKnowledgeClosestParity asserts the optimized bucket-locality walk in
// Knowledge.Closest returns bit-for-bit the same result (same contacts, same order)
// as a full scan, for an arbitrary table and target. raw seeds self (chunk 0),
// target (chunk 1), and the contacts (chunks 2…); nb picks the result width n.
func FuzzKnowledgeClosestParity(f *testing.F) {
	f.Add([]byte{}, uint8(16))
	f.Add(make([]byte, 32*4), uint8(3))
	mix := make([]byte, 32*6)
	for i := range mix {
		mix[i] = byte(i*7 + 1)
	}
	f.Add(mix, uint8(8))

	f.Fuzz(func(t *testing.T, raw []byte, nb uint8) {
		n := int(nb%32) + 1 // 1..32
		self := idFromChunk(raw, 0)
		target := idFromChunk(raw, 1)
		k := NewKnowledge(self, nil, 0)
		for ci := 2; ci*32 < len(raw); ci++ {
			k.Observe(Contact{ID: idFromChunk(raw, ci)}, t0)
		}

		got := k.Closest(target, n, make([]Contact, 0, n))
		want := closestFullRef(k, target, n)
		if len(got) != len(want) {
			t.Fatalf("len mismatch: walk %d, full %d (n=%d)", len(got), len(want), n)
		}
		for i := range got {
			if got[i].ID != want[i].ID {
				t.Fatalf("contact %d mismatch: walk %x, full %x (n=%d)", i, got[i].ID, want[i].ID, n)
			}
		}
	})
}
