package nat

import (
	"encoding/binary"
	"errors"
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

// TestDecodeConnectRejectsAddrFlood: a Connect declaring an absurd candidate count
// (here ~500k, riding on ~1 MiB of zero bytes that each parse as an empty address)
// must be refused before the address slice is allocated — otherwise every delivered
// frame costs a ~16 MiB zeroed allocation on the dispatch goroutine. A real Connect
// carries a handful of candidates, so the cap rejects nothing legitimate.
func TestDecodeConnectRejectsAddrFlood(t *testing.T) {
	const cnt = 500_000
	b := make([]byte, 0, NonceLen+binary.MaxVarintLen64+2*cnt)
	b = append(b, make([]byte, NonceLen)...)
	b = binary.AppendUvarint(b, cnt)
	b = append(b, make([]byte, 2*cnt)...) // each 0x00 0x00 = one empty address
	if allocs := testing.AllocsPerRun(10, func() {
		if _, err := DecodeConnect(b); !errors.Is(err, transport.ErrTooManyAddrs) {
			t.Fatalf("DecodeConnect(flood): err = %v, want transport.ErrTooManyAddrs", err)
		}
	}); allocs != 0 {
		t.Errorf("flood rejection allocated %.0f times, want 0", allocs)
	}
}

// The protocol cap is symmetric: the encoder refuses a list the decoder would
// reject, and a list exactly at the cap round-trips.
func TestConnectAddrCapBoundary(t *testing.T) {
	atCap := Connect{Addrs: make([]transport.Addr, maxConnectAddrs)}
	b, err := MarshalConnect(&atCap)
	if err != nil {
		t.Fatalf("MarshalConnect(at cap): %v", err)
	}
	got, err := DecodeConnect(b)
	if err != nil {
		t.Fatalf("DecodeConnect(at cap): %v", err)
	}
	if len(got.Addrs) != maxConnectAddrs {
		t.Fatalf("naddrs = %d, want %d", len(got.Addrs), maxConnectAddrs)
	}
	over := Connect{Addrs: make([]transport.Addr, maxConnectAddrs+1)}
	if _, err := MarshalConnect(&over); !errors.Is(err, transport.ErrTooManyAddrs) {
		t.Fatalf("MarshalConnect(over cap): err = %v, want transport.ErrTooManyAddrs", err)
	}
}
