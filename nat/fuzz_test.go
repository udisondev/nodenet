package nat

import (
	"encoding/binary"
	"testing"

	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/wire"
)

// FuzzConnect feeds arbitrary bytes to the Connect decoder: it must never panic,
// anything that decodes must survive a re-encode/re-decode round trip unchanged, and
// a decoded candidate list never exceeds the protocol cap.
func FuzzConnect(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, NonceLen)) // valid: nonce + zero addrs
	if b, err := MarshalConnect(&Connect{Addrs: []transport.Addr{{Net: "quic", Endpoint: "1.2.3.4:5"}}}); err == nil {
		f.Add(b)
	}
	// Over-cap count over a parseable body of empty addresses: must be refused.
	flood := binary.AppendUvarint(make([]byte, NonceLen), 1000)
	f.Add(append(flood, make([]byte, 2000)...))

	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := DecodeConnect(b)
		if err != nil {
			return
		}
		if len(c.Addrs) > maxConnectAddrs {
			t.Fatalf("decoded %d addrs, cap is %d", len(c.Addrs), maxConnectAddrs)
		}
		re, err := MarshalConnect(&c)
		if err != nil {
			t.Fatalf("re-encode of a decoded Connect failed: %v", err)
		}
		got, err := DecodeConnect(re)
		if err != nil {
			t.Fatalf("re-decode failed: %v", err)
		}
		if got.Nonce != c.Nonce || len(got.Addrs) != len(c.Addrs) {
			t.Fatalf("round-trip changed the message")
		}
		for i := range got.Addrs {
			if got.Addrs[i] != c.Addrs[i] {
				t.Fatalf("round-trip changed addr[%d]", i)
			}
		}
	})
}

// FuzzRelayGrant: the relay-grant decoder must never panic, and a decoded grant must
// survive a re-encode/re-decode round trip unchanged.
func FuzzRelayGrant(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, NonceLen+2)) // valid: nonce + empty addr
	if b, err := func() ([]byte, error) {
		dst := make([]byte, wire.MaxFrameLen)
		w, err := EncodeRelayGrantFrame(dst, [NonceLen]byte{1, 2, 3},
			transport.Addr{Net: "quic", Endpoint: "1.2.3.4:5"})
		return dst[:w], err
	}(); err == nil {
		if _, pl, _, perr := wire.ParseFrame(b); perr == nil {
			f.Add(pl)
		}
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		nonce, addr, err := DecodeRelayGrant(b)
		if err != nil {
			return
		}
		payload := parseFramePayload(t, func(dst []byte) (int, error) {
			return EncodeRelayGrantFrame(dst, nonce, addr)
		})
		n2, a2, err := DecodeRelayGrant(payload)
		if err != nil {
			t.Fatalf("re-decode failed: %v", err)
		}
		if n2 != nonce || a2 != addr {
			t.Fatalf("round-trip changed the grant")
		}
	})
}

// parseFramePayload encodes one frame via enc, then returns its decoded payload region —
// the slice the Decode* functions actually parse (after wire.ParseFrame). It lets the
// relay fuzzers round-trip through the same framing the wire path uses.
func parseFramePayload(t *testing.T, enc func([]byte) (int, error)) []byte {
	buf := make([]byte, wire.MaxFrameLen)
	w, err := enc(buf)
	if err != nil {
		t.Fatalf("encode frame: %v", err)
	}
	_, payload, _, err := wire.ParseFrame(buf[:w])
	if err != nil {
		t.Fatalf("parse re-encoded frame: %v", err)
	}
	return payload
}

// FuzzRelayRequest: the relay-request decoder must never panic, and a decoded request
// must survive a re-encode/re-decode round trip unchanged.
func FuzzRelayRequest(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, NonceLen+kad.IDLen)) // valid: nonce + target
	f.Fuzz(func(t *testing.T, b []byte) {
		nonce, target, err := DecodeRelayRequest(b)
		if err != nil {
			return
		}
		payload := parseFramePayload(t, func(dst []byte) (int, error) {
			return EncodeRelayRequestFrame(dst, nonce, target)
		})
		n2, t2, err := DecodeRelayRequest(payload)
		if err != nil {
			t.Fatalf("re-decode failed: %v", err)
		}
		if n2 != nonce || t2 != target {
			t.Fatalf("round-trip changed the request")
		}
	})
}

// FuzzRelayBind: the relay-bind decoder must never panic, and a decoded address must
// survive a re-encode/re-decode round trip unchanged.
func FuzzRelayBind(f *testing.F) {
	f.Add([]byte{})
	if b, err := func() ([]byte, error) {
		dst := make([]byte, wire.MaxFrameLen)
		w, err := EncodeRelayBindFrame(dst, transport.Addr{Net: "quic", Endpoint: "1.2.3.4:5"})
		return dst[:w], err
	}(); err == nil {
		if _, pl, _, perr := wire.ParseFrame(b); perr == nil {
			f.Add(pl)
		}
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		addr, err := DecodeRelayBind(b)
		if err != nil {
			return
		}
		payload := parseFramePayload(t, func(dst []byte) (int, error) {
			return EncodeRelayBindFrame(dst, addr)
		})
		got, err := DecodeRelayBind(payload)
		if err != nil {
			t.Fatalf("re-decode failed: %v", err)
		}
		if got != addr {
			t.Fatalf("round-trip changed the bind address")
		}
	})
}
