package nat

import (
	"testing"

	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/wire"
)

func TestRelayRequestRoundTrip(t *testing.T) {
	nonce := [NonceLen]byte{1, 2, 3}
	target := kad.ID{9, 8, 7}
	buf := make([]byte, 256)
	n, err := EncodeRelayRequestFrame(buf, nonce, target)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	typ, payload, _, err := wire.ParseFrame(buf[:n])
	if err != nil || typ != TypeRelayRequest {
		t.Fatalf("ParseFrame typ=%d err=%v", typ, err)
	}
	gn, gt, err := DecodeRelayRequest(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if gn != nonce || gt != target {
		t.Fatalf("round-trip mismatch: %v %v", gn, gt)
	}
}

func TestRelayGrantRoundTrip(t *testing.T) {
	nonce := [NonceLen]byte{4, 5, 6}
	addr := transport.Addr{Net: "quic", Endpoint: "200.0.0.9:41000"}
	buf := make([]byte, 256)
	n, err := EncodeRelayGrantFrame(buf, nonce, addr)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	typ, payload, _, err := wire.ParseFrame(buf[:n])
	if err != nil || typ != TypeRelayGrant {
		t.Fatalf("ParseFrame typ=%d err=%v", typ, err)
	}
	gn, ga, err := DecodeRelayGrant(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if gn != nonce || ga != addr {
		t.Fatalf("round-trip mismatch: %v %v", gn, ga)
	}
}

func TestRelayBindRoundTrip(t *testing.T) {
	addr := transport.Addr{Net: "quic", Endpoint: "200.0.0.9:42000"}
	buf := make([]byte, 256)
	n, err := EncodeRelayBindFrame(buf, addr)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	typ, payload, _, err := wire.ParseFrame(buf[:n])
	if err != nil || typ != TypeRelayBind {
		t.Fatalf("ParseFrame typ=%d err=%v", typ, err)
	}
	ga, err := DecodeRelayBind(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ga != addr {
		t.Fatalf("round-trip mismatch: %v", ga)
	}
}

func TestRelayDecodersRejectShort(t *testing.T) {
	if _, _, err := DecodeRelayRequest([]byte{1, 2}); err == nil {
		t.Fatal("DecodeRelayRequest of short buffer should fail")
	}
	if _, _, err := DecodeRelayGrant([]byte{1, 2}); err == nil {
		t.Fatal("DecodeRelayGrant of short buffer should fail")
	}
	if _, err := DecodeRelayBind([]byte{}); err == nil {
		t.Fatal("DecodeRelayBind of empty buffer should fail")
	}
}
