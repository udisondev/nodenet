//go:build e2e_nat

// These tests run the production QUIC transport over the in-process NAT emulator
// (transport/quic/nattest) under real time, so they are gated behind the e2e_nat
// build tag and excluded from the default `go test ./...`. Run them with:
//
//	go test -tags e2e_nat ./transport/quic
package quic

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/transport/quic/nattest"
	"github.com/udisondev/nodenet/transport/transporttest"
)

// listenOnFabric starts a QUIC transport for the seed identity over pc (a fabric
// endpoint), cleaning it up at test end.
func listenOnFabric(t *testing.T, seed byte, pc net.PacketConn) transport.Transport {
	t.Helper()
	tr, err := ListenPacketConn(idFromSeed(seed), pc, WithHandshakeTimeout(2*time.Second))
	if err != nil {
		t.Fatalf("ListenPacketConn(seed %d): %v", seed, err)
	}
	t.Cleanup(func() { tr.Close() })
	return tr
}

// TestNATDialsPublic is the foundation spike: a node behind a restricted-cone NAT
// dials a public peer over real QUIC across the fabric, and a frame flows. This is the
// ordinary outbound case every NAT node relies on, and it proves real QUIC handshakes
// complete over the emulator before hole-punching builds on it.
func TestNATDialsPublic(t *testing.T) {
	f := nattest.NewFabric()

	pubPC, err := f.Public("100.0.0.9:9000")
	if err != nil {
		t.Fatalf("Public: %v", err)
	}
	natPC, err := f.BehindNAT("10.0.0.2:1111", nattest.RestrictedConeNAT("200.0.0.1"))
	if err != nil {
		t.Fatalf("BehindNAT: %v", err)
	}

	pub := listenOnFabric(t, 1, pubPC)
	nat := listenOnFabric(t, 2, natPC)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := nat.Dial(ctx, transporttest.IDFromSeed(1), pub.LocalAddr())
	if err != nil {
		t.Fatalf("NAT node dialing public peer: %v", err)
	}

	p := transport.Get()
	copy(p.Buf(), []byte("hello"))
	p.SetLen(5)
	if err := conn.Send(p); err != nil {
		p.Release()
		t.Fatalf("Send: %v", err)
	}
	p.Release()

	select {
	case d := <-pub.Inbound():
		if got := string(d.Pkt.Bytes()); got != "hello" {
			t.Fatalf("public peer received %q, want hello", got)
		}
		d.Pkt.Release()
	case <-ctx.Done():
		t.Fatal("public peer received nothing before timeout")
	}
}
