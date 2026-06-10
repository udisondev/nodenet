//go:build e2e_nat

package node

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/routing"
	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/transport/quic"
	"github.com/udisondev/nodenet/transport/quic/nattest"
)

// TestMediaCallThroughRelay — a call between two symmetric-NAT peers rides the
// SAME relay tunnel as their overlay edge: the media connection is dialed from
// the same socket toward the same allocation address, so the relay splice (and
// the NAT mappings it pinned) carries both, multiplexed by connection ID — no
// second allocation. The relay sees only ciphertext; its shaper admits a small
// call easily. A datagram and a message cross.
func TestMediaCallThroughRelay(t *testing.T) {
	f := nattest.NewFabric()

	mk := func(addr string) net.PacketConn {
		pc, err := f.Public(addr)
		if err != nil {
			t.Fatalf("Public %s: %v", addr, err)
		}
		return pc
	}
	mkSym := func(internal, extIP string) net.PacketConn {
		pc, err := f.BehindNAT(internal, nattest.SymmetricNAT(extIP))
		if err != nil {
			t.Fatalf("BehindNAT %s: %v", internal, err)
		}
		return pc
	}
	var allocN int32
	relayFactory := func() (net.PacketConn, error) {
		n := atomic.AddInt32(&allocN, 1)
		return f.Public(fmt.Sprintf("150.0.0.1:%d", 50000+n))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c1 := spawnQUIC(t, ctx, 5, mk("100.0.0.5:9000"))
	c2 := spawnQUIC(t, ctx, 6, mk("100.0.0.6:9000"))
	r := spawnQUICTr(t, ctx, 7, mk("100.0.0.7:9000"), []quic.Option{quic.WithRelaySocketFactory(relayFactory)}, WithRelay())
	a := spawnQUIC(t, ctx, 50, mkSym("10.0.5.2:1111", "200.0.0.5"), WithMaintenance(fastMaintenance()))
	b := spawnQUIC(t, ctx, 60, mkSym("10.0.6.2:2222", "200.0.0.6"),
		WithMaintenance(fastMaintenance()), WithMediaConsent(func(kad.ID) bool { return true }))

	for _, peer := range []*natNode{c1, c2, r} {
		dialReg(t, ctx, a, peer)
		dialReg(t, ctx, b, peer)
	}
	relayContact := routing.Contact{ID: r.ID(), Caps: routing.CanRelay, Addrs: []transport.Addr{r.addr}}
	a.Bootstrap([]routing.Contact{relayContact})
	b.Bootstrap([]routing.Contact{relayContact})
	waitReflexiveSymmetric(t, a, 3*time.Second)
	waitReflexiveSymmetric(t, b, 3*time.Second)

	cctx, ccancel := context.WithTimeout(ctx, 20*time.Second)
	defer ccancel()
	if _, err := a.Connect(cctx, b.ID()); err != nil {
		t.Fatalf("Connect A->B via relay: %v", err)
	}

	// The call: OpenMedia rides the relayed edge's path (the allocation addr).
	near, err := a.OpenMedia(cctx, b.ID())
	if err != nil {
		t.Fatalf("OpenMedia through the relay: %v", err)
	}
	defer near.Close()
	var far transport.MediaSession
	select {
	case far = <-b.InboundMedia():
	case <-cctx.Done():
		t.Fatal("no admitted inbound session on B")
	}

	// A datagram crosses the tunnel (unreliable: retry until it lands).
	p := transport.GetMedia()
	p.SetLen(copy(p.Buf(), []byte("relayed-voice")))
	got := false
	for !got {
		if err := near.SendDatagram(16, p); err != nil && !errors.Is(err, transport.ErrMediaBackpressure) {
			t.Fatalf("SendDatagram: %v", err)
		}
		select {
		case d, ok := <-far.Datagrams():
			if !ok {
				t.Fatal("far Datagrams drained shut mid-test")
			}
			if string(d.Pkt.Bytes()) != "relayed-voice" {
				t.Fatalf("far got %q", d.Pkt.Bytes())
			}
			d.Pkt.Release()
			got = true
		case <-time.After(100 * time.Millisecond):
		case <-cctx.Done():
			t.Fatal("datagram never crossed the relay tunnel")
		}
	}
	p.Release()

	// A message crosses reliably.
	m := transport.Get()
	m.SetLen(copy(m.Buf(), []byte("relayed-frame")))
	if err := near.SendMessage(cctx, 17, m); err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	m.Release()
	select {
	case msg, ok := <-far.Messages():
		if !ok {
			t.Fatal("far Messages drained shut mid-test")
		}
		if msg.Channel != 17 || string(msg.Pkt.Bytes()) != "relayed-frame" {
			t.Fatalf("message = (ch %d, %q)", msg.Channel, msg.Pkt.Bytes())
		}
		msg.Pkt.Release()
	case <-cctx.Done():
		t.Fatal("message never crossed the relay tunnel")
	}
}
