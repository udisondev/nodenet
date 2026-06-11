package node

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/transport/mem"
)

// consentAll is the test application's consent gate: take every call.
func consentAll(kad.ID) bool { return true }

// openCall opens a media session a→b over the node API and takes the admitted
// far end off b's InboundMedia.
func openCall(t *testing.T, ctx context.Context, a, b *testNode) (near, far transport.MediaSession) {
	t.Helper()
	near, err := a.OpenMedia(ctx, b.ID())
	if err != nil {
		t.Fatalf("OpenMedia: %v", err)
	}
	synctest.Wait()
	select {
	case far = <-b.InboundMedia():
	default:
		near.Close()
		t.Fatal("no admitted inbound session on the callee")
	}
	return near, far
}

// TestMediaCallOverLiveEdge: with a live edge a→b, OpenMedia rides its path;
// the admitted session moves a datagram and the edge keeps forwarding overlay
// traffic (separate fates).
func TestMediaCallOverLiveEdge(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))
		a := spawn(t, ctx, hub, 1)
		b := spawn(t, ctx, hub, 2, WithMediaConsent(consentAll))
		link(t, ctx, a, b)

		near, far := openCall(t, ctx, a, b)
		defer near.Close()

		p := transport.GetMedia()
		p.SetLen(copy(p.Buf(), []byte("hi")))
		if err := near.SendDatagram(16, p); err != nil {
			t.Fatalf("SendDatagram: %v", err)
		}
		p.Release()
		synctest.Wait()
		select {
		case d := <-far.Datagrams():
			if string(d.Pkt.Bytes()) != "hi" {
				t.Errorf("far got %q, want hi", d.Pkt.Bytes())
			}
			d.Pkt.Release()
		default:
			t.Fatal("datagram never arrived")
		}

		// The overlay edge is untouched by the call: a routed send still works.
		if err := a.Send(b.ID(), []byte("overlay")); err != nil {
			t.Fatalf("Send: %v", err)
		}
		synctest.Wait()
		select {
		case got := <-b.Deliveries():
			if string(got.Payload) != "overlay" {
				t.Errorf("overlay payload = %q", got.Payload)
			}
		default:
			t.Fatal("overlay delivery lost during the call")
		}
	})
}

// TestMediaConsentDefaultReject: without WithMediaConsent every inbound session
// is refused (secure by default), counted, and never reaches the application.
func TestMediaConsentDefaultReject(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))
		a := spawn(t, ctx, hub, 1)
		b := spawn(t, ctx, hub, 2) // no consent gate
		link(t, ctx, a, b)

		near, err := a.OpenMedia(ctx, b.ID())
		if err != nil {
			t.Fatalf("OpenMedia: %v", err)
		}
		defer near.Close()
		synctest.Wait()

		select {
		case <-b.InboundMedia():
			t.Fatal("session admitted without consent")
		default:
		}
		if got := b.Stats().DroppedMediaConsent; got != 1 {
			t.Errorf("DroppedMediaConsent = %d, want 1", got)
		}
		// The refusal closed the session; the caller observes it.
		select {
		case <-near.Closed():
		default:
			t.Error("caller's session not closed after consent refusal")
		}
	})
}

// TestMediaAdmissionPoW: an inbound call from a sub-PoW identity is refused
// before consent — a call must not be a way around the admission speed bump.
func TestMediaAdmissionPoW(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))

		const dmin = 8
		calleeSeed := seedSatisfying(t, dmin, true)
		callerSeed := seedSatisfying(t, dmin, false, calleeSeed)
		consentCalls := 0
		callee := spawn(t, ctx, hub, calleeSeed, WithDmin(dmin),
			WithMediaConsent(func(kad.ID) bool { consentCalls++; return true }))
		caller := spawn(t, ctx, hub, callerSeed, WithDmin(dmin))
		link(t, ctx, caller, callee)

		near, err := caller.OpenMedia(ctx, callee.ID())
		if err != nil {
			t.Fatalf("OpenMedia: %v", err)
		}
		defer near.Close()
		synctest.Wait()

		select {
		case <-callee.InboundMedia():
			t.Fatal("sub-PoW caller's session was admitted")
		default:
		}
		if got := callee.Stats().DroppedMediaSubPoW; got != 1 {
			t.Errorf("DroppedMediaSubPoW = %d, want 1", got)
		}
		if consentCalls != 0 {
			t.Errorf("consent gate consulted %d times for a sub-PoW caller, want 0", consentCalls)
		}
	})
}

// TestMediaSessionCap: past maxMediaSessions admitted inbound sessions the next
// one is refused and counted; closing a session frees its slot for a new call.
func TestMediaSessionCap(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))
		callee := spawn(t, ctx, hub, 1, WithMediaConsent(consentAll))

		var sessions []transport.MediaSession
		defer func() {
			for _, s := range sessions {
				s.Close()
			}
		}()
		admitted := make([]transport.MediaSession, 0, maxMediaSessions)
		for i := range maxMediaSessions {
			caller := spawn(t, ctx, hub, uint64(10+i))
			link(t, ctx, caller, callee)
			s, err := caller.OpenMedia(ctx, callee.ID())
			if err != nil {
				t.Fatalf("OpenMedia #%d: %v", i, err)
			}
			sessions = append(sessions, s)
			synctest.Wait()
			select {
			case far := <-callee.InboundMedia():
				admitted = append(admitted, far)
			default:
				t.Fatalf("session #%d not admitted below the cap", i)
			}
		}

		over := spawn(t, ctx, hub, 99)
		link(t, ctx, over, callee)
		s, err := over.OpenMedia(ctx, callee.ID())
		if err != nil {
			t.Fatalf("OpenMedia over cap: %v", err)
		}
		sessions = append(sessions, s)
		synctest.Wait()
		select {
		case <-callee.InboundMedia():
			t.Fatal("session admitted past maxMediaSessions")
		default:
		}
		if got := callee.Stats().DroppedMediaCap; got != 1 {
			t.Errorf("DroppedMediaCap = %d, want 1", got)
		}

		// A finished call frees its slot: close one admitted session, the next
		// caller gets in.
		admitted[0].Close()
		synctest.Wait()
		retry := spawn(t, ctx, hub, 100)
		link(t, ctx, retry, callee)
		s2, err := retry.OpenMedia(ctx, callee.ID())
		if err != nil {
			t.Fatalf("OpenMedia after a slot freed: %v", err)
		}
		sessions = append(sessions, s2)
		synctest.Wait()
		select {
		case far := <-callee.InboundMedia():
			admitted = append(admitted, far)
		default:
			t.Fatal("no admission after a slot was freed")
		}
	})
}

// TestMediaDialFailureReapsZombieEdge — the anti-zombie coupling: the edge
// table says the peer is alive, but its transport is gone; the failed media
// dial pings the edge out of schedule, the ping's send fails, and the edge is
// dropped immediately — no waiting for keepalive timers, no maintenance loop.
func TestMediaDialFailureReapsZombieEdge(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))
		a := spawn(t, ctx, hub, 1)
		b := spawn(t, ctx, hub, 2, WithMediaConsent(consentAll))
		link(t, ctx, a, b)

		b.t.Close() // b vanishes abruptly; a's edge entry is now a zombie
		synctest.Wait()
		if _, ok := a.e.Conn(b.ID()); !ok {
			t.Fatal("precondition: a should still hold the (zombie) edge")
		}

		if _, err := a.OpenMedia(ctx, b.ID()); err == nil {
			t.Fatal("OpenMedia to a dead peer succeeded")
		}
		synctest.Wait()
		if _, ok := a.e.Conn(b.ID()); ok {
			t.Error("zombie edge survived the failed media dial; the liveness ping must have dropped it")
		}
	})
}

// TestMediaUnsupportedPeerKeepsEdge: a peer without media support refuses the
// call with ErrMediaUnsupported, and — since that says nothing about liveness —
// the overlay edge stays.
func TestMediaUnsupportedPeerKeepsEdge(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))
		a := spawn(t, ctx, hub, 1)
		b := spawn(t, ctx, hub, 2)
		link(t, ctx, a, b)
		hub.SetMediaSupport(b.ID(), false)

		if _, err := a.OpenMedia(ctx, b.ID()); !errors.Is(err, transport.ErrMediaUnsupported) {
			t.Fatalf("OpenMedia: err = %v, want ErrMediaUnsupported", err)
		}
		synctest.Wait()
		if _, ok := a.e.Conn(b.ID()); !ok {
			t.Error("edge to a media-less (but alive) peer was dropped")
		}
	})
}

// TestMediaIdleDeathPingsEdge: a call dying of path death (partition outlasting
// the media idle timeout) triggers the out-of-schedule edge ping; with the
// partition still up the ping is blackholed, and once it heals the edge is
// proven alive again — the coupling never falsely reaps a healthy edge.
func TestMediaIdleDeathPingsEdge(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))
		a := spawn(t, ctx, hub, 1)
		b := spawn(t, ctx, hub, 2, WithMediaConsent(consentAll))
		link(t, ctx, a, b)
		near, far := openCall(t, ctx, a, b)
		defer near.Close()
		defer far.Close()

		hub.Partition(a.ID(), b.ID())
		time.Sleep(20 * time.Second) // mem media idle timeout is 10 s
		select {
		case <-near.Closed():
		default:
			t.Fatal("session survived a partition past the idle timeout")
		}
		// The edge survives (the mem ping was blackholed, not failed); after
		// healing it still works — and a fresh call can be re-established.
		hub.Heal(a.ID(), b.ID())
		near2, far2 := openCall(t, ctx, a, b)
		near2.Close()
		_ = far2
	})
}

// TestMediaSlotsPerPeer exercises the per-identity half of the session caps
// directly: four sessions from one NodeID fill its allowance, the fifth is refused
// while another identity still gets in, and a release reopens the slot. The key is
// the NodeID, so two identities reaching us through one relay (one shared IP) are
// NOT collapsed. An empty key disables per-peer accounting.
func TestMediaSlotsPerPeer(t *testing.T) {
	slots := newMediaSlots()
	for i := range maxMediaPerPeer {
		if !slots.reserve("peerA") {
			t.Fatalf("reserve #%d under the per-peer cap refused", i)
		}
	}
	if slots.reserve("peerA") {
		t.Fatal("reserve past maxMediaPerPeer allowed")
	}
	if !slots.reserve("peerB") {
		t.Fatal("another identity refused while only one is saturated (per-relay collapse)")
	}
	slots.release("peerA")
	if !slots.reserve("peerA") {
		t.Fatal("reserve refused after a release freed the identity's slot")
	}

	// Empty keys count toward the node-wide cap only.
	fresh := newMediaSlots()
	for i := range maxMediaSessions {
		if !fresh.reserve("") {
			t.Fatalf("keyless reserve #%d refused below the node cap", i)
		}
	}
	if fresh.reserve("") {
		t.Fatal("keyless reserve past maxMediaSessions allowed")
	}
}

// TestMediaInboundUnconsumedRefused: an application that never reads
// InboundMedia gets admitted sessions parked in the bounded gate channel; the
// one past its depth is refused (closed + counted) instead of queued
// unboundedly.
func TestMediaInboundUnconsumedRefused(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))
		callee := spawn(t, ctx, hub, 1, WithMediaConsent(consentAll))

		var sessions []transport.MediaSession
		defer func() {
			for _, s := range sessions {
				s.Close()
			}
		}()
		for i := 0; i <= mediaInBuffer; i++ {
			caller := spawn(t, ctx, hub, uint64(10+i))
			link(t, ctx, caller, callee)
			s, err := caller.OpenMedia(ctx, callee.ID())
			if err != nil {
				t.Fatalf("OpenMedia #%d: %v", i, err)
			}
			sessions = append(sessions, s)
			synctest.Wait()
		}

		if got := callee.Stats().DroppedMediaCap; got != 1 {
			t.Errorf("DroppedMediaCap = %d, want 1 (the overflow past mediaInBuffer)", got)
		}
		select {
		case <-sessions[len(sessions)-1].Closed():
		default:
			t.Error("the unconsumed-overflow session was not closed")
		}
	})
}

// mediaLess hides any optional capabilities of the wrapped transport: only the
// plain Transport methods promote, so a type assertion to transport.Media (or
// any other capability) fails — a stand-in for a future capability-poor
// transport.
type mediaLess struct{ transport.Transport }

// TestMediaWithoutTransportCapability: a transport without the Media capability
// yields ErrUnsupported from OpenMedia (nothing in the node assumes it).
func TestMediaWithoutTransportCapability(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		idn := identity.FromSeed(seedFor(1))
		tr, err := mem.NewHub().New(idn.ID(), transport.Addr{Net: "mem", Endpoint: "x"})
		if err != nil {
			t.Fatalf("hub.New: %v", err)
		}
		n := New(idn, mediaLess{tr})
		if _, err := n.OpenMedia(context.Background(), kad.ID{7}); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("OpenMedia on a media-less transport: err = %v, want ErrUnsupported", err)
		}
	})
}
