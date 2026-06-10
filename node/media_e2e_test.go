package node

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/transport/mem"
)

// sendCallDatagram pushes one datagram into a session, tolerating backpressure
// (the saturation tests flood on purpose).
func sendCallDatagram(t *testing.T, s transport.MediaSession, payload []byte) error {
	t.Helper()
	p := transport.GetMedia()
	defer p.Release()
	p.SetLen(copy(p.Buf(), payload))
	return s.SendDatagram(16, p)
}

// TestMediaCallDoesNotHarmRouter — the "a call must not break the router role"
// e2e: a node in the middle of an overlay chain is ALSO in a call whose path is
// badly bufferbloated (shaped link, flooded until its tx-ring backpressures).
// Overlay transit through that node keeps flowing and its edges survive — the
// call lives on its own connection with its own congestion control, so media
// saturation cannot starve forwarding.
func TestMediaCallDoesNotHarmRouter(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))

		dst := spawn(t, ctx, hub, 1)
		mids := []*testNode{spawn(t, ctx, hub, 2), spawn(t, ctx, hub, 3)}
		src := chainToward(t, ctx, dst.ID(), dst, mids)
		var router *testNode // the chain's middle hop: it forwards src→dst
		for _, m := range mids {
			if m != src {
				router = m
			}
		}

		// The router takes a call with a peer over a starved, bloated link.
		callee := spawn(t, ctx, hub, 7, WithMediaConsent(consentAll))
		link(t, ctx, router, callee)
		hub.SetLinkProfile(router.ID(), callee.ID(), mem.LinkProfile{
			RateBytesPerSec: 1200, // ~1 datagram/s: the call is hopeless, transit must not care
		})
		call, _ := openCall(t, ctx, router, callee)
		defer call.Close()

		// Saturate the call until the tx-ring pushes back.
		payload := make([]byte, transport.MaxMediaDatagram)
		backpressured := false
		for range 4 * transport.MediaTxRing {
			if err := sendCallDatagram(t, call, payload); errors.Is(err, transport.ErrMediaBackpressure) {
				backpressured = true
			}
		}
		if !backpressured {
			t.Fatal("the call never saturated; the scenario is not exercising bufferbloat")
		}

		// Transit through the router, mid-saturation: every message arrives.
		const transits = 10
		for i := range transits {
			if err := src.Send(dst.ID(), []byte{byte(i)}); err != nil {
				t.Fatalf("overlay Send #%d during the call: %v", i, err)
			}
		}
		synctest.Wait()
		if got := drainDeliveries(dst); got < transits {
			t.Errorf("dst received %d of %d transit messages during the saturated call", got, transits)
		}
		// And the router's edges survived the call's congestion.
		if _, ok := router.e.Conn(callee.ID()); !ok {
			t.Error("router's edge to the callee was reaped because of media congestion")
		}
		if st := router.e.Status(); st.OutEdges == 0 {
			t.Error("router lost its outgoing edges during the call")
		}
	})
}

// TestMediaCallSurvivesEdgeChurn — "churn must not kill the call": the overlay
// edge that the call was opened over dies mid-call and is later re-established;
// the session never notices — datagrams flow before, during and after, because
// session and edge have separate fates by construction.
func TestMediaCallSurvivesEdgeChurn(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))
		a := spawn(t, ctx, hub, 1)
		b := spawn(t, ctx, hub, 2, WithMediaConsent(consentAll))
		link(t, ctx, a, b)
		near, far := openCall(t, ctx, a, b)
		defer near.Close()

		exchange := func(tag string) {
			t.Helper()
			if err := sendCallDatagram(t, near, []byte(tag)); err != nil {
				t.Fatalf("SendDatagram (%s): %v", tag, err)
			}
			synctest.Wait()
			select {
			case d := <-far.Datagrams():
				if string(d.Pkt.Bytes()) != tag {
					t.Errorf("got %q, want %q", d.Pkt.Bytes(), tag)
				}
				d.Pkt.Release()
			default:
				t.Fatalf("datagram (%s) never arrived", tag)
			}
		}

		exchange("before-churn")

		// The edge dies abruptly mid-call (the conn closes, the table entry is
		// reaped) — the kill/replace churn event.
		conn, ok := a.e.Conn(b.ID())
		if !ok {
			t.Fatal("no edge to kill")
		}
		_ = conn.Close()
		a.dropEdge(b.ID())
		synctest.Wait()

		exchange("during-churn")

		// Maintenance (here: the test) replaces the edge; the call still flows.
		link(t, ctx, a, b)
		exchange("after-replace")
	})
}

// TestMediaMakeBeforeBreak — several sessions to one peer are legal by design:
// open a second session mid-call (the "better path" one), move traffic to it,
// close the old one. The switch loses nothing on the new session.
func TestMediaMakeBeforeBreak(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))
		a := spawn(t, ctx, hub, 1)
		b := spawn(t, ctx, hub, 2, WithMediaConsent(consentAll))
		link(t, ctx, a, b)

		oldNear, oldFar := openCall(t, ctx, a, b)
		if err := sendCallDatagram(t, oldNear, []byte("on-old")); err != nil {
			t.Fatalf("old session send: %v", err)
		}

		// Make: the second session to the same peer, while the first lives.
		newNear, newFar := openCall(t, ctx, a, b)
		defer newNear.Close()
		if err := sendCallDatagram(t, newNear, []byte("on-new")); err != nil {
			t.Fatalf("new session send: %v", err)
		}
		synctest.Wait()

		// Break: the old session closes; the new one is untouched.
		oldNear.Close()
		synctest.Wait()
		select {
		case <-newNear.Closed():
			t.Fatal("closing the old session killed the new one")
		default:
		}
		if err := sendCallDatagram(t, newNear, []byte("after-break")); err != nil {
			t.Fatalf("send after the break: %v", err)
		}
		synctest.Wait()

		var got []string
		for {
			select {
			case d := <-newFar.Datagrams():
				got = append(got, string(d.Pkt.Bytes()))
				d.Pkt.Release()
				continue
			default:
			}
			break
		}
		if len(got) != 2 || got[0] != "on-new" || got[1] != "after-break" {
			t.Errorf("new session delivered %v, want [on-new after-break]", got)
		}
		// oldFar's channel is already drained shut (the session closed), so a
		// plain receive distinguishes "the datagram made it before the break"
		// from "lost": ok is false once only the close remains.
		if d, ok := <-oldFar.Datagrams(); !ok {
			t.Error("old session's datagram lost before the break")
		} else {
			if string(d.Pkt.Bytes()) != "on-old" {
				t.Errorf("old session delivered %q, want on-old", d.Pkt.Bytes())
			}
			d.Pkt.Release()
		}

		// The callee saw two admitted sessions and released both slots in the
		// end — closing newNear at defer settles the second; check the first
		// freed already.
		time.Sleep(time.Millisecond)
		synctest.Wait()
		b.Node.mediaSlots.mu.Lock()
		count := b.Node.mediaSlots.count
		b.Node.mediaSlots.mu.Unlock()
		if count != 1 {
			t.Errorf("callee's admitted-session count = %d before the deferred close, want 1", count)
		}
	})
}
