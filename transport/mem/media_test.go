package mem

import (
	"context"
	"errors"
	mrand "math/rand/v2"
	"testing"
	"testing/synctest"
	"time"

	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/transport"
)

// mediaPair brings up two transports on a fresh hub and opens a media session
// a→b, returning both ends. Everything is registered for teardown via cleanup
// so the synctest bubble drains (pumps and watchdogs exit).
func mediaPair(t *testing.T) (hub *Hub, near, far transport.MediaSession, aID, bID kad.ID) {
	t.Helper()
	hub = NewHub()
	aID, bID = id(1), id(2)
	ta := newT(t, hub, aID, "a")
	tb := newT(t, hub, bID, "b")

	near, err := ta.(transport.Media).OpenMedia(context.Background(), bID, transport.Addr{Net: "mem", Endpoint: "b"})
	if err != nil {
		t.Fatalf("OpenMedia: %v", err)
	}
	select {
	case far = <-tb.(transport.Media).InboundMedia():
	default:
		t.Fatal("no inbound media session surfaced")
	}
	return hub, near, far, aID, bID
}

// id derives a distinct NodeID for tests.
func id(b byte) kad.ID {
	var x kad.ID
	x[0] = b
	return x
}

// newT registers a transport on the hub and closes it at test end.
func newT(t *testing.T, hub *Hub, nodeID kad.ID, name string) transport.Transport {
	t.Helper()
	tr, err := hub.New(nodeID, transport.Addr{Net: "mem", Endpoint: name})
	if err != nil {
		t.Fatalf("hub.New(%s): %v", name, err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	return tr
}

// sendDatagram sends one datagram with the given payload byte and waits for the
// pump to finish with it, so each test step is deterministic.
func sendDatagram(t *testing.T, s transport.MediaSession, ch uint8, payload ...byte) {
	t.Helper()
	p := transport.GetMedia()
	defer p.Release()
	p.SetLen(copy(p.Buf(), payload))
	if err := s.SendDatagram(ch, p); err != nil {
		t.Fatalf("SendDatagram: %v", err)
	}
	synctest.Wait()
}

// recvDatagram takes one already-delivered datagram without blocking, returning
// its payload (copied) and RxTime, and Releases the packet.
func recvDatagram(t *testing.T, s transport.MediaSession) ([]byte, time.Time) {
	t.Helper()
	select {
	case d := <-s.Datagrams():
		out := append([]byte(nil), d.Pkt.Bytes()...)
		d.Pkt.Release()
		return out, d.RxTime
	default:
		t.Fatal("no datagram waiting")
		return nil, time.Time{}
	}
}

// A session moves datagrams and messages in both directions, each tagged with
// its channel, datagrams stamped with the fake-clock receive time — and none of
// it crosses the transports' overlay Inbound streams.
func TestMediaExchange(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, near, far, _, _ := mediaPair(t)
		defer near.Close()

		t0 := time.Now()
		sendDatagram(t, near, 16, 'v', 'o', 'x')
		got, rx := recvDatagram(t, far)
		if string(got) != "vox" {
			t.Errorf("far datagram = %q, want vox", got)
		}
		if !rx.Equal(t0) {
			t.Errorf("RxTime = %v, want the fake-clock now %v (ideal link: no delay)", rx, t0)
		}

		// Reverse direction over the same session.
		sendDatagram(t, far, 17, 'a', 'c', 'k')
		back, _ := recvDatagram(t, near)
		if string(back) != "ack" {
			t.Errorf("near datagram = %q, want ack", back)
		}

		// A message: reliable, channel-tagged, whole.
		p := transport.Get()
		p.SetLen(copy(p.Buf(), []byte("keyframe")))
		if err := near.SendMessage(context.Background(), 20, p); err != nil {
			t.Fatalf("SendMessage: %v", err)
		}
		p.Release()
		synctest.Wait()
		select {
		case m := <-far.Messages():
			if m.Channel != 20 || string(m.Pkt.Bytes()) != "keyframe" {
				t.Errorf("message = (ch %d, %q), want (20, keyframe)", m.Channel, m.Pkt.Bytes())
			}
			m.Pkt.Release()
		default:
			t.Fatal("no message delivered")
		}

		st := near.Stats()
		if st.TxDatagrams != 1 || st.TxMessages != 1 {
			t.Errorf("near stats = %+v, want TxDatagrams=1 TxMessages=1", st)
		}
		fst := far.Stats()
		if fst.RxDatagrams != 1 || fst.RxMessages != 1 || fst.TxDatagrams != 1 {
			t.Errorf("far stats = %+v, want RxDatagrams=1 RxMessages=1 TxDatagrams=1", fst)
		}
	})
}

// A peer flagged media-less refuses OpenMedia with ErrMediaUnsupported; its
// overlay dial keeps working untouched.
func TestMediaUnsupportedPeer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hub := NewHub()
		ta := newT(t, hub, id(1), "a")
		newT(t, hub, id(2), "b")
		hub.SetMediaSupport(id(2), false)

		baddr := transport.Addr{Net: "mem", Endpoint: "b"}
		_, err := ta.(transport.Media).OpenMedia(context.Background(), id(2), baddr)
		if !errors.Is(err, transport.ErrMediaUnsupported) {
			t.Fatalf("OpenMedia to a media-less peer: err = %v, want ErrMediaUnsupported", err)
		}
		if _, err := ta.Dial(context.Background(), id(2), baddr); err != nil {
			t.Fatalf("overlay Dial must be unaffected, got %v", err)
		}
	})
}

// Dial-style failures: wrong identity at the address, unknown address, and a
// partition all refuse the open the same way the overlay dial would.
func TestMediaOpenFailures(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hub := NewHub()
		ta := newT(t, hub, id(1), "a")
		newT(t, hub, id(2), "b")
		media := ta.(transport.Media)
		baddr := transport.Addr{Net: "mem", Endpoint: "b"}

		if _, err := media.OpenMedia(context.Background(), id(9), baddr); !errors.Is(err, transport.ErrIdentityMismatch) {
			t.Errorf("wrong identity: err = %v, want ErrIdentityMismatch", err)
		}
		if _, err := media.OpenMedia(context.Background(), id(2), transport.Addr{Net: "mem", Endpoint: "nowhere"}); !errors.Is(err, transport.ErrNoRoute) {
			t.Errorf("unknown addr: err = %v, want ErrNoRoute", err)
		}
		hub.Partition(id(1), id(2))
		if _, err := media.OpenMedia(context.Background(), id(2), baddr); !errors.Is(err, transport.ErrNoRoute) {
			t.Errorf("partitioned: err = %v, want ErrNoRoute", err)
		}
	})
}

// Closing either end ends the session for both: Closed fires, sends refuse with
// ErrMediaClosed, and the receive channels drain shut.
func TestMediaClosePropagates(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, near, far, _, _ := mediaPair(t)

		if err := near.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		synctest.Wait()

		select {
		case <-far.Closed():
		default:
			t.Fatal("far Closed() not signalled after near.Close")
		}
		p := transport.GetMedia()
		defer p.Release()
		p.SetLen(1)
		if err := far.SendDatagram(16, p); !errors.Is(err, transport.ErrMediaClosed) {
			t.Errorf("SendDatagram on a closed session: err = %v, want ErrMediaClosed", err)
		}
		if err := near.SendMessage(context.Background(), 16, p); !errors.Is(err, transport.ErrMediaClosed) {
			t.Errorf("SendMessage on a closed session: err = %v, want ErrMediaClosed", err)
		}
		if _, ok := <-far.Datagrams(); ok {
			t.Error("far Datagrams delivered after close, want drained shut")
		}
		if _, ok := <-near.Messages(); ok {
			t.Error("near Messages delivered after close, want drained shut")
		}
	})
}

// Sending on a reserved channel is a programmer error and panics.
func TestMediaReservedChannelSendPanics(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, near, _, _, _ := mediaPair(t)
		defer near.Close()
		p := transport.GetMedia()
		defer p.Release()
		p.SetLen(1)
		defer func() {
			if recover() == nil {
				t.Error("SendDatagram on channel 3 did not panic")
			}
		}()
		_ = near.SendDatagram(3, p)
	})
}

// A frame arriving on a reserved channel is shed at the receive gate, counted,
// never delivered (level-2). Driven white-box: the public send side refuses to
// emit one, which is exactly why the receive side must still guard.
func TestMediaReservedChannelRxDropped(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, near, far, _, _ := mediaPair(t)
		defer near.Close()

		q := transport.GetMedia()
		n, err := transport.PutMediaFrame(q.Buf(), 3, []byte("core?"))
		if err != nil {
			t.Fatal(err)
		}
		q.SetLen(n)
		far.(*memMediaSession).receiveDatagram(q)

		if st := far.Stats(); st.RxDroppedReserved != 1 || st.RxDatagrams != 0 {
			t.Errorf("far stats = %+v, want RxDroppedReserved=1 RxDatagrams=0", st)
		}
		select {
		case <-far.Datagrams():
			t.Fatal("reserved-channel frame was delivered")
		default:
		}
	})
}

// With a shaper slowing the pump, the bounded tx-ring fills and SendDatagram
// refuses synchronously with ErrMediaBackpressure — the mirrored tx-ring that
// makes the earliest congestion signal testable.
func TestMediaBackpressure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hub, near, _, aID, bID := mediaPair(t)
		defer near.Close()
		// 100 B/s: one 101-byte frame takes >1 s, so the pump sleeps while the
		// sender floods.
		hub.SetLinkProfile(aID, bID, LinkProfile{RateBytesPerSec: 100})

		p := transport.GetMedia()
		defer p.Release()
		p.SetLen(100)

		if err := near.SendDatagram(16, p); err != nil {
			t.Fatalf("first send: %v", err)
		}
		synctest.Wait() // the pump now owns the first frame and sleeps on the shaper

		var backpressured int
		for range transport.MediaTxRing + 8 {
			if err := near.SendDatagram(16, p); errors.Is(err, transport.ErrMediaBackpressure) {
				backpressured++
			} else if err != nil {
				t.Fatalf("unexpected send error: %v", err)
			}
		}
		if backpressured != 8 {
			t.Errorf("backpressured sends = %d, want 8 (ring holds exactly MediaTxRing)", backpressured)
		}
		if st := near.Stats(); st.TxDroppedQueue != 8 {
			t.Errorf("TxDroppedQueue = %d, want 8", st.TxDroppedQueue)
		}
	})
}

// Loss is deterministic: the model's PRNG is seeded, so the exact set of
// surviving datagrams is reproducible — computed here by replaying the PRNG.
func TestMediaLinkLossDeterministic(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hub, near, far, aID, bID := mediaPair(t)
		defer near.Close()
		const seed, loss, total = 42, 0.5, 100
		hub.SetLinkProfile(aID, bID, LinkProfile{Seed: seed, Loss: loss})

		want := 0
		rng := mrand.New(mrand.NewPCG(seed, ^uint64(seed)))
		for range total {
			if rng.Float64() >= loss {
				want++
			}
		}

		for i := range total {
			sendDatagram(t, near, 16, byte(i))
		}
		got := 0
		for {
			select {
			case d := <-far.Datagrams():
				d.Pkt.Release()
				got++
				continue
			default:
			}
			break
		}
		if got != want {
			t.Errorf("delivered = %d, want %d (seeded loss must be reproducible)", got, want)
		}
		if st := far.Stats(); st.RxDatagrams != uint64(want) {
			t.Errorf("RxDatagrams = %d, want %d", st.RxDatagrams, want)
		}
	})
}

// The shaper queues datagrams behind each other (bufferbloat a delay-based
// estimator can see) and tail-drops past the queue bound, deterministically.
func TestMediaLinkShaperBufferbloat(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hub, near, far, aID, bID := mediaPair(t)
		defer near.Close()
		// 1200 B/s and 1200-byte frames: 1 s of transmission each; queue caps
		// at two frames' worth of backlog.
		hub.SetLinkProfile(aID, bID, LinkProfile{RateBytesPerSec: 1200, QueueBytes: 2400})

		t0 := time.Now()
		p := transport.GetMedia()
		p.SetLen(1199) // frame = 1199 + 1 channel byte = 1200
		for range 5 {
			if err := near.SendDatagram(16, p); err != nil {
				t.Fatalf("send: %v", err)
			}
		}
		p.Release()
		time.Sleep(10 * time.Second) // let the shaper drain everything

		var rxTimes []time.Time
		for {
			select {
			case d := <-far.Datagrams():
				rxTimes = append(rxTimes, d.RxTime)
				d.Pkt.Release()
				continue
			default:
			}
			break
		}
		// Frame 1 transmits in (0,1]s, frame 2 queues behind it ((1,2]s); 3–5
		// arrive to a full queue and tail-drop.
		if len(rxTimes) != 2 {
			t.Fatalf("delivered = %d datagrams, want 2 (queue overflow tail-drops)", len(rxTimes))
		}
		if want := t0.Add(1 * time.Second); !rxTimes[0].Equal(want) {
			t.Errorf("first RxTime = %v, want %v", rxTimes[0], want)
		}
		if want := t0.Add(2 * time.Second); !rxTimes[1].Equal(want) {
			t.Errorf("second RxTime = %v, want %v (queued behind the first)", rxTimes[1], want)
		}
	})
}

// Every Nth datagram is held back for the configured number of deliveries —
// explicit, deterministic reordering.
func TestMediaLinkReorder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hub, near, far, aID, bID := mediaPair(t)
		defer near.Close()
		hub.SetLinkProfile(aID, bID, LinkProfile{ReorderEvery: 3, ReorderHold: 2})

		for i := 1; i <= 8; i++ {
			sendDatagram(t, near, 16, byte(i))
		}
		var got []byte
		for {
			select {
			case d := <-far.Datagrams():
				got = append(got, d.Pkt.Bytes()[0])
				d.Pkt.Release()
				continue
			default:
			}
			break
		}
		want := []byte{1, 2, 4, 5, 3, 7, 8, 6}
		if string(got) != string(want) {
			t.Errorf("delivery order = %v, want %v", got, want)
		}
	})
}

// Jitter is deterministic and order-preserving: each datagram's extra delay
// replays from the seeded PRNG (with Loss = 0 the jitter draw is the only PRNG
// consumer), and the serial link still delivers in send order even when a
// later datagram drew a smaller delay.
func TestMediaLinkJitterDeterministic(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hub, near, far, aID, bID := mediaPair(t)
		defer near.Close()
		const seed, jitter, total = 7, time.Second, 10
		hub.SetLinkProfile(aID, bID, LinkProfile{Seed: seed, Jitter: jitter})

		t0 := time.Now()
		var want []time.Duration
		rng := mrand.New(mrand.NewPCG(seed, ^uint64(seed)))
		for range total {
			want = append(want, time.Duration(rng.Int64N(int64(jitter))))
		}

		for i := range total {
			sendDatagram(t, near, 16, byte(i))
		}
		time.Sleep(2 * jitter) // let every delayed delivery land

		var order []byte
		var rxTimes []time.Time
		for {
			select {
			case d := <-far.Datagrams():
				order = append(order, d.Pkt.Bytes()[0])
				rxTimes = append(rxTimes, d.RxTime)
				d.Pkt.Release()
				continue
			default:
			}
			break
		}
		if len(order) != total {
			t.Fatalf("delivered %d of %d datagrams", len(order), total)
		}
		floor := t0 // the serial link never reorders: each delivery ≥ the previous
		for i := range total {
			if order[i] != byte(i) {
				t.Fatalf("delivery order %v: jitter must not reorder a serial link", order)
			}
			at := t0.Add(want[i])
			if at.Before(floor) {
				at = floor // a smaller draw still waits its turn behind the previous frame
			}
			floor = at
			if !rxTimes[i].Equal(at) {
				t.Errorf("datagram %d RxTime = %v, want %v (seeded jitter must replay)", i, rxTimes[i], at)
			}
		}
	})
}

// A datagram over the link MTU is refused at send and visible to the sender
// (TxDroppedSend) — the mirror of the QUIC stack refusing an over-MTU datagram.
func TestMediaLinkMTU(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hub, near, far, aID, bID := mediaPair(t)
		defer near.Close()
		hub.SetLinkProfile(aID, bID, LinkProfile{MTU: 100})

		p := transport.GetMedia()
		defer p.Release()
		p.SetLen(200)
		if err := near.SendDatagram(16, p); err != nil {
			t.Fatalf("send: %v", err)
		}
		synctest.Wait()

		if st := near.Stats(); st.TxDroppedSend != 1 {
			t.Errorf("TxDroppedSend = %d, want 1", st.TxDroppedSend)
		}
		select {
		case <-far.Datagrams():
			t.Fatal("over-MTU datagram was delivered")
		default:
		}
	})
}

// The receive budget (level-2) sheds a flood before it reaches the queue, and
// the bounded queue drops the newest past its depth — every drop counted.
func TestMediaRxBudgetAndQueueBounds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, near, far, _, _ := mediaPair(t)
		defer near.Close()

		const total = 500 // all at one fake-clock instant: no budget refill
		p := transport.GetMedia()
		p.SetLen(1)
		for range total {
			if err := near.SendDatagram(16, p); err != nil {
				t.Fatalf("send: %v", err)
			}
			synctest.Wait() // pump drains each one; the ring never fills
		}
		p.Release()

		st := far.Stats()
		wantBudget := uint64(total - transport.MediaRxPPSBurst)
		if st.RxDroppedBudget != wantBudget {
			t.Errorf("RxDroppedBudget = %d, want %d (pps burst then refusal)", st.RxDroppedBudget, wantBudget)
		}
		wantQueue := uint64(transport.MediaRxPPSBurst - transport.MediaDatagramQueue)
		if st.RxDroppedQueue != wantQueue {
			t.Errorf("RxDroppedQueue = %d, want %d (drop-newest past the queue)", st.RxDroppedQueue, wantQueue)
		}
		if st.RxDatagrams != transport.MediaDatagramQueue {
			t.Errorf("RxDatagrams = %d, want %d", st.RxDatagrams, transport.MediaDatagramQueue)
		}

		// The receiver owns what was delivered: drain and Release the queue —
		// exactly the queue's depth must be waiting.
		near.Close()
		synctest.Wait()
		drained := 0
		for d := range far.Datagrams() {
			d.Pkt.Release()
			drained++
		}
		if drained != transport.MediaDatagramQueue {
			t.Errorf("drained %d datagrams, want %d", drained, transport.MediaDatagramQueue)
		}
	})
}

// The message queue is bounded too: past its depth the newest is dropped and
// counted, and the sender (reliable plane) is not poisoned by it.
func TestMediaMessageQueueBound(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, near, far, _, _ := mediaPair(t)
		defer near.Close()

		p := transport.Get()
		defer p.Release()
		p.SetLen(8)
		for range transport.MediaMessageQueue + 3 {
			if err := near.SendMessage(context.Background(), 16, p); err != nil {
				t.Fatalf("SendMessage: %v", err)
			}
		}
		synctest.Wait()
		st := far.Stats()
		if st.RxMessages != transport.MediaMessageQueue || st.RxDroppedMessages != 3 {
			t.Errorf("far stats = %+v, want RxMessages=%d RxDroppedMessages=3", st, transport.MediaMessageQueue)
		}

		// Drain and Release what was delivered — the receiver's ownership duty.
		near.Close()
		synctest.Wait()
		for m := range far.Messages() {
			m.Pkt.Release()
		}
	})
}

// When nobody consumes the peer's InboundMedia, OpenMedia mirrors the QUIC
// transport: the open SUCCEEDS (there the dialer's handshake completes before
// the acceptor refuses) and the session dies at once — the caller observes
// Closed(), not an error.
func TestMediaInboundOverflowClosesSession(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hub := NewHub()
		ta := newT(t, hub, id(1), "a")
		newT(t, hub, id(2), "b")
		baddr := transport.Addr{Net: "mem", Endpoint: "b"}

		var sessions []transport.MediaSession
		defer func() {
			for _, s := range sessions {
				s.Close()
			}
		}()
		for i := 0; i <= inMediaBuffer; i++ {
			s, err := ta.(transport.Media).OpenMedia(context.Background(), id(2), baddr)
			if err != nil {
				t.Fatalf("OpenMedia #%d: %v", i, err)
			}
			sessions = append(sessions, s)
		}
		synctest.Wait()
		// The first inMediaBuffer sessions sit in the unconsumed inbox alive;
		// the overflowing one is closed immediately.
		last := sessions[len(sessions)-1]
		select {
		case <-last.Closed():
		default:
			t.Fatal("session past the inbound buffer was not closed")
		}
		for i, s := range sessions[:len(sessions)-1] {
			select {
			case <-s.Closed():
				t.Errorf("buffered session #%d closed prematurely", i)
			default:
			}
		}
	})
}

// A partition blackholes datagrams without erroring the sender (the path is
// dark, not closed); healing restores flow on the same session.
func TestMediaPartitionBlackholesAndHeals(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hub, near, far, aID, bID := mediaPair(t)
		defer near.Close()

		hub.Partition(aID, bID)
		sendDatagram(t, near, 16, 'x')
		select {
		case <-far.Datagrams():
			t.Fatal("datagram crossed a partition")
		default:
		}

		hub.Heal(aID, bID)
		sendDatagram(t, near, 16, 'y')
		got, _ := recvDatagram(t, far)
		if string(got) != "y" {
			t.Errorf("after heal got %q, want y", got)
		}
	})
}

// A partition outlasting the idle timeout kills the session — the mirror of
// QUIC's keepalive going unanswered until the idle timer fires. The owner
// observes it on Closed() and every later send refuses with ErrMediaClosed.
func TestMediaIdleDeathUnderPartition(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hub, near, far, aID, bID := mediaPair(t)

		hub.Partition(aID, bID)
		time.Sleep(mediaIdleTimeout + mediaIdleTimeout/2)

		select {
		case <-near.Closed():
		default:
			t.Fatal("near not closed after the partition outlasted the idle timeout")
		}
		select {
		case <-far.Closed():
		default:
			t.Fatal("far not closed after the partition outlasted the idle timeout")
		}
		p := transport.GetMedia()
		defer p.Release()
		p.SetLen(1)
		if err := near.SendDatagram(16, p); !errors.Is(err, transport.ErrMediaClosed) {
			t.Errorf("SendDatagram after idle death: err = %v, want ErrMediaClosed", err)
		}
	})
}

// A short partition (healed before the idle timeout) does NOT kill the session.
func TestMediaShortPartitionSurvives(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hub, near, far, aID, bID := mediaPair(t)
		defer near.Close()

		hub.Partition(aID, bID)
		time.Sleep(mediaIdleTimeout / 2)
		hub.Heal(aID, bID)
		time.Sleep(2 * mediaIdleTimeout)

		select {
		case <-near.Closed():
			t.Fatal("session died despite the partition healing inside the idle window")
		default:
		}
		sendDatagram(t, near, 16, 'z')
		if got, _ := recvDatagram(t, far); string(got) != "z" {
			t.Errorf("after short partition got %q, want z", got)
		}
	})
}

// Closing the transport tears its media sessions down and closes InboundMedia.
func TestMediaTransportCloseTearsSessions(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hub := NewHub()
		ta := newT(t, hub, id(1), "a")
		tb := newT(t, hub, id(2), "b")
		near, err := ta.(transport.Media).OpenMedia(context.Background(), id(2), transport.Addr{Net: "mem", Endpoint: "b"})
		if err != nil {
			t.Fatalf("OpenMedia: %v", err)
		}
		far := <-tb.(transport.Media).InboundMedia()

		_ = ta.Close()
		synctest.Wait()
		select {
		case <-near.Closed():
		default:
			t.Error("near session survived its transport's Close")
		}
		select {
		case <-far.Closed():
		default:
			t.Error("far session survived the peer transport's Close")
		}
		_ = tb.Close()
		if _, ok := <-tb.(transport.Media).InboundMedia(); ok {
			t.Error("InboundMedia delivered after Close, want closed channel")
		}
	})
}
