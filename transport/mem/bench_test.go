package mem

import (
	"context"
	"testing"

	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/wire"
)

// benchEdge brings up two transports on a hub with a roomy inbound buffer and
// returns the dialer's edge plus the receiving transport. The buffer keeps a
// single-goroutine send-then-receive loop from blocking.
func benchEdge(b *testing.B) (transport.Conn, transport.Transport) {
	b.Helper()
	h := NewHub(WithInboundBuffer(1024))
	idA, idB := nodeID(1), nodeID(2)
	a, _ := h.New(idA, addr("a"))
	bt, _ := h.New(idB, addr("b"))
	b.Cleanup(func() { a.Close(); bt.Close() })
	conn, err := a.Dial(context.Background(), idB, addr("b"))
	if err != nil {
		b.Fatalf("Dial: %v", err)
	}
	return conn, bt
}

// BenchmarkSendRecv is the forwarding hot path: encode a small frame into a
// pooled Packet, Send it (which copies into the peer's pooled Packet; Send borrows
// ours, so we Release it), receive it, parse, and Release. Both Packets come from
// the pool, so steady state must be 0 allocs/op. b.Loop keeps the body live.
func BenchmarkSendRecv(b *testing.B) {
	conn, bt := benchEdge(b)
	payload := []byte("small control frame")
	b.ReportAllocs()
	for b.Loop() {
		p := transport.Get()
		frame, _ := wire.EncodeFrame(p.Buf(), testType, payload)
		p.SetLen(len(frame))
		if err := conn.Send(p); err != nil {
			b.Fatalf("Send: %v", err)
		}
		p.Release()
		d := <-bt.Inbound()
		_, _, _, _ = wire.ParseFrame(d.Pkt.Bytes())
		d.Pkt.Release()
	}
}

// benchMediaPair opens a media session between two fresh transports.
func benchMediaPair(b *testing.B) (near, far transport.MediaSession) {
	b.Helper()
	h := NewHub()
	a, _ := h.New(nodeID(1), addr("a"))
	bt, _ := h.New(nodeID(2), addr("b"))
	b.Cleanup(func() { a.Close(); bt.Close() })
	near, err := a.(transport.Media).OpenMedia(context.Background(), nodeID(2), addr("b"))
	if err != nil {
		b.Fatalf("OpenMedia: %v", err)
	}
	return near, <-bt.(transport.Media).InboundMedia()
}

// BenchmarkMediaSendDatagram is the datagram send path: copy into a media-class
// pooled buffer, plan the (ideal) link, queue on the tx-ring — with the pump
// draining concurrently. The gate is 0 allocs/op. A backpressured send (the
// pump briefly behind at full speed) refuses without allocating, so it stays in
// the measurement rather than failing it.
func BenchmarkMediaSendDatagram(b *testing.B) {
	near, _ := benchMediaPair(b)
	p := transport.GetMedia()
	defer p.Release()
	p.SetLen(transport.MaxMediaDatagram)
	b.SetBytes(transport.MaxMediaDatagram)
	b.ReportAllocs()
	for b.Loop() {
		_ = near.SendDatagram(transport.FirstAppChannel, p)
	}
	near.Close()
}

// BenchmarkMediaReceiveGate is the datagram receive path, driven white-box:
// budget charge, frame split, in-place slide, bounded queue — and the
// consumer's Release. The gate is 0 allocs/op. At benchmark speed the receive
// budget sheds most frames — that branch is part of the path and is just as
// allocation-free.
func BenchmarkMediaReceiveGate(b *testing.B) {
	_, far := benchMediaPair(b)
	sess := far.(*memMediaSession)
	frame := make([]byte, transport.MaxMediaDatagram+1)
	frame[0] = transport.FirstAppChannel
	b.SetBytes(int64(len(frame)))
	b.ReportAllocs()
	for b.Loop() {
		q := transport.GetMedia()
		q.SetLen(copy(q.Buf(), frame))
		sess.receiveDatagram(q)
		select {
		case d := <-sess.datagrams:
			d.Pkt.Release()
		default:
		}
	}
	far.Close()
}

// BenchmarkThroughput measures sustained bytes/sec over one edge with a larger
// payload, reporting MB/s via SetBytes alongside the allocation count.
func BenchmarkThroughput(b *testing.B) {
	conn, bt := benchEdge(b)
	payload := make([]byte, 4096)
	var frameLen int
	{
		p := transport.Get()
		frame, _ := wire.EncodeFrame(p.Buf(), testType, payload)
		frameLen = len(frame)
		p.Release()
	}
	b.SetBytes(int64(frameLen))
	b.ReportAllocs()
	for b.Loop() {
		p := transport.Get()
		frame, _ := wire.EncodeFrame(p.Buf(), testType, payload)
		p.SetLen(len(frame))
		if err := conn.Send(p); err != nil {
			b.Fatalf("Send: %v", err)
		}
		p.Release()
		d := <-bt.Inbound()
		d.Pkt.Release()
	}
}
