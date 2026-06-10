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
