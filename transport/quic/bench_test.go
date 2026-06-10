package quic

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/udisondev/nodenet/transport"
)

// nopWriter is a concrete, non-retaining sink, mirroring how quic-go's
// Stream.Write consumes bytes synchronously — so the framing write benches the
// real escape behaviour rather than an interface-induced heap escape.
type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

// BenchmarkWriteFrame measures the Send hot path's framing: a uvarint length
// prefix written from the reused per-connection scratch, then the payload. With
// the scratch preallocated (as it is on quicConn) the write is allocation-free —
// it must report 0 allocs/op.
func BenchmarkWriteFrame(b *testing.B) {
	payload := []byte("small control frame")
	var whdr [binary.MaxVarintLen64]byte // stands in for quicConn.whdr (allocated once)
	var sink nopWriter
	b.ReportAllocs()
	for b.Loop() {
		n := binary.PutUvarint(whdr[:], uint64(len(payload)))
		if _, err := sink.Write(whdr[:n]); err != nil {
			b.Fatalf("write hdr: %v", err)
		}
		if _, err := sink.Write(payload); err != nil {
			b.Fatalf("write payload: %v", err)
		}
	}
}

// BenchmarkMediaSendDatagramQUIC measures the datagram send path over a real
// loopback connection: our gate (copy into the media pool + tx-ring — proven
// 0 allocs/op by the mem mirror's benchmarks) plus everything upstream of it.
// The figure is dominated by quic-go on both ends of the in-process pair (its
// SendDatagram copies into a fresh frame, its receive path allocates
// internally); our own additions stay allocation-free, and the receiver's
// budget gate sheds the flood BEFORE any pool copy, so no pooled buffer churn
// appears either. A backpressured send (the pump briefly behind) refuses
// without allocating and stays in the measurement.
func BenchmarkMediaSendDatagramQUIC(b *testing.B) {
	a, err := Listen(idFromByte(1), "127.0.0.1:0")
	if err != nil {
		b.Fatalf("Listen: %v", err)
	}
	defer a.Close()
	peer, err := Listen(idFromByte(2), "127.0.0.1:0")
	if err != nil {
		b.Fatalf("Listen peer: %v", err)
	}
	defer peer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	near, err := a.(transport.Media).OpenMedia(ctx, idFromByte(2).ID(), peer.LocalAddr())
	if err != nil {
		b.Fatalf("OpenMedia: %v", err)
	}
	far := <-peer.(transport.Media).InboundMedia()
	defer near.Close()
	// Drain whatever survives the far end's budget so its queue counters do
	// not saturate mid-benchmark.
	go func() {
		for d := range far.Datagrams() {
			d.Pkt.Release()
		}
	}()

	p := transport.GetMedia()
	defer p.Release()
	p.SetLen(transport.MaxMediaDatagram)
	b.SetBytes(transport.MaxMediaDatagram)
	b.ReportAllocs()
	for b.Loop() {
		_ = near.SendDatagram(transport.FirstAppChannel, p)
	}
}

// BenchmarkReadFrame measures the read path's length-prefix parse over a buffered
// reader, the per-frame cost of the read loop's framing. Target 0 allocs/op.
func BenchmarkReadFrame(b *testing.B) {
	frame := appendFrame(nil, []byte("small control frame"))
	src := bytes.NewReader(nil)
	br := bufio.NewReader(src)
	b.ReportAllocs()
	for b.Loop() {
		src.Reset(frame)
		br.Reset(src)
		n, err := readFrameLen(br)
		if err != nil {
			b.Fatalf("readFrameLen: %v", err)
		}
		if _, err := br.Discard(n); err != nil {
			b.Fatalf("discard: %v", err)
		}
	}
}
