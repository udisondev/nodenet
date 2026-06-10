//go:build e2e_real

// These tests run the production QUIC transport over a real loopback UDP socket
// under real time, so they are gated behind the e2e_real build tag and excluded
// from the default `go test ./...`. Run them with:
//
//	go test -tags e2e_real ./transport/quic
package quic

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/udisondev/nodenet/routing"
	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/transport/transporttest"
	"github.com/udisondev/nodenet/wire"
)

// quicFactory adapts the loopback QUIC transport to the shared contract suite. It
// runs bodies directly under real time (no synctest) and uses a dead loopback
// port as the no-route address.
type quicFactory struct{}

func (quicFactory) New(t *testing.T, seed byte) (transport.Transport, transport.Addr) {
	t.Helper()
	tr, err := Listen(idFromSeed(seed), "127.0.0.1:0", WithHandshakeTimeout(2*time.Second))
	if err != nil {
		t.Fatalf("Listen(seed %d): %v", seed, err)
	}
	t.Cleanup(func() { tr.Close() })
	return tr, tr.LocalAddr()
}

func (quicFactory) Run(t *testing.T, fn func(t *testing.T)) { fn(t) }

func (quicFactory) NoRouteAddr() transport.Addr {
	return transport.Addr{Net: "quic", Endpoint: "127.0.0.1:1"} // nothing listens here
}

// TestContract runs the shared transport contract suite over real QUIC, the same
// suite transport/mem passes — proving the QUIC transport is a drop-in pipe.
func TestContract(t *testing.T) {
	transporttest.RunContract(t, func() transporttest.Factory { return quicFactory{} })
}

// TestMediaSaturationDoesNotStarveOverlay is the media track's mandatory
// real-QUIC gate: a session saturated with datagrams for a while — two real
// congestion controllers interacting, which the in-memory mirror cannot show —
// must neither kill the overlay edge between the same two transports nor stop
// its frames. The edge and the call are separate connections, so quic-go's
// datagram-over-stream priority applies only inside the call.
func TestMediaSaturationDoesNotStarveOverlay(t *testing.T) {
	f := quicFactory{}
	a, _ := f.New(t, 1)
	b, baddr := f.New(t, 2)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	edge, err := a.Dial(ctx, transporttest.IDFromSeed(2), baddr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	sess, err := a.(transport.Media).OpenMedia(ctx, transporttest.IDFromSeed(2), baddr)
	if err != nil {
		t.Fatalf("OpenMedia: %v", err)
	}
	defer sess.Close()
	far := <-b.(transport.Media).InboundMedia()
	var received atomic.Int64
	go func() { // drain the survivors so queues do not mask anything
		for d := range far.Datagrams() {
			d.Pkt.Release()
			received.Add(1)
		}
	}()

	// The flooder: saturate the call for the whole test.
	floodCtx, floodCancel := context.WithCancel(ctx)
	defer floodCancel()
	go func() {
		p := transport.GetMedia()
		defer p.Release()
		p.SetLen(transport.MaxMediaDatagram)
		for floodCtx.Err() == nil {
			_ = sess.SendDatagram(transport.FirstAppChannel, p) // backpressure expected, keep pushing
		}
	}()

	// Meanwhile the overlay edge must keep moving frames, promptly.
	deadline := time.Now().Add(3 * time.Second)
	frames := 0
	for time.Now().Before(deadline) {
		p := transport.Get()
		frame, _ := wire.EncodeFrame(p.Buf(), transporttest.TestType, []byte("transit"))
		p.SetLen(len(frame))
		err := edge.Send(p)
		p.Release()
		if err != nil {
			t.Fatalf("overlay Send during media saturation: %v (edge reaped?)", err)
		}
		select {
		case d := <-b.Inbound():
			d.Pkt.Release()
			frames++
		case <-time.After(2 * time.Second):
			t.Fatal("overlay frame starved by media saturation")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if frames == 0 {
		t.Fatal("no overlay frames moved during the saturated call")
	}
	// The gate must not pass vacuously: the saturation has to have actually
	// happened — the session alive throughout, datagrams really crossing.
	select {
	case <-sess.Closed():
		t.Fatal("media session died during saturation; the gate measured nothing")
	default:
	}
	if received.Load() == 0 {
		t.Fatal("no media datagrams crossed during saturation; the gate measured nothing")
	}
	st := sess.Stats()
	if st.TxDatagrams == 0 {
		t.Fatal("flooder queued no datagrams; the gate measured nothing")
	}
	t.Logf("overlay moved %d frames during %v of media saturation; media delivered %d; session stats: %+v",
		frames, 3*time.Second, received.Load(), st)
}

// TestRemoteAddrParsesForSubnet checks that the address a peer is reached at is a
// real "ip:port" that routing.SubnetFromHostPort accepts — the seam the node
// layer uses for subnet-diversity accounting.
func TestRemoteAddrParsesForSubnet(t *testing.T) {
	f := quicFactory{}
	a, _ := f.New(t, 1)
	b, baddr := f.New(t, 2)

	conn, err := a.Dial(context.Background(), transporttest.IDFromSeed(2), baddr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if _, ok := routing.SubnetFromHostPort(conn.RemoteAddr()); !ok {
		t.Fatalf("RemoteAddr %q not parseable by SubnetFromHostPort", conn.RemoteAddr())
	}
	_ = b
}
