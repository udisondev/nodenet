package node

import (
	"context"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/routing"
	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/transport/mem"
	"github.com/udisondev/nodenet/wire"
)

// TestDispatchLoopSurvivesStalledControlReply: the single dispatch loop answers a
// ping with a pong sent back over the pinger's edge. A peer that stops draining its
// receive side (its inbound channel full, never read) would, with an unbounded send,
// block that pong forever — wedging ALL forwarding and delivery for every other peer,
// since the loop is single-goroutine and TypePing is deliberately not rate-limited.
// The control reply must ride the same bounded send the forward path uses: the stuck
// send fails fast, the stalled edge is dropped, and the loop keeps serving everyone
// else.
func TestDispatchLoopSurvivesStalledControlReply(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// No WithSendBound on the hub: without the bounded control send the pong
		// would block forever (the exact config the forward path already survives).
		hub := mem.NewHub(mem.WithInboundBuffer(1))
		aIdn := identity.FromSeed(seedFor(1))
		aT, err := hub.New(aIdn.ID(), transport.Addr{Net: "mem", Endpoint: "a"})
		if err != nil {
			t.Fatalf("New a: %v", err)
		}
		a := New(aIdn, aT, WithoutMaintenance())
		bIdn := identity.FromSeed(seedFor(2))
		bT, err := hub.New(bIdn.ID(), transport.Addr{Net: "mem", Endpoint: "b"})
		if err != nil {
			t.Fatalf("New b: %v", err)
		}
		cIdn := identity.FromSeed(seedFor(3))
		cT, err := hub.New(cIdn.ID(), transport.Addr{Net: "mem", Endpoint: "c"})
		if err != nil {
			t.Fatalf("New c: %v", err)
		}

		// Fill B's inbound buffer (cap 1) so A's pong to B cannot be delivered —
		// B is the stalled peer: it sends but never reads.
		fillConn, err := cT.Dial(context.Background(), bIdn.ID(), transport.Addr{Net: "mem", Endpoint: "b"})
		if err != nil {
			t.Fatalf("Dial c→b: %v", err)
		}
		fill := transport.Get()
		fill.SetLen(1)
		if err := fillConn.Send(fill); err != nil {
			t.Fatalf("fill Send: %v", err)
		}
		fill.Release()

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { _ = a.Run(ctx); close(done) }()

		// The stalled B pings A: A's pong back to B has nowhere to land.
		bConn, err := bT.Dial(context.Background(), aIdn.ID(), transport.Addr{Net: "mem", Endpoint: "a"})
		if err != nil {
			t.Fatalf("Dial b→a: %v", err)
		}
		sendControl(t, bConn, routing.EncodePingFrame)

		// A healthy peer C pings A next; its pong proves the loop is still alive.
		cConn, err := cT.Dial(context.Background(), aIdn.ID(), transport.Addr{Net: "mem", Endpoint: "a"})
		if err != nil {
			t.Fatalf("Dial c→a: %v", err)
		}
		sendControl(t, cConn, routing.EncodePingFrame)

		select {
		case d := <-cT.Inbound():
			typ, _, _, perr := wire.ParseFrame(d.Pkt.Bytes())
			d.Pkt.Release()
			if perr != nil || typ != routing.TypePong {
				t.Fatalf("healthy peer received type %d (err %v), want pong", typ, perr)
			}
		case <-time.After(time.Minute):
			t.Fatal("dispatch loop wedged on a stalled control reply: healthy peer got no pong")
		}
		// The stalled edge failed fast and was dropped, not left to wedge again.
		if _, ok := a.Edges().Conn(bIdn.ID()); ok {
			t.Fatal("stalled peer's edge survived the timed-out control reply")
		}

		cancel()
		<-done
	})
}

// boundedModeConn records which send path a frame left on: the transport's plain
// (possibly unbounded) Send or the per-send-budget SendBounded. Pointer-identity so
// each instance is a distinct edge.
type boundedModeConn struct {
	id      kad.ID
	send    atomic.Int32
	bounded atomic.Int32
}

func (c *boundedModeConn) Remote() kad.ID               { return c.id }
func (c *boundedModeConn) RemoteAddr() transport.Addr   { return transport.Addr{} }
func (c *boundedModeConn) Send(*transport.Packet) error { c.send.Add(1); return nil }
func (c *boundedModeConn) Close() error                 { return nil }
func (c *boundedModeConn) SendBounded(*transport.Packet, time.Duration) error {
	c.bounded.Add(1)
	return nil
}

// TestPeerFacingSendsUseBoundedPath: every send that targets a peer-controlled edge
// from the dispatch loop or the maintenance goroutine — keepalive ping, pong reply
// (sendFrame, which also carries the relay grant/bind), neighbours answers (direct
// and routed), and the origination fan-out — must use the bounded send when a
// forward deadline is set, exactly like the forward path. A plain Send here re-opens
// the stalled-peer wedge WithForwardSendDeadline exists to close.
func TestPeerFacingSendsUseBoundedPath(t *testing.T) {
	cases := []struct {
		name     string
		exercise func(t *testing.T, n *Node, conn *boundedModeConn)
	}{
		{"keepalive ping", func(t *testing.T, n *Node, conn *boundedModeConn) {
			n.ping(conn)
		}},
		{"pong reply", func(t *testing.T, n *Node, conn *boundedModeConn) {
			n.handlePing(conn)
		}},
		{"neighbours direct", func(t *testing.T, n *Node, conn *boundedModeConn) {
			cs := []routing.Contact{n.selfContact()}
			n.sendNeighbors(conn.id, cs, conn, [routing.LookupNonceLen]byte{1})
		}},
		{"neighbours routed", func(t *testing.T, n *Node, conn *boundedModeConn) {
			target := n.ID()
			target[0] ^= 0xff
			cs := []routing.Contact{n.selfContact()}
			n.sendNeighbors(target, cs, nil, [routing.LookupNonceLen]byte{1})
		}},
		{"origination", func(t *testing.T, n *Node, conn *boundedModeConn) {
			target := n.ID()
			target[0] ^= 0xff
			if err := n.originate(target, routing.TypeRoute, []byte("x")); err != nil {
				t.Fatalf("originate: %v", err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				n := newBareNode(t, 1)
				peer := n.ID()
				peer[1] ^= 0x40
				conn := &boundedModeConn{id: peer}
				if err := n.e.AddEdge(conn, true, 0, time.Now()); err != nil {
					t.Fatalf("AddEdge: %v", err)
				}
				tc.exercise(t, n, conn)
				synctest.Wait() // origination dispatches its copies on goroutines
				if conn.bounded.Load() == 0 || conn.send.Load() != 0 {
					t.Fatalf("frames sent: %d plain, %d bounded; want every send on the bounded path",
						conn.send.Load(), conn.bounded.Load())
				}
			})
		})
	}
}
