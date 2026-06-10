package node

import (
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/routing"
	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/transport/mem"
	"github.com/udisondev/nodenet/wire"
)

// seedFor turns a small integer into a deterministic master-seed, so tests get
// stable distinct identities.
func seedFor(i uint64) [identity.SeedLen]byte {
	var s [identity.SeedLen]byte
	binary.BigEndian.PutUint64(s[:], i)
	return s
}

// solicit registers a correlation nonce in n's pending-lookup set as if n had sent a
// lookup/sibling request, so a hand-built neighbours response echoing that nonce passes the
// solicitation gate. Tests that inject a response directly — bypassing the maintenance loop
// that registers the nonce in the real flow — use it.
func solicit(n *Node, nonce [routing.LookupNonceLen]byte) {
	n.pendingLookupMu.Lock()
	n.pendingLookup[nonce] = time.Now().Add(time.Hour).UnixNano()
	n.pendingLookupMu.Unlock()
}

// newBareNode builds a Node on its own hub without starting Run — for driving handle
// and Send directly.
func newBareNode(t testing.TB, seed uint64, opts ...Option) *Node {
	t.Helper()
	idn := identity.FromSeed(seedFor(seed))
	tr, err := mem.NewHub().New(idn.ID(), transport.Addr{Net: "mem", Endpoint: "x"})
	if err != nil {
		t.Fatalf("hub.New: %v", err)
	}
	return New(idn, tr, opts...)
}

// stubConn is a no-op transport.Conn for wiring edges in handler unit tests and
// benchmarks: it carries an identity and drops sends.
type stubConn struct{ id kad.ID }

func (c stubConn) Remote() kad.ID               { return c.id }
func (c stubConn) RemoteAddr() transport.Addr   { return transport.Addr{} }
func (c stubConn) Send(*transport.Packet) error { return nil }
func (c stubConn) Close() error                 { return nil }

// captureConn records the bytes of every frame sent on it, for asserting what an
// originator emits (one copy per disjoint path). Origination dispatches the copies
// concurrently, so the recorder is mutex-guarded and signals each send on wg, letting the
// test wait for all copies before inspecting them.
type captureConn struct {
	id     kad.ID
	mu     *sync.Mutex
	frames *[][]byte
	wg     *sync.WaitGroup
}

func (c captureConn) Remote() kad.ID             { return c.id }
func (c captureConn) RemoteAddr() transport.Addr { return transport.Addr{} }
func (c captureConn) Send(p *transport.Packet) error {
	c.mu.Lock()
	*c.frames = append(*c.frames, append([]byte(nil), p.Bytes()...))
	c.mu.Unlock()
	c.wg.Done()
	return nil
}
func (c captureConn) Close() error { return nil }

// TestSendDisjointPaths: origination emits one copy per first hop (up to d), each
// carrying the OTHER first hops in its avoid-set, all built in one reused buffer.
func TestSendDisjointPaths(t *testing.T) {
	n := newBareNode(t, 1)
	target := n.ID()
	target[0] ^= 0xff

	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		captured [][]byte
	)
	wg.Add(routing.KMin)
	ids := make([]kad.ID, 0, routing.KMin)
	for k := byte(1); k <= routing.KMin; k++ {
		id := n.ID()
		id[1] ^= k // distinct, not self
		ids = append(ids, id)
		if err := n.e.AddEdge(captureConn{id: id, mu: &mu, frames: &captured, wg: &wg}, true, 0, time.Now()); err != nil {
			t.Fatalf("AddEdge: %v", err)
		}
	}

	if err := n.Send(target, []byte("multi")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	wg.Wait() // origination fans the copies out concurrently; wait for all to land
	if len(captured) != routing.KMin {
		t.Fatalf("emitted %d copies, want d=%d", len(captured), routing.KMin)
	}

	idSet := make(map[kad.ID]bool, len(ids))
	for _, id := range ids {
		idSet[id] = true
	}
	// Each copy avoids exactly the d-1 other first hops; across all copies every
	// first hop is the "missing" one exactly once (so each path is distinct).
	missing := make(map[kad.ID]int)
	for _, frame := range captured {
		_, payload, _, err := wire.ParseFrame(frame)
		if err != nil {
			t.Fatalf("ParseFrame: %v", err)
		}
		m, err := routing.DecodeMsg(payload)
		if err != nil {
			t.Fatalf("DecodeMsg: %v", err)
		}
		if m.Target != target || string(m.Payload) != "multi" {
			t.Errorf("copy target/payload mismatch")
		}
		if m.Avoid.Len() != routing.KMin-1 {
			t.Errorf("avoid len = %d, want %d", m.Avoid.Len(), routing.KMin-1)
		}
		avoided := make(map[kad.ID]bool)
		for j := 0; j < m.Avoid.Len(); j++ {
			a := m.Avoid.At(j)
			if !idSet[a] {
				t.Errorf("avoid contains non-first-hop %v", a)
			}
			avoided[a] = true
		}
		for id := range idSet {
			if !avoided[id] {
				missing[id]++
			}
		}
	}
	for _, id := range ids {
		if missing[id] != 1 {
			t.Errorf("first hop %v is the path target in %d copies, want 1", id, missing[id])
		}
	}
}

func TestSendUnroutable(t *testing.T) {
	n := newBareNode(t, 1)
	if err := n.Send(kad.ID{1}, []byte("hi")); !errors.Is(err, ErrUnroutable) {
		t.Errorf("Send with no live edges: err = %v, want ErrUnroutable", err)
	}
}

// A malformed or non-routing frame must be dropped without panic and without
// delivering anything.
func TestHandleMalformed(t *testing.T) {
	n := newBareNode(t, 1)
	for _, frame := range [][]byte{
		{0xff, 0xff, 0xff}, // bad version
		nil,                // empty
		{1, byte(routing.TypeRoute), 0x05, 0x01, 0x02}, // TypeRoute but truncated msg
	} {
		p := transport.Get()
		p.SetLen(copy(p.Buf(), frame))
		n.handle(transport.Delivery{Pkt: p})
	}
	select {
	case <-n.Deliveries():
		t.Fatal("delivered from malformed input")
	default:
	}
}

// target == self delivers the payload up.
func TestHandleDeliverSelf(t *testing.T) {
	n := newBareNode(t, 1)
	p := transport.Get()
	msg := routing.Msg{Target: n.ID(), TTL: routing.MaxHops, EdPub: n.edPub, Payload: []byte("me")}
	routing.SignMsg(n.id, routing.TypeRoute, &msg, time.Now())
	w, err := routing.EncodeRouteFrame(p.Buf(), &msg)
	if err != nil {
		t.Fatalf("EncodeRouteFrame: %v", err)
	}
	p.SetLen(w)
	n.handle(transport.Delivery{Pkt: p})

	select {
	case got := <-n.Deliveries():
		if string(got.Payload) != "me" {
			t.Errorf("payload = %q, want me", got.Payload)
		}
		if got.Originator != n.ID() {
			t.Errorf("originator = %v, want self", got.Originator)
		}
	default:
		t.Fatal("self-delivery missing")
	}
}

// handle on a forwarded packet is the hot path: parse, PoW, Decide, in-place TTL
// patch, send. With pooled packets and a pre-sized hopsBuf it must not allocate.
func BenchmarkHandleForward(b *testing.B) {
	n := newBareNode(b, 1)
	self := n.ID()
	target := self
	target[0] ^= 0xff // far from self
	near := self
	near[0] ^= 0xf0 // strictly closer to target than self
	if err := n.e.AddEdge(stubConn{id: near}, true, 0, time.Now()); err != nil {
		b.Fatalf("AddEdge: %v", err)
	}

	// A forwarded packet is not signature-verified, but it IS freshness-checked, so the
	// frame's timestamp is re-stamped periodically below: a long -benchtime run (or one
	// under -race) would otherwise cross MaxEnvelopeAge mid-loop and silently measure
	// the stale-drop path instead of forwarding. A forwarder never checks the signature,
	// so re-encoding with a fresh Sent needs no re-sign.
	buf := make([]byte, transport.MaxPacketLen)
	msg := routing.Msg{Target: target, TTL: 10, EdPub: n.edPub, Payload: []byte("control")}
	var frame []byte
	restamp := func() {
		msg.Sent = time.Now().UnixNano()
		w, err := routing.EncodeRouteFrame(buf, &msg)
		if err != nil {
			b.Fatalf("EncodeRouteFrame: %v", err)
		}
		frame = buf[:w]
	}
	restamp()

	b.ReportAllocs()
	i := 0
	for b.Loop() {
		// Refresh roughly every 0.2 s of iterations — amortized to nothing, and the
		// timestamp can never go stale no matter how long the run.
		if i++; i&(1<<20-1) == 0 {
			restamp()
		}
		p := transport.Get()
		p.SetLen(copy(p.Buf(), frame))
		n.handle(transport.Delivery{Pkt: p})
	}
	// Belt and braces: if any iteration still fell onto a defensive drop path, the run
	// measured the wrong thing — fail loudly instead of publishing wrong numbers.
	if s := n.Stats(); s.DroppedStale != 0 || s.DroppedRateLimited != 0 {
		b.Fatalf("benchmark left the forward path: %d stale, %d rate-limited drops", s.DroppedStale, s.DroppedRateLimited)
	}
}
