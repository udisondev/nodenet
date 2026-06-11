package node

import (
	"testing"
	"time"

	"github.com/udisondev/nodenet/routing"
	"github.com/udisondev/nodenet/transport"
)

// pongDelivery hands handle a TypePong from conn whose payload reports observed as
// this node's externally-visible address.
func pongDelivery(t *testing.T, n *Node, conn transport.Conn, observed transport.Addr) {
	t.Helper()
	p := transport.Get()
	w, err := routing.EncodePongFrame(p.Buf(), observed)
	if err != nil {
		p.Release()
		t.Fatalf("EncodePongFrame: %v", err)
	}
	p.SetLen(w)
	n.handle(transport.Delivery{Conn: conn, Pkt: p})
}

// TestTrailingFrameDoesNotResurrectDroppedEdge: the inbound channel is FIFO, so a
// frame a peer enqueued just before its edge was dropped is processed after the drop.
// To handle's bookkeeping it looks like the first frame over a new peer-initiated
// edge (Touch misses), so without a tombstone it would re-register the now-CLOSED
// conn as a fresh inbound edge — and, if the trailing frame is a pong, re-add the
// very reflexive report dropEdge just removed, defeating its guarantee that a dead
// neighbour stops corroborating this node's external address. A trailing frame on a
// just-dropped conn must be discarded instead.
func TestTrailingFrameDoesNotResurrectDroppedEdge(t *testing.T) {
	n := newBareNode(t, 1)
	ext := transport.Addr{Net: "mem", Endpoint: "ext"}

	// Three neighbours agree on ext, establishing reflexive consensus (the in-memory
	// transport carries no subnet info, so the count alone confirms).
	conns := make([]*closeRecordConn, 3)
	for i := range conns {
		id := n.ID()
		id[2] ^= byte(i + 1)
		conns[i] = &closeRecordConn{id: id}
		if err := n.e.AddEdge(conns[i], false, 0, time.Now()); err != nil {
			t.Fatalf("AddEdge %d: %v", i, err)
		}
		pongDelivery(t, n, conns[i], ext)
	}
	if r := n.Reflexive(); r != ext {
		t.Fatalf("setup: quorum did not confirm reflexive (got %v)", r)
	}

	// Drop the first neighbour: its edge goes, and with it its reflexive report —
	// two remaining reports are below quorum.
	dropped := conns[0]
	n.dropEdge(dropped.id, "test")
	if !dropped.closed.Load() {
		t.Fatal("setup: dropEdge did not close the conn")
	}
	if r := n.Reflexive(); r != (transport.Addr{}) {
		t.Fatalf("setup: dropEdge left the dropped neighbour's report (reflexive %v)", r)
	}

	// A pong from the dropped peer that was already queued when the drop ran: it
	// arrives on the SAME closed conn and must be discarded, not re-admitted.
	pongDelivery(t, n, dropped, ext)

	if _, ok := n.e.Conn(dropped.id); ok {
		t.Fatal("trailing frame re-registered the just-dropped edge on its closed conn")
	}
	if r := n.Reflexive(); r != (transport.Addr{}) {
		t.Fatalf("trailing pong re-added the reflexive report dropEdge removed (reflexive %v)", r)
	}
}

// TestRedialAfterDropRegisters: the tombstone keys on the closed conn, not the peer,
// so a peer that honestly re-dials right after a drop — a FRESH conn, the same
// NodeID — registers as a live edge unhindered, even inside the tombstone window.
func TestRedialAfterDropRegisters(t *testing.T) {
	n := newBareNode(t, 1)
	peer := n.ID()
	peer[2] ^= 0x11

	old := &closeRecordConn{id: peer}
	if err := n.e.AddEdge(old, false, 0, time.Now()); err != nil {
		t.Fatalf("AddEdge: %v", err)
	}
	n.dropEdge(peer, "test")

	// The peer re-dials at once: its first frame arrives on a new conn.
	fresh := &closeRecordConn{id: peer}
	p := transport.Get()
	w, err := routing.EncodePingFrame(p.Buf())
	if err != nil {
		p.Release()
		t.Fatalf("EncodePingFrame: %v", err)
	}
	p.SetLen(w)
	n.handle(transport.Delivery{Conn: fresh, Pkt: p})

	if _, ok := n.e.Conn(peer); !ok {
		t.Fatal("an honest re-dial on a fresh conn was refused after a drop")
	}
}
