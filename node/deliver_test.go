package node

import (
	"testing"
	"time"

	"github.com/udisondev/nodenet/routing"
	"github.com/udisondev/nodenet/transport"
)

// TestDeliverNeverBlocksDispatch: a full delivery channel (a slow or stalled local
// consumer) must not block the single dispatch loop. The loop forwards, answers
// keepalives, and handles control for the whole node, so a blocking hand-off here would
// wedge the entire router. An undeliverable message is dropped instead — the overlay is
// best-effort.
func TestDeliverNeverBlocksDispatch(t *testing.T) {
	n := newBareNode(t, 1, WithInboundBuffer(1))
	n.deliver <- Inbound{} // occupy the only slot

	done := make(chan struct{})
	go func() {
		p := transport.Get()
		msg := routing.Msg{Target: n.ID(), TTL: routing.MaxHops, EdPub: n.edPub, Payload: []byte("x")}
		routing.SignMsg(n.id, routing.TypeRoute, &msg, time.Now())
		w, _ := routing.EncodeRouteFrame(p.Buf(), &msg)
		p.SetLen(w)
		n.handle(transport.Delivery{Pkt: p}) // self-delivery into a full channel
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handle blocked on a full delivery channel (head-of-line stall)")
	}
}
