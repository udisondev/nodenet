package node

import (
	"sync"
	"testing"
	"time"

	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/routing"
	"github.com/udisondev/nodenet/transport"
)

// recordConn captures the frames sent on it, for asserting whether a handler emitted
// a response. Unlike captureConn it needs no WaitGroup — the sends under test here run
// synchronously on the dispatch goroutine.
type recordConn struct {
	id     kad.ID
	mu     *sync.Mutex
	frames *[][]byte
}

func (c recordConn) Remote() kad.ID             { return c.id }
func (c recordConn) RemoteAddr() transport.Addr { return transport.Addr{} }
func (c recordConn) Send(p *transport.Packet) error {
	c.mu.Lock()
	*c.frames = append(*c.frames, append([]byte(nil), p.Bytes()...))
	c.mu.Unlock()
	return nil
}
func (c recordConn) Close() error { return nil }

// TestSpoofedOriginatorDropped (S1): the routing envelope is authenticated. An attacker
// who stamps a victim's public key into EdPub but cannot sign with the victim's key
// must not have its message delivered as if it came from the victim — the unsigned (or
// wrongly-signed) envelope is refused at the terminal hop.
func TestSpoofedOriginatorDropped(t *testing.T) {
	n := newBareNode(t, 1)
	victim := identity.FromSeed(seedFor(42))
	var victimEd [32]byte
	copy(victimEd[:], victim.EdPublic())

	p := transport.Get()
	// Crafted by the attacker: victim's EdPub and a fresh timestamp (so it passes the
	// freshness gate), but no valid signature over it — must be refused at the sig check.
	msg := routing.Msg{Target: n.ID(), TTL: routing.MaxHops, EdPub: victimEd, Sent: time.Now().UnixNano(), Payload: []byte("spoofed")}
	w, err := routing.EncodeRouteFrame(p.Buf(), &msg)
	if err != nil {
		t.Fatalf("EncodeRouteFrame: %v", err)
	}
	p.SetLen(w)
	n.handle(transport.Delivery{Pkt: p})

	select {
	case got := <-n.Deliveries():
		t.Fatalf("spoofed message delivered (Originator=%v payload=%q); must be dropped", got.Originator, got.Payload)
	default:
	}
}

// TestStaleEnvelopeDropped (#2): a validly-signed but stale envelope (its authenticated
// timestamp older than the freshness window) is dropped, so a captured packet replayed
// later does not re-deliver. A forwarder enforces this too, so replayed-stale traffic
// dies at the first hop.
func TestStaleEnvelopeDropped(t *testing.T) {
	n := newBareNode(t, 1)
	sender := identity.FromSeed(seedFor(42))
	var senderEd [32]byte
	copy(senderEd[:], sender.EdPublic())

	p := transport.Get()
	msg := routing.Msg{Target: n.ID(), TTL: routing.MaxHops, EdPub: senderEd, Payload: []byte("old")}
	// Signed an hour ago — far outside MaxEnvelopeAge.
	routing.SignMsg(sender, routing.TypeRoute, &msg, time.Now().Add(-time.Hour))
	w, err := routing.EncodeRouteFrame(p.Buf(), &msg)
	if err != nil {
		t.Fatalf("EncodeRouteFrame: %v", err)
	}
	p.SetLen(w)
	n.handle(transport.Delivery{Pkt: p})

	select {
	case <-n.Deliveries():
		t.Fatal("stale (replayed) envelope was delivered; must be dropped")
	default:
	}
}

// TestSignedOriginatorDelivered (S1): the legitimate counterpart — a message whose
// envelope is signed by the key behind EdPub IS delivered, with the authenticated
// originator surfaced.
func TestSignedOriginatorDelivered(t *testing.T) {
	n := newBareNode(t, 1)
	sender := identity.FromSeed(seedFor(42))
	var senderEd [32]byte
	copy(senderEd[:], sender.EdPublic())

	p := transport.Get()
	msg := routing.Msg{Target: n.ID(), TTL: routing.MaxHops, EdPub: senderEd, Payload: []byte("legit")}
	routing.SignMsg(sender, routing.TypeRoute, &msg, time.Now())
	w, err := routing.EncodeRouteFrame(p.Buf(), &msg)
	if err != nil {
		t.Fatalf("EncodeRouteFrame: %v", err)
	}
	p.SetLen(w)
	n.handle(transport.Delivery{Pkt: p})

	select {
	case got := <-n.Deliveries():
		if string(got.Payload) != "legit" {
			t.Errorf("payload = %q, want legit", got.Payload)
		}
		if got.Originator != sender.ID() {
			t.Errorf("Originator = %v, want %v", got.Originator, sender.ID())
		}
	default:
		t.Fatal("signed message was not delivered")
	}
}

// TestSpoofedLookupNotAnswered (S2): a spoofed TypeLookup must not make this node emit a
// (fat) Neighbors response routed to the forged originator — the reflection/amplification
// vector. The answer is gated on the same envelope-signature check, so an unsigned lookup
// is silently dropped; a properly signed one is answered.
func TestSpoofedLookupNotAnswered(t *testing.T) {
	n := newBareNode(t, 1)
	var (
		mu       sync.Mutex
		captured [][]byte
	)
	edgeID := n.ID()
	edgeID[2] ^= 0x7f // distinct from self
	if err := n.e.AddEdge(recordConn{id: edgeID, mu: &mu, frames: &captured}, true, 0, time.Now()); err != nil {
		t.Fatalf("AddEdge: %v", err)
	}

	victim := identity.FromSeed(seedFor(42))
	var victimEd [32]byte
	copy(victimEd[:], victim.EdPublic())

	// Spoofed lookup: target this node (so it is the terminal that answers), originator
	// forged to the victim, no valid signature.
	send := func(m *routing.Msg) {
		p := transport.Get()
		w, err := routing.EncodeLookupFrame(p.Buf(), m)
		if err != nil {
			t.Fatalf("EncodeLookupFrame: %v", err)
		}
		p.SetLen(w)
		n.handle(transport.Delivery{Pkt: p})
	}

	lookupNonce := [routing.LookupNonceLen]byte{0x55}
	spoofed := routing.Msg{Target: n.ID(), TTL: routing.MaxHops, EdPub: victimEd, Sent: time.Now().UnixNano(), Payload: lookupNonce[:]}
	send(&spoofed)
	mu.Lock()
	got := len(captured)
	mu.Unlock()
	if got != 0 {
		t.Fatalf("spoofed lookup was answered with %d frame(s); must be refused", got)
	}

	// Legitimate signed lookup IS answered (the mechanism is not just disabled).
	legit := routing.Msg{Target: n.ID(), TTL: routing.MaxHops, EdPub: victimEd, Payload: lookupNonce[:]}
	routing.SignMsg(victim, routing.TypeLookup, &legit, time.Now())
	send(&legit)
	mu.Lock()
	got = len(captured)
	mu.Unlock()
	if got == 0 {
		t.Fatal("signed lookup was not answered; verification is too strict")
	}
}
