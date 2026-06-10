package node

import (
	"testing"

	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/routing"
	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/transport/mem"
)

// ipSubnet is a test SubnetFunc that derives a /24-style key from a "host:port" endpoint
// by zeroing the last octet — enough to tell same-subnet sybils from independent peers.
func ipSubnet(a transport.Addr) (routing.Subnet, bool) {
	return routing.SubnetFromHostPort(a)
}

// pongConn is a Conn that reports a fixed remote address, so handlePong can derive the
// reporter's subnet from it. Send is a no-op.
type pongConn struct {
	id   kad.ID
	addr transport.Addr
}

func (c pongConn) Remote() kad.ID               { return c.id }
func (c pongConn) RemoteAddr() transport.Addr   { return c.addr }
func (c pongConn) Send(*transport.Packet) error { return nil }
func (c pongConn) Close() error                 { return nil }

// pong builds a TypePong frame whose payload echoes observed.
func pongFrame(t *testing.T, observed transport.Addr) []byte {
	t.Helper()
	buf := make([]byte, 256)
	w, err := routing.EncodePongFrame(buf, observed)
	if err != nil {
		t.Fatalf("EncodePongFrame: %v", err)
	}
	return buf[:w]
}

// TestReflexivePoisonSameSubnet (S5): two (or more) neighbours in the SAME subnet
// reporting the same forged address must NOT confirm it as this node's reflexive
// address — a cheap single-subnet sybil cluster cannot poison reflexive consensus.
func TestReflexivePoisonSameSubnet(t *testing.T) {
	n := newBareNode(t, 1, WithSubnetFunc(ipSubnet))
	forged := transport.Addr{Net: "quic", Endpoint: "203.0.113.9:6666"}

	// Three sybils, all in 198.51.100.0/24, all reporting the same forged address.
	for i, ep := range []string{"198.51.100.10:1", "198.51.100.11:1", "198.51.100.12:1"} {
		id := n.ID()
		id[3] ^= byte(i + 1)
		conn := pongConn{id: id, addr: transport.Addr{Net: "quic", Endpoint: ep}}
		p := transport.Get()
		p.SetLen(copy(p.Buf(), pongFrame(t, forged)))
		n.handle(transport.Delivery{Conn: conn, Pkt: p})
	}

	if r := n.Reflexive(); r != (transport.Addr{}) {
		t.Fatalf("single-subnet sybils confirmed reflexive = %v; must stay unconfirmed", r)
	}
}

// TestReflexiveConfirmSubnetDiverse (S5): the legitimate case — enough neighbours in
// independent subnets agreeing DO confirm the address.
func TestReflexiveConfirmSubnetDiverse(t *testing.T) {
	n := newBareNode(t, 1, WithSubnetFunc(ipSubnet))
	real := transport.Addr{Net: "quic", Endpoint: "203.0.113.9:6666"}

	for i, ep := range []string{"198.51.100.10:1", "203.0.113.20:1", "192.0.2.30:1"} {
		id := n.ID()
		id[3] ^= byte(i + 1)
		conn := pongConn{id: id, addr: transport.Addr{Net: "quic", Endpoint: ep}}
		p := transport.Get()
		p.SetLen(copy(p.Buf(), pongFrame(t, real)))
		n.handle(transport.Delivery{Conn: conn, Pkt: p})
	}

	if r := n.Reflexive(); r != real {
		t.Fatalf("subnet-diverse quorum did not confirm reflexive: got %v, want %v", r, real)
	}
}

// ipMemTransport wraps the in-memory transport and claims IP-addressed endpoints, so a
// test can exercise behaviour keyed on transport.IPAddressed on the deterministic hub.
type ipMemTransport struct{ transport.Transport }

func (ipMemTransport) IPAddressed() bool { return true }

// TestReflexivePoisonUnparsableRejectedOnIPTransport (S5): on a transport whose
// endpoints are real IP host:port pairs, a pong claiming this node lives at something
// that does not even parse as one is hostile garbage and must be rejected — fail-closed.
// (Fail-open here would let colluding reporters confirm a junk address that bypasses the
// routable-unicast filter and gets advertised in this node's coords.) Only a non-IP
// transport (the in-memory hub), whose endpoints carry no IP to judge, may pass them.
func TestReflexivePoisonUnparsableRejectedOnIPTransport(t *testing.T) {
	idn := identity.FromSeed(seedFor(1))
	tr, err := mem.NewHub().New(idn.ID(), transport.Addr{Net: "mem", Endpoint: "x"})
	if err != nil {
		t.Fatalf("hub.New: %v", err)
	}
	n := New(idn, ipMemTransport{tr})

	// A subnet-diverse quorum colludes on a non-parsing endpoint.
	for i, rep := range []string{"198.51.100.10:1", "203.0.113.20:1", "192.0.2.30:1"} {
		id := n.ID()
		id[3] ^= byte(i + 1)
		conn := pongConn{id: id, addr: transport.Addr{Net: "quic", Endpoint: rep}}
		p := transport.Get()
		p.SetLen(copy(p.Buf(), pongFrame(t, transport.Addr{Net: "quic", Endpoint: "localhost:9"})))
		n.handle(transport.Delivery{Conn: conn, Pkt: p})
	}
	if r := n.Reflexive(); r != (transport.Addr{}) {
		t.Fatalf("non-parsing reflexive claim confirmed on an IP transport = %v; want it rejected fail-closed", r)
	}
}

// TestReflexivePoisonLoopbackRejected (S5): a neighbour claiming this node lives at a
// non-routable address (loopback) is ignored outright, so reflexive can never be steered
// at a local target.
func TestReflexivePoisonLoopbackRejected(t *testing.T) {
	n := newBareNode(t, 1, WithSubnetFunc(ipSubnet))
	for i, rep := range []string{"198.51.100.10:1", "203.0.113.20:1", "192.0.2.30:1"} {
		id := n.ID()
		id[3] ^= byte(i + 1)
		conn := pongConn{id: id, addr: transport.Addr{Net: "quic", Endpoint: rep}}
		p := transport.Get()
		p.SetLen(copy(p.Buf(), pongFrame(t, transport.Addr{Net: "quic", Endpoint: "127.0.0.1:9"})))
		n.handle(transport.Delivery{Conn: conn, Pkt: p})
	}
	if r := n.Reflexive(); r != (transport.Addr{}) {
		t.Fatalf("loopback reflexive claim was accepted = %v", r)
	}
}
