package node

import (
	"context"
	"testing"

	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/transport"
)

// ipStubTransport is a minimal Transport that reports IPAddressed, for checking the
// node's subnet-diversity default. Its I/O methods are inert (the test only inspects
// construction).
type ipStubTransport struct{ id kad.ID }

func (t ipStubTransport) LocalID() kad.ID { return t.id }
func (t ipStubTransport) LocalAddr() transport.Addr {
	return transport.Addr{Net: "quic", Endpoint: "203.0.113.1:9000"}
}
func (t ipStubTransport) Dial(context.Context, kad.ID, transport.Addr) (transport.Conn, error) {
	return nil, transport.ErrNoRoute
}
func (t ipStubTransport) Inbound() <-chan transport.Delivery { return nil }
func (t ipStubTransport) Close() error                       { return nil }
func (t ipStubTransport) IPAddressed() bool                  { return true }

// TestSubnetFuncDefaultsFromTransport (#4): an IP-based transport enables subnet
// diversity by default (so the S5 reflexive-poison protection is not silently disabled),
// while the in-memory transport leaves it inert.
func TestSubnetFuncDefaultsFromTransport(t *testing.T) {
	idn := identity.FromSeed(seedFor(1))
	n := New(idn, ipStubTransport{id: idn.ID()})
	if n.subnetf == nil {
		t.Fatal("IP-addressed transport did not default a SubnetFunc")
	}
	// A real IP address yields a subnet; the default is the host-port derivation.
	if _, ok := n.subnetf(transport.Addr{Net: "quic", Endpoint: "198.51.100.4:443"}); !ok {
		t.Fatal("defaulted SubnetFunc does not derive a subnet from an IP address")
	}

	// The in-memory transport (not IPAddressed) leaves subnetf unset.
	memNode := newBareNode(t, 2)
	if memNode.subnetf != nil {
		t.Fatal("in-memory transport should leave SubnetFunc unset (inert caps)")
	}
}
