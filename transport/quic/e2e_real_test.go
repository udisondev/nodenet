//go:build e2e_real

// These tests run the production QUIC transport over a real loopback UDP socket
// under real time, so they are gated behind the e2e_real build tag and excluded
// from the default `go test ./...`. Run them with:
//
//	go test -tags e2e_real ./transport/quic
package quic

import (
	"context"
	"testing"
	"time"

	"github.com/udisondev/nodenet/routing"
	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/transport/transporttest"
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
