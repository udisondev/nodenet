package mem

import (
	"fmt"
	"testing"
	"testing/synctest"

	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/transport/transporttest"
)

// memFactory adapts the in-memory hub to the shared transport contract suite. A
// fresh factory (fresh hub) is built per subtest; bodies run under synctest so
// the deterministic fake clock drives them.
type memFactory struct{ h *Hub }

func (f *memFactory) New(t *testing.T, seed byte) (transport.Transport, transport.Addr) {
	t.Helper()
	a := transport.Addr{Net: "mem", Endpoint: fmt.Sprintf("mem-%d", seed)}
	tr, err := f.h.New(transporttest.IDFromSeed(seed), a)
	if err != nil {
		t.Fatalf("hub.New(seed %d): %v", seed, err)
	}
	t.Cleanup(func() { tr.Close() })
	return tr, a
}

func (f *memFactory) Run(t *testing.T, fn func(t *testing.T)) {
	synctest.Test(t, fn)
}

func (f *memFactory) NoRouteAddr() transport.Addr {
	return transport.Addr{Net: "mem", Endpoint: "unregistered"}
}

// TestContract runs the shared transport contract suite over the in-memory
// transport, the same suite transport/quic runs, proving they are equivalent
// pipes.
func TestContract(t *testing.T) {
	transporttest.RunContract(t, func() transporttest.Factory {
		return &memFactory{h: NewHub(WithInboundBuffer(64))}
	})
}
