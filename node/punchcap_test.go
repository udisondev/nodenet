package node

import (
	"context"
	"strconv"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/transport/mem"
)

// blockingPuncher holds each punch goroutine in its first PunchTo, so a spawned burst
// keeps its concurrency slot until released — letting the test observe the cap.
type blockingPuncher struct {
	calls   atomic.Int32
	release chan struct{}
}

func (b *blockingPuncher) PunchTo(transport.Addr) error {
	b.calls.Add(1)
	<-b.release
	return nil
}

// TestPunchAsyncBounded: reactive punch bursts are capped, so a flood of inbound
// Connect/RelayBind frames cannot spawn unbounded punch goroutines or turn the node into
// a high-volume reflector. Beyond the cap, punches are dropped. Every admitted burst is
// durably blocked in its first PunchTo, so after synctest.Wait the call count is exact —
// an erroneously over-cap goroutine would be counted deterministically, not raced for.
func TestPunchAsyncBounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := newBareNode(t, 1)
		p := &blockingPuncher{release: make(chan struct{})}

		addrs := []transport.Addr{{Net: "x", Endpoint: "1"}}
		for range maxConcurrentPunch + 20 {
			n.punchAsync(p, addrs)
		}

		synctest.Wait() // every admitted burst is now parked in PunchTo
		if got := p.calls.Load(); got != int32(maxConcurrentPunch) {
			t.Fatalf("punch calls = %d, want exactly the cap %d", got, maxConcurrentPunch)
		}

		// Release the bursts and let them play out their schedule on the fake clock, so
		// no goroutine outlives the bubble.
		close(p.release)
		time.Sleep(punchBurst * punchSpacing)
		synctest.Wait()
	})
}

// TestDialAnyRawBounded: the candidate list dialAnyRaw fans out to can come from the
// peer (a ConnectAck's or rendezvous reply's address list), so the concurrent-dial
// fan-out must be deduplicated and capped like a punch burst — a hostile peer must not
// be able to make this node spawn one dial goroutine per address it cares to list.
func TestDialAnyRawBounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hub := mem.NewHub(mem.WithInboundBuffer(64))
		idn := identity.FromSeed(seedFor(1))
		tr, err := hub.New(idn.ID(), transport.Addr{Net: "mem", Endpoint: "x"})
		if err != nil {
			t.Fatalf("hub.New: %v", err)
		}
		ct := &countDialTransport{Transport: tr}
		n := New(idn, ct)

		target := identity.FromSeed(seedFor(2)).ID()
		addrs := make([]transport.Addr, 0, 50)
		for i := range cap(addrs) {
			addrs = append(addrs, transport.Addr{Net: "mem", Endpoint: "peer-" + strconv.Itoa(i)})
		}

		_, _ = n.dialAnyRaw(context.Background(), target, addrs)
		synctest.Wait()

		if got := ct.dials.Load(); got == 0 {
			t.Fatal("dialAnyRaw dialed nothing")
		} else if got > maxPunchCandidates {
			t.Fatalf("dialAnyRaw fanned out %d concurrent dials; want ≤ %d (peer-fed list must be capped)",
				got, maxPunchCandidates)
		}
	})
}
