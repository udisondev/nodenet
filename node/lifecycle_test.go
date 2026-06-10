package node

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/routing"
	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/transport/mem"
)

// countDialTransport wraps a Transport and counts Dial calls, so a test can observe
// whether (and how much) a node is dialing.
type countDialTransport struct {
	transport.Transport
	dials atomic.Int64
}

func (t *countDialTransport) Dial(ctx context.Context, id kad.ID, addr transport.Addr) (transport.Conn, error) {
	t.dials.Add(1)
	return t.Transport.Dial(ctx, id, addr)
}

// gateDialTransport wraps a Transport: Dial waits for the gate and then dials with a
// fresh context — modelling a dial that completes successfully exactly as the node is
// shutting down — and records every conn it handed out, so a test can assert the node
// cleaned them all up.
type gateDialTransport struct {
	transport.Transport
	gate  chan struct{}
	mu    sync.Mutex
	conns []transport.Conn
}

func (g *gateDialTransport) Dial(ctx context.Context, id kad.ID, addr transport.Addr) (transport.Conn, error) {
	<-g.gate
	conn, err := g.Transport.Dial(context.Background(), id, addr)
	if err == nil {
		g.mu.Lock()
		g.conns = append(g.conns, conn)
		g.mu.Unlock()
	}
	return conn, err
}

// TestRunStopsMaintenanceOnTransportClose: when the transport shuts down, Run returns —
// and the maintenance loop and its dial workers must return WITH it, on every exit path.
// Before the fix they watched only the caller's ctx, so a caller that treated Run's
// return as the node's end of life leaked a ticking loop that kept re-dialing through
// the closed transport forever.
func TestRunStopsMaintenanceOnTransportClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel() // safety net so a regression fails the assert, not the bubble

		hub := mem.NewHub(mem.WithInboundBuffer(64))
		idn := identity.FromSeed(seedFor(1))
		tr, err := hub.New(idn.ID(), transport.Addr{Net: "mem", Endpoint: "a"})
		if err != nil {
			t.Fatalf("hub.New: %v", err)
		}
		ct := &countDialTransport{Transport: tr}
		n := New(idn, ct, WithMaintenance(testMaint()))
		// An un-dialable contact keeps the fill loop dialing for as long as it lives.
		n.Bootstrap([]routing.Contact{ghostContact(idNear(n.ID(), 1), "ghost")})

		done := make(chan error, 1)
		go func() { done <- n.Run(ctx) }()

		time.Sleep(3 * time.Second) // a few ticks: the loop is dialing
		synctest.Wait()
		if ct.dials.Load() == 0 {
			t.Fatal("precondition: the maintenance loop never dialed")
		}

		tr.Close()
		if err := <-done; err != nil {
			t.Fatalf("Run after transport close = %v, want nil", err)
		}
		synctest.Wait()

		before := ct.dials.Load()
		time.Sleep(5 * time.Minute) // far past every backoff ceiling
		synctest.Wait()
		if got := ct.dials.Load(); got != before {
			t.Fatalf("maintenance dialed %d more times after Run returned; the loop outlived the node", got-before)
		}
	})
}

// TestShutdownClosesDialedConns: a dial that succeeds exactly as the node shuts down
// must not leak its conn. Before the fix the worker's send-vs-ctx select could park the
// won conn in the result buffer that nobody drains anymore (a coin flip per conn), so
// the test runs a dozen nodes through that window and demands every conn closed.
func TestShutdownClosesDialedConns(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		hub := mem.NewHub(mem.WithInboundBuffer(64))
		b := spawn(t, ctx, hub, 100) // the peer every node dials

		const nodes = 12
		gates := make([]*gateDialTransport, 0, nodes)
		runs := make([]chan error, 0, nodes)
		for i := range nodes {
			idn := identity.FromSeed(seedFor(uint64(200 + i)))
			tr, err := hub.New(idn.ID(), transport.Addr{Net: "mem", Endpoint: idn.ID().String()})
			if err != nil {
				t.Fatalf("hub.New #%d: %v", i, err)
			}
			g := &gateDialTransport{Transport: tr, gate: make(chan struct{})}
			m := testMaint()
			m.Dialers = 1
			n := New(idn, g, WithMaintenance(m))
			n.Bootstrap([]routing.Contact{contactOf(b)})
			done := make(chan error, 1)
			go func() { done <- n.Run(ctx) }()
			gates, runs = append(gates, g), append(runs, done)
		}

		time.Sleep(2 * time.Second) // each node's single worker is now parked in its gated dial
		synctest.Wait()

		cancel() // shutdown lands while every dial is in flight
		synctest.Wait()
		for _, g := range gates {
			close(g.gate) // ...and now the dials complete successfully
		}
		for _, done := range runs {
			<-done // Run must not return before its workers' conns are accounted for
		}
		synctest.Wait()

		// Every conn handed to a worker during shutdown must have been closed.
		p := transport.Get()
		defer p.Release()
		w, err := routing.EncodePingFrame(p.Buf())
		if err != nil {
			t.Fatalf("EncodePingFrame: %v", err)
		}
		p.SetLen(w)
		dialed, leaked := 0, 0
		for _, g := range gates {
			g.mu.Lock()
			conns := g.conns
			g.mu.Unlock()
			for _, conn := range conns {
				dialed++
				if err := conn.Send(p); !errors.Is(err, transport.ErrConnClosed) {
					leaked++
				}
			}
		}
		if dialed == 0 {
			t.Fatal("precondition: no dial completed during the shutdown window")
		}
		if leaked > 0 {
			t.Fatalf("%d of %d conns dialed during shutdown leaked open", leaked, dialed)
		}
	})
}
