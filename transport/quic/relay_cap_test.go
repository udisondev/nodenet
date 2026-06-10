package quic

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/udisondev/nodenet/transport"
)

// stubPacketConn is a relay-allocation socket that blocks reads until closed and drops
// writes — enough to exercise AllocateRelay's slot accounting without real UDP.
type stubPacketConn struct {
	closed chan struct{}
	once   sync.Once
}

func newStubPacketConn() *stubPacketConn { return &stubPacketConn{closed: make(chan struct{})} }

func (s *stubPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	<-s.closed
	return 0, nil, net.ErrClosed
}
func (s *stubPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (s *stubPacketConn) Close() error                              { s.once.Do(func() { close(s.closed) }); return nil }
func (s *stubPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
}
func (s *stubPacketConn) SetDeadline(time.Time) error      { return nil }
func (s *stubPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (s *stubPacketConn) SetWriteDeadline(time.Time) error { return nil }

// TestAllocateRelayCapUnderConcurrency: concurrent AllocateRelay callers must never
// collectively exceed maxRelaySessions. A load-then-add cap (TOCTOU) lets racing callers
// all observe "below the cap" and overshoot; the atomic reservation must hold the bound.
func TestAllocateRelayCapUnderConcurrency(t *testing.T) {
	tr := &quicTransport{
		relaySocket: func() (net.PacketConn, error) { return newStubPacketConn(), nil },
		relaySlots:  make(chan struct{}, maxRelaySessions),
		relays:      make(map[*relaySession]func()),
	}

	const goroutines = maxRelaySessions + 64
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		closes []func()
		ok     int
		start  = make(chan struct{})
	)
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			<-start // release all at once to maximise contention
			_, _, closeFn, err := tr.AllocateRelay()
			if err != nil {
				return
			}
			mu.Lock()
			ok++
			closes = append(closes, closeFn)
			mu.Unlock()
		}()
	}
	close(start)
	wg.Wait()

	if ok > maxRelaySessions {
		t.Fatalf("granted %d relay sessions, cap is %d", ok, maxRelaySessions)
	}
	if got := len(tr.relaySlots); got > maxRelaySessions {
		t.Fatalf("held %d relay slots, exceeds cap %d", got, maxRelaySessions)
	}
	// None were closed during the run, so the cap should be exactly saturated.
	if ok != maxRelaySessions {
		t.Fatalf("granted %d sessions, want exactly %d (cap saturated)", ok, maxRelaySessions)
	}

	// A saturated cap is "busy", not "closed": the transport is alive and the caller
	// should pick another volunteer or retry, so the refusal must be ErrRelayBusy.
	if _, _, _, err := tr.AllocateRelay(); !errors.Is(err, transport.ErrRelayBusy) {
		t.Fatalf("AllocateRelay at cap: err = %v, want transport.ErrRelayBusy", err)
	}

	for _, c := range closes {
		c()
	}
}

// TestRelaySessionsTornDownByClose (regression): relay sessions are tied to the
// transport's lifecycle. The node deliberately discards the close func ("the session
// reclaims itself when idle"), so without transport-side tracking an active session —
// whose traffic keeps refreshing lastActive — outlives Close forever, leaking sockets
// and goroutines. Close must tear every session down (sockets closed, slots returned),
// and AllocateRelay on a closed transport must refuse.
func TestRelaySessionsTornDownByClose(t *testing.T) {
	var (
		mu    sync.Mutex
		socks []*stubPacketConn
	)
	tr := &quicTransport{
		relaySocket: func() (net.PacketConn, error) {
			s := newStubPacketConn()
			mu.Lock()
			socks = append(socks, s)
			mu.Unlock()
			return s, nil
		},
		relaySlots: make(chan struct{}, maxRelaySessions),
		relays:     make(map[*relaySession]func()),
		conns:      make(map[*quicConn]struct{}),
		in:         make(chan transport.Delivery, 1),
		done:       make(chan struct{}),
		cancel:     func() {},
	}

	// The caller discards the close func, exactly as node's handleRelayRequest does.
	if _, _, _, err := tr.AllocateRelay(); err != nil {
		t.Fatalf("AllocateRelay: %v", err)
	}

	if err := tr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(socks) != 2 {
		t.Fatalf("allocated %d sockets, want 2", len(socks))
	}
	for i, s := range socks {
		select {
		case <-s.closed:
		default:
			t.Fatalf("relay socket %d still open after transport Close", i)
		}
	}
	if got := len(tr.relaySlots); got != 0 {
		t.Fatalf("after Close %d relay slots still held, want 0", got)
	}
	if _, _, _, err := tr.AllocateRelay(); !errors.Is(err, transport.ErrConnClosed) {
		t.Fatalf("AllocateRelay after Close: err = %v, want transport.ErrConnClosed", err)
	}
}
