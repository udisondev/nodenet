package quic

import (
	"net"
	"sync"
	"testing"
	"time"
)

// fakeRelayConn is a packet conn whose reads are fed from a channel and whose writes are
// recorded, so a test can drive relaySession.pump with chosen source addresses and
// observe what it forwards.
type fakeRelayConn struct {
	reads  chan relayPkt
	closed chan struct{}
	once   sync.Once
	mu     sync.Mutex
	writes []relayPkt
}

type relayPkt struct {
	data []byte
	addr net.Addr
}

func newFakeRelayConn() *fakeRelayConn {
	return &fakeRelayConn{reads: make(chan relayPkt, 16), closed: make(chan struct{})}
}

func (f *fakeRelayConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case p := <-f.reads:
		return copy(b, p.data), p.addr, nil
	case <-f.closed:
		return 0, nil, net.ErrClosed
	}
}

func (f *fakeRelayConn) WriteTo(b []byte, to net.Addr) (int, error) {
	f.mu.Lock()
	f.writes = append(f.writes, relayPkt{append([]byte(nil), b...), to})
	f.mu.Unlock()
	return len(b), nil
}

func (f *fakeRelayConn) writeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.writes)
}

func (f *fakeRelayConn) Close() error { f.once.Do(func() { close(f.closed) }); return nil }
func (f *fakeRelayConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
}
func (f *fakeRelayConn) SetDeadline(time.Time) error      { return nil }
func (f *fakeRelayConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakeRelayConn) SetWriteDeadline(time.Time) error { return nil }

func udp(ip string, port int) *net.UDPAddr { return &net.UDPAddr{IP: net.ParseIP(ip), Port: port} }

// waitPinned blocks until the relay session has learned (pinned) the given address, so a
// test can send the other side's first datagram only after this side is known — otherwise
// the first datagram could arrive before its peer's address is learned and be dropped
// (in production the continuous packet flow retransmits; a single-shot test must order it).
func waitPinned(t *testing.T, s *relaySession, addr *net.Addr) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		set := *addr != nil
		s.mu.Unlock()
		if set {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("relay session did not pin the address in time")
}

// waitWrites polls for fc to have reached at least n recorded writes.
func waitWrites(t *testing.T, fc *fakeRelayConn, n int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if fc.writeCount() >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d writes (have %d)", n, fc.writeCount())
}

// TestRelayPinsLearnedPeers: once a relay session has learned each side's address
// from its first datagram, a datagram arriving from any OTHER source is dropped, not
// spliced through. Without pinning, whoever sends last becomes a side — letting a third
// party that learns the allocation address hijack the session or use the relay as an
// open reflector.
func TestRelayPinsLearnedPeers(t *testing.T) {
	fa, fb := newFakeRelayConn(), newFakeRelayConn()
	s := &relaySession{a: fa, b: fb, done: make(chan struct{})}
	// pump exits on a ReadFrom error, not on s.done (only idleWatch — not running
	// here — listens to it), so the teardown that actually stops the pumps is
	// closing their sockets.
	defer fa.Close()
	defer fb.Close()
	go s.pump(fa, fb, &s.aAddr, &s.bAddr)
	go s.pump(fb, fa, &s.bAddr, &s.aAddr)

	caller, callee, attacker := udp("203.0.113.1", 1000), udp("204.0.113.2", 2000), udp("205.0.113.3", 3000)

	// Learn caller (on a) first, then callee (on b); the callee's first datagram is then
	// spliced to the caller, establishing both pins.
	fa.reads <- relayPkt{[]byte("hello-from-caller"), caller}
	waitPinned(t, s, &s.aAddr)
	fb.reads <- relayPkt{[]byte("hello-from-callee"), callee}
	waitWrites(t, fa, 1) // callee->caller forwarded

	// A legitimate caller datagram is spliced to the callee.
	fa.reads <- relayPkt{[]byte("data"), caller}
	waitWrites(t, fb, 1)

	// An attacker datagram on a, from a different source, must be dropped — NOT forwarded
	// to the callee.
	fa.reads <- relayPkt{[]byte("hijack"), attacker}
	// Give the pump a moment; the count must stay at 1.
	time.Sleep(50 * time.Millisecond)
	if got := fb.writeCount(); got != 1 {
		t.Fatalf("attacker datagram was spliced: fb writes = %d, want 1", got)
	}
	// And the bytes forwarded to the callee were the legitimate ones only.
	fb.mu.Lock()
	got := string(fb.writes[0].data)
	fb.mu.Unlock()
	if got != "data" {
		t.Fatalf("forwarded %q to callee, want \"data\"", got)
	}
}

// TestRelayFollowsPortRebind: a datagram from the SAME host but a NEW port (a NAT
// port rebind of the legitimate peer) is followed — it is spliced through, and the
// peer's learned address updates — so an active relayed connection survives a remap. A
// different host is still rejected (covered by TestRelayPinsLearnedPeers).
func TestRelayFollowsPortRebind(t *testing.T) {
	fa, fb := newFakeRelayConn(), newFakeRelayConn()
	s := &relaySession{a: fa, b: fb, done: make(chan struct{})}
	defer fa.Close() // closing the sockets is what ends the pumps (see above)
	defer fb.Close()
	go s.pump(fa, fb, &s.aAddr, &s.bAddr)
	go s.pump(fb, fa, &s.bAddr, &s.aAddr)

	caller := udp("203.0.113.1", 1000)
	callee := udp("204.0.113.2", 2000)
	rebind := udp("203.0.113.1", 1001) // same host, new port

	fa.reads <- relayPkt{[]byte("hi"), caller}
	waitPinned(t, s, &s.aAddr)
	fb.reads <- relayPkt{[]byte("ack"), callee}
	waitWrites(t, fa, 1)

	// The caller's NAT rebinds its port; the new datagram must still be spliced.
	fa.reads <- relayPkt{[]byte("after-rebind"), rebind}
	waitWrites(t, fb, 1)
	fb.mu.Lock()
	got := string(fb.writes[0].data)
	fb.mu.Unlock()
	if got != "after-rebind" {
		t.Fatalf("forwarded %q after rebind, want \"after-rebind\"", got)
	}

	// And the callee's reply now goes to the caller's NEW port.
	fb.reads <- relayPkt{[]byte("reply"), callee}
	waitWrites(t, fa, 2)
	fa.mu.Lock()
	to := fa.writes[1].addr
	fa.mu.Unlock()
	if !sameHostIP(to, rebind) || to.(*net.UDPAddr).Port != 1001 {
		t.Fatalf("reply addressed to %v, want the rebound port 1001", to)
	}
}
