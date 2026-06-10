package quic

import (
	"testing"
	"time"

	"github.com/udisondev/nodenet/transport"
)

// TestRelayShaperDropsExcess: a session forwarding 1 KiB datagrams passes its
// burst's worth and then sheds the rest — dropped, not torn down: the session
// stays pinned and later (refilled) traffic flows again.
func TestRelayShaperDropsExcess(t *testing.T) {
	fa, fb := newFakeRelayConn(), newFakeRelayConn()
	s := &relaySession{a: fa, b: fb, done: make(chan struct{})}
	defer fa.Close()
	defer fb.Close()
	go s.pump(fa, fb, &s.aAddr, &s.bAddr)
	go s.pump(fb, fa, &s.bAddr, &s.aAddr)

	caller, callee := udp("203.0.113.1", 1000), udp("204.0.113.2", 2000)
	fa.reads <- relayPkt{[]byte("hi"), caller}
	waitPinned(t, s, &s.aAddr)
	fb.reads <- relayPkt{[]byte("ack"), callee}
	waitWrites(t, fa, 1)

	// Flood caller→callee with 1 KiB datagrams: the session bandwidth bucket
	// (relaySessionBurst) admits ~burst/1KiB of them; the rest are shed. The
	// refill during the test (relaySessionRate ≈ 250 KB/s for well under a
	// second) adds a small tolerance.
	const size = 1 << 10
	const flood = 3 * relaySessionBurst / size
	payload := make([]byte, size)
	for range flood {
		fa.reads <- relayPkt{payload, caller}
	}
	// Wait for the pump to chew through the queue: writes stop growing.
	waitDrained(t, fb)

	got := fb.writeCount()
	want := relaySessionBurst / size
	if got < want || got > want+want/4 {
		t.Fatalf("forwarded %d of %d datagrams; want ~%d (session burst) with small refill tolerance", got, flood, want)
	}

	// Dropped ≠ torn down: after a refill the same session forwards again.
	time.Sleep(50 * time.Millisecond) // ~12 KiB refill at relaySessionRate
	before := fb.writeCount()
	fa.reads <- relayPkt{payload, caller}
	waitWrites(t, fb, before+1)
}

// TestRelayShaperAggregate: sessions also share the volunteer-wide bucket.
// THREE sessions make the aggregate the binding limit (3 × relaySessionBurst =
// 384 KiB > relayAggBurst = 256 KiB), so the total forwarded must track the
// aggregate budget and stay strictly below the sum of the per-session budgets
// — the assertion that fails if the aggregate charge is ever dropped.
func TestRelayShaperAggregate(t *testing.T) {
	var agg transport.TokenBucket
	mk := func() (*relaySession, *fakeRelayConn, *fakeRelayConn) {
		fa, fb := newFakeRelayConn(), newFakeRelayConn()
		s := &relaySession{a: fa, b: fb, agg: &agg, done: make(chan struct{})}
		t.Cleanup(func() { fa.Close(); fb.Close() })
		go s.pump(fa, fb, &s.aAddr, &s.bAddr)
		go s.pump(fb, fa, &s.bAddr, &s.aAddr)
		caller, callee := udp("203.0.113.1", 1000), udp("204.0.113.2", 2000)
		fa.reads <- relayPkt{[]byte("hi"), caller}
		waitPinned(t, s, &s.aAddr)
		fb.reads <- relayPkt{[]byte("ack"), callee}
		waitWrites(t, fa, 1)
		return s, fa, fb
	}

	const sessions = 3
	ins := make([]*fakeRelayConn, sessions)
	outs := make([]*fakeRelayConn, sessions)
	for i := range sessions {
		_, ins[i], outs[i] = mk()
	}

	// Each session floods exactly its own session burst's worth (so its own
	// bucket never refuses); together they demand 1.5× the aggregate burst.
	const size = 1 << 10
	perSession := relaySessionBurst / size
	payload := make([]byte, size)
	caller := udp("203.0.113.1", 1000)
	for range perSession {
		for i := range sessions {
			ins[i].reads <- relayPkt{payload, caller}
		}
	}
	total := 0
	for i := range sessions {
		waitDrained(t, outs[i])
		total += outs[i].writeCount()
	}

	aggCap := relayAggBurst / size
	demanded := sessions * perSession
	if total > aggCap+aggCap/4 {
		t.Fatalf("three sessions forwarded %d datagrams total; the aggregate budget allows ~%d", total, aggCap)
	}
	// The decisive bound: strictly below the per-session sum — remove the
	// aggregate charge from allowRelay and this fails.
	if total >= demanded-perSession/2 {
		t.Fatalf("three sessions forwarded %d of %d demanded; the aggregate (~%d) never throttled", total, demanded, aggCap)
	}
	if total < aggCap/2 {
		t.Fatalf("three sessions forwarded only %d datagrams; the aggregate (~%d) should admit far more", total, aggCap)
	}
}

// waitDrained waits until fc's write count stops growing (the pump has chewed
// through everything queued for it).
func waitDrained(t *testing.T, fc *fakeRelayConn) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	last := -1
	for time.Now().Before(deadline) {
		cur := fc.writeCount()
		if cur == last {
			return
		}
		last = cur
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("relay pump never went quiet")
}
