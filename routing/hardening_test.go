package routing

import (
	"math"
	"testing"
	"time"

	"github.com/udisondev/nodenet/kad"
)

// TestFreshOverflowSafe: m.Sent is attacker-controlled, so the freshness window must be
// checked without feeding it into a time.Duration subtraction that would overflow and wrap
// for a value near MinInt64/MaxInt64 — letting a crafted timestamp land back inside the
// window. A hostile extreme is rejected; a genuine timestamp still passes.
func TestFreshOverflowSafe(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	for _, sent := range []int64{math.MaxInt64, math.MinInt64, math.MaxInt64 - 1, math.MinInt64 + 1, 0} {
		if (&Msg{Sent: sent}).Fresh(now, MaxEnvelopeAge) {
			t.Fatalf("Fresh accepted hostile Sent=%d (overflow wrap)", sent)
		}
	}
	if !(&Msg{Sent: now.UnixNano()}).Fresh(now, MaxEnvelopeAge) {
		t.Fatal("Fresh rejected a current timestamp")
	}
	// Just inside the window passes; just outside is rejected.
	if !(&Msg{Sent: now.Add(-MaxEnvelopeAge + time.Second).UnixNano()}).Fresh(now, MaxEnvelopeAge) {
		t.Fatal("Fresh rejected a timestamp inside the window")
	}
	if (&Msg{Sent: now.Add(2 * MaxEnvelopeAge).UnixNano()}).Fresh(now, MaxEnvelopeAge) {
		t.Fatal("Fresh accepted a far-future timestamp")
	}
}

// TestDecodeMsgRejectsTrailingBytes: the wire form is canonical — a frame and frame+junk
// must not both decode to the same Msg. An exact-length encoding decodes; one byte of
// trailing junk is refused.
func TestDecodeMsgRejectsTrailingBytes(t *testing.T) {
	m := Msg{Target: fill(1), TTL: 7, EdPub: fill32(2), Payload: []byte("hi")}
	buf := make([]byte, msgLen(&m)+4)
	n, err := EncodeMsg(buf, &m)
	if err != nil {
		t.Fatalf("EncodeMsg: %v", err)
	}
	if _, err := DecodeMsg(buf[:n]); err != nil {
		t.Fatalf("DecodeMsg of an exact-length frame: %v", err)
	}
	if _, err := DecodeMsg(buf[:n+1]); err == nil {
		t.Fatal("DecodeMsg accepted a frame with a trailing byte")
	}
}

// TestAllowForwardThrottlesFlood: the per-edge routed-frame limiter caps how fast one edge
// can drive forward/decode work. At a single instant (no refill) exactly ForwardBurst
// frames pass and the rest are dropped; an untracked peer is denied outright (no edge, no
// budget) while a self-originated zero id passes; the bucket refills over its window.
func TestAllowForwardThrottlesFlood(t *testing.T) {
	var self kad.ID
	e := NewEdges(self, nil)
	id := idInBucket(self, 5, 1)
	if err := e.AddEdge(fakeConn{id: id}, true, 0, t0); err != nil {
		t.Fatalf("AddEdge: %v", err)
	}

	allowed := 0
	for range ForwardBurst + 200 {
		if e.AllowForward(id, t0) {
			allowed++
		}
	}
	if allowed != ForwardBurst {
		t.Fatalf("allowed %d frames at one instant, want exactly ForwardBurst=%d", allowed, ForwardBurst)
	}
	if e.AllowForward(idInBucket(self, 6, 9), t0) {
		t.Fatal("an untracked peer must be denied (no edge, no budget)")
	}
	if !e.AllowForward(kad.ID{}, t0) {
		t.Fatal("a self-originated (zero-id) frame must pass uncharged")
	}
	later := t0.Add(time.Duration(ForwardBurst/ForwardRate+1) * time.Second)
	if !e.AllowForward(id, later) {
		t.Fatal("the bucket did not refill after a full window")
	}
}
