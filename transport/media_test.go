package transport

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// GetMedia hands out media-class buffers, and Release routes each class back to
// its own pool: a media-class Packet re-issued by GetMedia must come back
// media-sized, not 64 KiB — pools must not cross-contaminate.
func TestGetMediaClass(t *testing.T) {
	p := GetMedia()
	if len(p.Buf()) != MaxMediaPacketLen {
		t.Fatalf("GetMedia Buf len = %d, want %d", len(p.Buf()), MaxMediaPacketLen)
	}
	if p.Len() != 0 {
		t.Errorf("fresh media Packet Len = %d, want 0", p.Len())
	}
	p.SetLen(100)
	p.Release()

	q := GetMedia()
	defer q.Release()
	if len(q.Buf()) != MaxMediaPacketLen {
		t.Errorf("reused media Packet Buf len = %d, want %d", len(q.Buf()), MaxMediaPacketLen)
	}
	if q.Len() != 0 {
		t.Errorf("reused media Packet Len = %d, want 0", q.Len())
	}

	big := Get()
	defer big.Release()
	if len(big.Buf()) != MaxPacketLen {
		t.Errorf("Get Buf len = %d, want %d (media release must not pollute the big pool)", len(big.Buf()), MaxPacketLen)
	}
}

// SetLen on a media-class Packet is bounded by ITS buffer, not MaxPacketLen.
func TestGetMediaSetLenBounds(t *testing.T) {
	p := GetMedia()
	defer p.Release()
	p.SetLen(MaxMediaPacketLen) // at capacity: fine
	defer func() {
		if recover() == nil {
			t.Error("SetLen past MaxMediaPacketLen on a media Packet did not panic")
		}
	}()
	p.SetLen(MaxMediaPacketLen + 1)
}

func TestMediaFrameRoundTrip(t *testing.T) {
	payload := []byte("opus frame bytes")
	dst := make([]byte, MediaFrameLen(len(payload)))
	n, err := PutMediaFrame(dst, 17, payload)
	if err != nil {
		t.Fatalf("PutMediaFrame: %v", err)
	}
	if n != len(payload)+1 {
		t.Fatalf("PutMediaFrame n = %d, want %d", n, len(payload)+1)
	}
	ch, got, err := ParseMediaFrame(dst[:n])
	if err != nil {
		t.Fatalf("ParseMediaFrame: %v", err)
	}
	if ch != 17 || !bytes.Equal(got, payload) {
		t.Errorf("ParseMediaFrame = (%d, %q), want (17, %q)", ch, got, payload)
	}
	// The parsed payload aliases the input (zero-copy), like wire.ParseFrame.
	dst[1] = 'X'
	if got[0] != 'X' {
		t.Error("parsed payload did not alias the input buffer")
	}
}

func TestMediaFrameErrors(t *testing.T) {
	if _, _, err := ParseMediaFrame(nil); !errors.Is(err, ErrBadMediaFrame) {
		t.Errorf("ParseMediaFrame(nil) err = %v, want ErrBadMediaFrame", err)
	}
	if _, err := PutMediaFrame(make([]byte, 3), 16, []byte("abcd")); !errors.Is(err, ErrBadMediaFrame) {
		t.Errorf("PutMediaFrame into a short buffer err = %v, want ErrBadMediaFrame", err)
	}
	// An empty payload is a legal frame: just the channel byte.
	dst := make([]byte, 1)
	n, err := PutMediaFrame(dst, 16, nil)
	if err != nil || n != 1 {
		t.Fatalf("PutMediaFrame(empty payload) = (%d, %v), want (1, nil)", n, err)
	}
	ch, payload, err := ParseMediaFrame(dst)
	if err != nil || ch != 16 || len(payload) != 0 {
		t.Errorf("ParseMediaFrame(channel only) = (%d, %q, %v), want (16, empty, nil)", ch, payload, err)
	}
}

// AllowN charges a whole cost at once and refuses without consuming: the
// byte-budget form the media receive budget and the relay shaper meter with.
func TestTokenBucketAllowN(t *testing.T) {
	var tb TokenBucket
	now := time.Unix(1000, 0)
	const rate, burst = 100, 1000

	if !tb.AllowN(now, 600, rate, burst) {
		t.Fatal("first AllowN(600) on a full bucket refused")
	}
	if tb.AllowN(now, 600, rate, burst) {
		t.Fatal("second AllowN(600) allowed: bucket should hold only 400")
	}
	// The refused call must not have consumed anything: 400 are still there.
	if !tb.AllowN(now, 400, rate, burst) {
		t.Fatal("AllowN(400) refused after a refused AllowN left the bucket untouched")
	}
	// Refill: 2 s at rate 100 = 200 tokens.
	now = now.Add(2 * time.Second)
	if !tb.AllowN(now, 200, rate, burst) {
		t.Fatal("AllowN(200) refused after a 2 s refill")
	}
	if tb.AllowN(now, 1, rate, burst) {
		t.Fatal("AllowN(1) allowed on an empty bucket")
	}
}

func TestMediaCountersSnapshot(t *testing.T) {
	var c MediaCounters
	c.TxDatagrams.Add(3)
	c.RxDroppedBudget.Add(2)
	c.RxDroppedReserved.Add(1)
	s := c.Snapshot()
	if s.TxDatagrams != 3 || s.RxDroppedBudget != 2 || s.RxDroppedReserved != 1 {
		t.Errorf("Snapshot = %+v, want TxDatagrams=3 RxDroppedBudget=2 RxDroppedReserved=1", s)
	}
	if s.RxDatagrams != 0 || s.TxDroppedQueue != 0 {
		t.Errorf("untouched counters non-zero: %+v", s)
	}
}
