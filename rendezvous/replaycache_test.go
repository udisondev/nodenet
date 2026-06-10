package rendezvous

import (
	"errors"
	"testing"
	"time"
)

// TestReplayCacheRejectsWithinWindow: the freshness window bounds the replay
// horizon, but a box can still be replayed WITHIN it; the ReplayCache closes that gap —
// a box opens at most once. A second open of the same box, even while still fresh, is
// ErrReplay; a different box still opens.
func TestReplayCacheRejectsWithinWindow(t *testing.T) {
	sender := idFromSeed(1)
	recipient := idFromSeed(2)
	rx := recipient.KEXPublic()
	const window = time.Minute
	cache := NewReplayCache(window)

	at := time.Unix(1_700_000_000, 0)
	box, err := Seal(&zeroRand{}, sender, rx, []byte("once"), nil, at)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// First open succeeds.
	if _, pt, err := cache.Open(recipient, box, nil, at.Add(time.Second)); err != nil || string(pt) != "once" {
		t.Fatalf("first Open: pt=%q err=%v", pt, err)
	}
	// Replay within the window is rejected.
	if _, _, err := cache.Open(recipient, box, nil, at.Add(2*time.Second)); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay within window: err = %v, want ErrReplay", err)
	}
	// A stale replay is rejected by the window before the cache even matters.
	if _, _, err := cache.Open(recipient, box, nil, at.Add(2*time.Minute)); !errors.Is(err, ErrExpired) {
		t.Fatalf("stale replay: err = %v, want ErrExpired", err)
	}

	// A distinct box (fresh ephemeral key) still opens.
	box2, err := Seal(&zeroRand{b: 0x40}, sender, rx, []byte("twice"), nil, at)
	if err != nil {
		t.Fatalf("Seal box2: %v", err)
	}
	if _, pt, err := cache.Open(recipient, box2, nil, at.Add(time.Second)); err != nil || string(pt) != "twice" {
		t.Fatalf("distinct box Open: pt=%q err=%v", pt, err)
	}
}

// TestReplayCacheEvictsExpired: once a box's window has fully passed, its entry is swept,
// so the cache does not grow without bound. (Re-opening the same box after expiry is
// rejected by the window, not the cache — this just asserts the entry is gone.)
func TestReplayCacheEvictsExpired(t *testing.T) {
	sender := idFromSeed(1)
	recipient := idFromSeed(2)
	rx := recipient.KEXPublic()
	const window = time.Minute
	cache := NewReplayCache(window)

	at := time.Unix(1_700_000_000, 0)
	box, _ := Seal(&zeroRand{}, sender, rx, []byte("x"), nil, at)
	if _, _, err := cache.Open(recipient, box, nil, at.Add(time.Second)); err != nil {
		t.Fatalf("Open: %v", err)
	}
	// Trigger a sweep well past the window by opening a fresh box; the old entry expires.
	box2, _ := Seal(&zeroRand{b: 0x40}, sender, rx, []byte("y"), nil, at.Add(2*window))
	if _, _, err := cache.Open(recipient, box2, nil, at.Add(2*window)); err != nil {
		t.Fatalf("Open box2: %v", err)
	}
	cache.mu.Lock()
	var e [ephPubLen]byte
	copy(e[:], box[:ephPubLen])
	_, inCur := cache.cur[e]
	_, inPrev := cache.prev[e]
	present := inCur || inPrev
	n := len(cache.cur) + len(cache.prev)
	cache.mu.Unlock()
	if present {
		t.Error("expired entry was not swept")
	}
	if n != 1 {
		t.Fatalf("cache holds %d entries, want 1 (only the fresh box)", n)
	}
}
