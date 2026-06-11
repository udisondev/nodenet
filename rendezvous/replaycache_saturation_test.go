package rendezvous

import (
	"encoding/binary"
	"testing"
	"time"
)

// BenchmarkReplayCacheRecordSaturated measures record on a saturated cache — the path an
// attacker forces by flooding distinct valid boxes. Every iteration records a fresh key
// while the cache is at capacity, so the eviction strategy dominates the cost.
func BenchmarkReplayCacheRecordSaturated(b *testing.B) {
	cache := NewReplayCache(time.Minute)
	now := time.Unix(1_700_000_000, 0) // fixed clock: the sweep never re-triggers
	exp := now.Add(time.Minute).UnixNano()
	var k [ephPubLen]byte
	for i := range maxReplayEntries {
		binary.BigEndian.PutUint64(k[8:], uint64(i))
		cache.record(k, now, exp)
	}
	k[0] = 0xff // distinct namespace from the fill keys
	var n uint64
	for b.Loop() {
		n++
		binary.BigEndian.PutUint64(k[8:], n)
		if !cache.record(k, now, exp) {
			b.Fatal("fresh key was not recorded")
		}
	}
}

// TestReplayCacheSaturationStillDedups: when the cache is full of still-fresh entries
// a freshly opened box must still be RECORDED — accepting it unrecorded would silently
// downgrade dedup to window-only, so an attacker who flooded the recipient with distinct
// valid boxes could then replay a captured box freely. The generation rotation makes room
// in O(1): the new box is recorded and its immediate replay is rejected, with the total
// entry count still capped.
func TestReplayCacheSaturationStillDedups(t *testing.T) {
	cache := NewReplayCache(time.Minute)
	now := time.Unix(1_700_000_000, 0)
	exp := now.Add(time.Minute).UnixNano()

	// Saturate the current generation with distinct still-fresh synthetic entries. Their
	// keys occupy only the low bytes (big-endian counters), so the probe key below is
	// guaranteed distinct.
	for i := range maxReplayEntries / 2 {
		var k [ephPubLen]byte
		binary.BigEndian.PutUint64(k[:], uint64(i))
		cache.cur[k] = exp
	}
	if len(cache.cur) != maxReplayEntries/2 {
		t.Fatalf("setup: %d entries, want %d", len(cache.cur), maxReplayEntries/2)
	}

	var probe [ephPubLen]byte
	probe[0] = 0xff // distinct from every synthetic key (whose byte 0 is always zero)
	probe[ephPubLen-1] = 0xff

	if !cache.record(probe, now, exp) {
		t.Fatal("saturated cache did not record a fresh box (silent window-only downgrade)")
	}
	if cache.record(probe, now, exp) {
		t.Fatal("replay of a box recorded under saturation was accepted")
	}
	if total := len(cache.cur) + len(cache.prev); total > maxReplayEntries {
		t.Fatalf("cache grew past the cap: %d entries", total)
	}
}

// TestReplayCacheRotationKeepsRecentKeys: rotation must not forget the keys recorded just
// before it — the full generation moves to prev, which lookups still consult, so a key
// survives at least one full generation of subsequent inserts before it can be dropped.
func TestReplayCacheRotationKeepsRecentKeys(t *testing.T) {
	cache := NewReplayCache(time.Minute)
	now := time.Unix(1_700_000_000, 0)
	exp := now.Add(time.Minute).UnixNano()

	// Fill to one short of the rotation threshold, then record the witness key: it lands
	// in the current generation and brings it exactly to the threshold.
	for i := range maxReplayEntries/2 - 1 {
		var k [ephPubLen]byte
		binary.BigEndian.PutUint64(k[:], uint64(i))
		cache.cur[k] = exp
	}
	var witness [ephPubLen]byte
	witness[0] = 0xee
	if !cache.record(witness, now, exp) {
		t.Fatal("witness was not recorded")
	}

	// The next record rotates: the generation holding the witness becomes prev.
	var trigger [ephPubLen]byte
	trigger[0] = 0xff
	if !cache.record(trigger, now, exp) {
		t.Fatal("trigger was not recorded")
	}
	if _, ok := cache.prev[witness]; !ok {
		t.Fatal("rotation did not move the witness's generation to prev")
	}

	// The witness still dedups from the previous generation.
	if cache.record(witness, now, exp) {
		t.Fatal("replay of a key recorded just before rotation was accepted")
	}
}
