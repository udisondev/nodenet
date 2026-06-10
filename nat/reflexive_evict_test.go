package nat

import (
	"encoding/binary"
	"testing"

	"github.com/udisondev/nodenet/kad"
)

// idN returns a distinct ID for each i (more than the single-byte id() helper allows).
func idN(i int) kad.ID {
	var k kad.ID
	binary.BigEndian.PutUint32(k[:], uint32(i))
	return k
}

// TestReflexiveRemoveForgetsReport: when a neighbour's edge dies its report must be
// dropped, so a departed (or evicted) neighbour can no longer prop up a consensus or
// linger as stale corroboration. Without eviction the reports map only ever grows.
func TestReflexiveRemoveForgetsReport(t *testing.T) {
	r := NewReflexive()
	pub := addr("203.0.113.7:4242")
	r.Record(id(1), sub(1), true, pub)
	r.Record(id(2), sub(2), true, pub)
	r.Record(id(3), sub(3), true, pub)
	if _, ok := r.Consensus(); !ok {
		t.Fatal("three subnet-diverse reporters should reach quorum")
	}

	r.Remove(id(1))
	if _, ok := r.Consensus(); ok {
		t.Fatal("consensus survived removing a reporter")
	}
	// Removing an unknown reporter is a no-op (not a panic).
	r.Remove(id(99))
}

// TestReflexiveReportsBounded: the reports map is capped, so even a stream of distinct
// reporters cannot grow it without bound (level-2 self-protection backstop).
func TestReflexiveReportsBounded(t *testing.T) {
	r := NewReflexive()
	for i := range maxReports + 50 {
		r.Record(idN(i), sub(byte(i)), true, addr("203.0.113.7:4242"))
	}
	r.mu.Lock()
	n := len(r.reports)
	r.mu.Unlock()
	if n > maxReports {
		t.Fatalf("reports map holds %d entries, cap is %d", n, maxReports)
	}
}
