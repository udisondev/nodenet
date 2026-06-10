package routing

import "testing"

// TestSetTTLShortBuffer: SetTTL is exported and patches a byte at a fixed offset of an
// encoded message whose length is ultimately attacker-influenced. On a buffer too short
// to hold the TTL it must be a safe no-op, never an index panic — matching the codec's
// "never panic on malformed input" contract. On a long-enough buffer it patches the byte.
func TestSetTTLShortBuffer(t *testing.T) {
	// Too short: must not panic.
	SetTTL(nil, 7)
	SetTTL(make([]byte, ttlOffset), 7) // one byte short of the TTL slot

	buf := make([]byte, ttlOffset+1)
	SetTTL(buf, 9)
	if buf[ttlOffset] != 9 {
		t.Fatalf("TTL byte = %d, want 9", buf[ttlOffset])
	}
}
