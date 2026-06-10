package transport

import (
	"bytes"
	"testing"
)

func TestPacketGetZeroLen(t *testing.T) {
	p := Get()
	defer p.Release()
	if p.Len() != 0 {
		t.Errorf("fresh Packet Len = %d, want 0", p.Len())
	}
	if len(p.Buf()) != MaxPacketLen {
		t.Errorf("Buf len = %d, want %d", len(p.Buf()), MaxPacketLen)
	}
	if len(p.Bytes()) != 0 {
		t.Errorf("fresh Packet Bytes len = %d, want 0", len(p.Bytes()))
	}
}

// Writing into Buf() then SetLen must be visible through Bytes(), and Bytes()
// must alias the same backing array (no copy).
func TestPacketWriteReadAliases(t *testing.T) {
	p := Get()
	defer p.Release()

	payload := []byte("hello nodenet")
	copy(p.Buf(), payload)
	p.SetLen(len(payload))

	if got := p.Bytes(); !bytes.Equal(got, payload) {
		t.Fatalf("Bytes() = %q, want %q", got, payload)
	}
	if p.Len() != len(payload) {
		t.Errorf("Len = %d, want %d", p.Len(), len(payload))
	}
	// Bytes() aliases Buf(): mutating the buffer shows through.
	p.Buf()[0] = 'H'
	if p.Bytes()[0] != 'H' {
		t.Error("Bytes() did not alias Buf()")
	}
}

func TestPacketSetLenBounds(t *testing.T) {
	cases := []struct {
		name      string
		n         int
		wantPanic bool
	}{
		{"zero", 0, false},
		{"max", MaxPacketLen, false},
		{"negative", -1, true},
		{"over-max", MaxPacketLen + 1, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := Get()
			defer p.Release()
			defer func() {
				if r := recover(); (r != nil) != c.wantPanic {
					t.Errorf("SetLen(%d): panic=%v, wantPanic=%v", c.n, r, c.wantPanic)
				}
			}()
			p.SetLen(c.n)
		})
	}
}

// A buffer returned to the pool and re-issued must come back full-capacity with
// zero length — no stale length leaking across reuse.
func TestPacketReuseResets(t *testing.T) {
	p := Get()
	p.SetLen(100)
	p.Release()

	q := Get()
	defer q.Release()
	if q.Len() != 0 {
		t.Errorf("reused Packet Len = %d, want 0", q.Len())
	}
	if len(q.Buf()) != MaxPacketLen {
		t.Errorf("reused Packet Buf len = %d, want %d", len(q.Buf()), MaxPacketLen)
	}
}
