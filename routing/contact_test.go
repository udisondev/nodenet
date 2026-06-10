package routing

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestCapabilityHas(t *testing.T) {
	tests := []struct {
		name string
		c    Capability
		f    Capability
		want bool
	}{
		{"zero has nothing", 0, CanRelay, false},
		{"single match", CanRelay, CanRelay, true},
		{"single miss", CanRelay, PublicAnchor, false},
		{"both set, query one", CanRelay | PublicAnchor, PublicAnchor, true},
		{"both set, query both", CanRelay | PublicAnchor, CanRelay | PublicAnchor, true},
		{"one set, query both", CanRelay, CanRelay | PublicAnchor, false},
		{"query zero is vacuously true", CanRelay, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.Has(tt.f); got != tt.want {
				t.Fatalf("Has = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCapabilityDistinctBits(t *testing.T) {
	// The flags must occupy distinct bits, or Has would conflate them.
	if CanRelay&PublicAnchor != 0 {
		t.Fatalf("CanRelay and PublicAnchor overlap: %b / %b", CanRelay, PublicAnchor)
	}
}

func TestContactEdPublic(t *testing.T) {
	var c Contact
	for i := range c.EdPub {
		c.EdPub[i] = byte(i + 1)
	}
	pub := c.EdPublic()
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("EdPublic len = %d, want %d", len(pub), ed25519.PublicKeySize)
	}
	if !bytes.Equal(pub, c.EdPub[:]) {
		t.Fatalf("EdPublic = %x, want %x", pub, c.EdPub[:])
	}
	// EdPublic must copy, not alias: mutating the result leaves the Contact intact.
	pub[0] ^= 0xff
	if pub[0] == c.EdPub[0] {
		t.Fatalf("EdPublic aliases the Contact's array")
	}
}
