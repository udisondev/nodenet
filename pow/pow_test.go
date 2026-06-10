package pow

import (
	"context"
	"errors"
	"testing"

	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/kad"
)

// idWithLeadingZeros returns an ID whose first set bit is bit n (MSB-first), so
// it has exactly n leading zero bits. n == kad.IDBits yields the all-zero ID.
func idWithLeadingZeros(n int) kad.ID {
	var id kad.ID
	if n < kad.IDBits {
		id[n>>3] = 1 << (7 - uint(n&7))
	}
	return id
}

func TestLeadingZeros(t *testing.T) {
	for n := 0; n <= kad.IDBits; n++ {
		if got := LeadingZeros(idWithLeadingZeros(n)); got != n {
			t.Errorf("LeadingZeros(first set bit = %d) = %d, want %d", n, got, n)
		}
	}
}

func TestSatisfies(t *testing.T) {
	const n = 17 // arbitrary leading-zero count to probe around
	id := idWithLeadingZeros(n)

	for d := 0; d <= n; d++ {
		if !Satisfies(id, d) {
			t.Errorf("Satisfies(id with %d leading zeros, d=%d) = false, want true", n, d)
		}
	}
	for _, d := range []int{n + 1, n + 8, kad.IDBits} {
		if Satisfies(id, d) {
			t.Errorf("Satisfies(id with %d leading zeros, d=%d) = true, want false", n, d)
		}
	}

	// d <= 0 disables PoW: any ID, including a maximal one, clears it.
	var maxID kad.ID
	for i := range maxID {
		maxID[i] = 0xff
	}
	if !Satisfies(maxID, 0) {
		t.Error("Satisfies(maxID, 0) = false, want true (PoW disabled at d=0)")
	}
}

// counterReader is a deterministic, infinite source of distinct seeds: each read
// is filled from a monotonically increasing counter. BLAKE2b spreads even
// sequential seeds into uniformly distributed NodeIDs, so a small difficulty is
// reached after roughly 2^d attempts without depending on real entropy.
type counterReader struct{ n uint64 }

func (c *counterReader) Read(p []byte) (int, error) {
	for i := range p {
		if i%8 == 0 {
			c.n++
		}
		p[i] = byte(c.n >> uint(8*(i%8)))
	}
	return len(p), nil
}

func TestSolve(t *testing.T) {
	const d = 8
	id, err := Solve(context.Background(), &counterReader{}, d)
	if err != nil {
		t.Fatalf("Solve: %v", err)
	}
	if !Satisfies(id.ID(), d) {
		t.Errorf("Solve returned ID with %d leading zeros, want >= %d", LeadingZeros(id.ID()), d)
	}
	// The returned identity must be internally consistent: its NodeID is exactly
	// BLAKE2b(ed_pub), so a forwarder re-deriving from the advertised key agrees.
	if identity.DeriveID(id.EdPublic()) != id.ID() {
		t.Error("Solve returned an identity whose DeriveID(ed_pub) != ID()")
	}
	// And it must round-trip from its own seed (so persisting Seed() suffices).
	if identity.FromSeed(id.Seed()).ID() != id.ID() {
		t.Error("Solve result does not round-trip from its Seed()")
	}
}

func TestSolveUnsatisfiable(t *testing.T) {
	_, err := Solve(context.Background(), &counterReader{}, kad.IDBits+1)
	if !errors.Is(err, ErrUnsatisfiable) {
		t.Errorf("Solve(d > IDBits) error = %v, want ErrUnsatisfiable", err)
	}
}

func TestSolveCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled: workers must bail before doing real work

	_, err := Solve(ctx, &counterReader{}, 16)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Solve(cancelled ctx) error = %v, want context.Canceled", err)
	}
}

func TestSolveReadError(t *testing.T) {
	_, err := Solve(context.Background(), errReader{}, 8)
	if !errors.Is(err, errBoom) {
		t.Errorf("Solve(failing reader) error = %v, want errBoom", err)
	}
}

var errBoom = errors.New("boom")

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errBoom }
