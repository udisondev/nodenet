package kad

import (
	"math/big"
	"math/rand/v2"
	"testing"
)

// id builds an ID from a hex string, failing the test on a bad literal. Test
// helper only.
func id(t *testing.T, s string) ID {
	t.Helper()
	v, err := ParseID(s)
	if err != nil {
		t.Fatalf("ParseID(%q): %v", s, err)
	}
	return v
}

func TestDistance(t *testing.T) {
	a := id(t, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	b := id(t, "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100")

	// Self distance is zero.
	if d := Distance(a, a); d != (ID{}) {
		t.Errorf("Distance(a,a) = %v, want zero", d)
	}

	// Symmetry.
	if Distance(a, b) != Distance(b, a) {
		t.Error("Distance not symmetric")
	}

	// a ^ b: each byte pair here XORs to 0xff.
	got := Distance(a, b)
	for i, v := range got {
		if v != 0xff {
			t.Errorf("Distance byte %d = %#x, want 0xff", i, v)
		}
	}

	// XOR identity: distance from zero is the ID itself.
	if Distance(a, ID{}) != a {
		t.Error("Distance(a, 0) != a")
	}
}

func TestCommonPrefixLen(t *testing.T) {
	tests := []struct {
		name string
		a, b ID
		want int
	}{
		{
			name: "equal -> full",
			a:    id(t, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"),
			b:    id(t, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"),
			want: IDBits,
		},
		{
			name: "differ in first bit -> 0",
			a:    id(t, "0000000000000000000000000000000000000000000000000000000000000000"),
			b:    id(t, "8000000000000000000000000000000000000000000000000000000000000000"),
			want: 0,
		},
		{
			name: "differ in second bit -> 1",
			a:    id(t, "0000000000000000000000000000000000000000000000000000000000000000"),
			b:    id(t, "4000000000000000000000000000000000000000000000000000000000000000"),
			want: 1,
		},
		{
			// Bytes 0..2 equal; byte 3 = 0x00 vs 0x08 -> first set bit at
			// index 4 within the byte, so prefix = 3*8 + 4 = 28.
			name: "differ mid-byte across a byte boundary",
			a:    id(t, "11223300000000000000000000000000000000000000000000000000000000ff"),
			b:    id(t, "11223308000000000000000000000000000000000000000000000000000000ff"),
			want: 28,
		},
		{
			// Differ only in the very last bit.
			name: "differ in last bit -> 255",
			a:    id(t, "0000000000000000000000000000000000000000000000000000000000000000"),
			b:    id(t, "0000000000000000000000000000000000000000000000000000000000000001"),
			want: 255,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CommonPrefixLen(tt.a, tt.b); got != tt.want {
				t.Errorf("CommonPrefixLen = %d, want %d", got, tt.want)
			}
			// Symmetric.
			if got := CommonPrefixLen(tt.b, tt.a); got != tt.want {
				t.Errorf("CommonPrefixLen reversed = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestCommonPrefixLenSingleBit: CommonPrefixLen is the index of the first
// differing bit. Synthesize two IDs differing only at bit k (MSB-first within
// the big-endian blob) and confirm the prefix length lands exactly on k.
func TestCommonPrefixLenSingleBit(t *testing.T) {
	for _, k := range []int{0, 7, 8, 63, 64, 200, 255} {
		var a, b ID
		b[k>>3] = 1 << (7 - uint(k&7))
		if got := CommonPrefixLen(a, b); got != k {
			t.Errorf("CPL of IDs differing at bit %d = %d", k, got)
		}
	}
}

// TestDistanceCmpOracle cross-checks DistanceCmp against a math/big reference
// over many random triples. The RNG is fixed-seed for determinism.
func TestDistanceCmpOracle(t *testing.T) {
	rng := rand.New(rand.NewPCG(0x9e3779b97f4a7c15, 0xbf58476d1ce4e5b9))

	bigDist := func(a, b ID) *big.Int {
		d := Distance(a, b)
		return new(big.Int).SetBytes(d[:])
	}

	const N = 100_000
	for range N {
		target, a, b := randID(rng), randID(rng), randID(rng)
		got := sign(DistanceCmp(target, a, b))
		want := bigDist(a, target).Cmp(bigDist(b, target))
		if got != want {
			t.Fatalf("DistanceCmp mismatch:\n target=%s\n a=%s\n b=%s\n got %d want %d",
				target, a, b, got, want)
		}
	}
}

func TestParseIDString(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	for range 1000 {
		want := randID(rng)
		got, err := ParseID(want.String())
		if err != nil {
			t.Fatalf("ParseID(String()) error: %v", err)
		}
		if got != want {
			t.Fatalf("round-trip mismatch: %s != %s", got, want)
		}
	}

	// Error cases.
	if _, err := ParseID("abc"); err == nil { // odd length, not hex-decodable
		t.Error("ParseID on odd-length string: want error")
	}
	if _, err := ParseID("00"); err == nil { // valid hex, wrong length
		t.Error("ParseID on short ID: want error")
	}
	if _, err := ParseID("zz" + "00112233445566778899aabbccddeeff00112233445566778899aabbccddee"); err == nil {
		t.Error("ParseID on non-hex: want error")
	}
}

// sign collapses an int to -1/0/+1 so DistanceCmp can be compared against
// big.Int.Cmp, which is already normalized.
func sign(x int) int {
	switch {
	case x < 0:
		return -1
	case x > 0:
		return 1
	default:
		return 0
	}
}

// randID fills an ID from the given RNG. Test helper.
func randID(rng *rand.Rand) ID {
	var v ID
	for i := 0; i < IDLen; i += 8 {
		x := rng.Uint64()
		for j := range 8 {
			v[i+j] = byte(x >> (8 * j))
		}
	}
	return v
}
