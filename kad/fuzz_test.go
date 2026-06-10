package kad

import "testing"

// FuzzParseID asserts ParseID is robust against arbitrary strings: it must never
// panic, and whenever it accepts a string the resulting ID must survive a
// canonical round-trip through String.
func FuzzParseID(f *testing.F) {
	f.Add("")
	f.Add("abc")                                                              // odd length
	f.Add("00")                                                               // valid hex, wrong length
	f.Add("zz112233445566778899aabbccddeeff00112233445566778899aabbccddeeff") // non-hex
	f.Add("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff") // valid

	f.Fuzz(func(t *testing.T, s string) {
		got, err := ParseID(s)
		if err != nil {
			return // rejecting malformed input is fine; not panicking is the point
		}
		again, err := ParseID(got.String())
		if err != nil {
			t.Fatalf("re-parse of accepted ID failed: %v", err)
		}
		if again != got {
			t.Fatalf("round-trip mismatch: %s != %s", again, got)
		}
	})
}

// FuzzIDStringRoundTrip asserts String→ParseID is the identity over the whole ID
// space: any 32 bytes form a valid ID whose hex string parses back unchanged.
func FuzzIDStringRoundTrip(f *testing.F) {
	f.Add(make([]byte, IDLen)) // all zero
	f.Add([]byte{0xff})        // short input → zero-padded tail
	seed := make([]byte, IDLen)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	f.Add(seed)

	f.Fuzz(func(t *testing.T, b []byte) {
		var want ID
		copy(want[:], b) // first min(len(b), IDLen) bytes; the rest stay zero
		got, err := ParseID(want.String())
		if err != nil {
			t.Fatalf("ParseID(String()) error for a valid ID: %v", err)
		}
		if got != want {
			t.Fatalf("round-trip mismatch: %s != %s", got, want)
		}
	})
}
