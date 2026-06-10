package rendezvous

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/udisondev/nodenet/identity"
)

// testSealTime and testMaxAge are a fixed clock and a generous freshness window so the
// round-trip/robustness tests are deterministic and not time-sensitive; the dedicated
// replay test exercises the window itself.
var testSealTime = time.Unix(1_700_000_000, 0)

const testMaxAge = time.Hour

// idFromSeed derives a deterministic identity from a one-byte seed for tests.
func idFromSeed(b byte) *identity.Identity {
	var seed [identity.SeedLen]byte
	for i := range seed {
		seed[i] = b
	}
	return identity.FromSeed(seed)
}

// zeroRand is a deterministic, non-secure byte source for sealing in tests: it makes
// a box reproducible without pulling in crypto/rand. It never fails.
type zeroRand struct{ b byte }

func (z *zeroRand) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = z.b
		z.b++
	}
	return len(p), nil
}

func TestSealOpenRoundTrip(t *testing.T) {
	sender := idFromSeed(1)
	recipient := idFromSeed(2)
	rx := recipient.KEXPublic()

	cases := []struct {
		name      string
		plaintext []byte
		aad       []byte
	}{
		{"empty", nil, nil},
		{"short", []byte("hi R"), nil},
		{"with-aad", []byte("coordinates"), []byte("context")},
		{"binary", []byte{0, 1, 2, 0xff, 0x80}, []byte{0xaa}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			box, err := Seal(&zeroRand{}, sender, rx, tc.plaintext, tc.aad, testSealTime)
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			gotID, pt, err := Open(recipient, box, tc.aad, testSealTime, testMaxAge)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if gotID != sender.ID() {
				t.Errorf("sender = %v, want %v", gotID, sender.ID())
			}
			if !bytes.Equal(pt, tc.plaintext) {
				t.Errorf("plaintext = %q, want %q", pt, tc.plaintext)
			}
		})
	}
}

func TestOpenWrongRecipient(t *testing.T) {
	sender := idFromSeed(1)
	recipient := idFromSeed(2)
	other := idFromSeed(3)
	rx := recipient.KEXPublic()

	box, err := Seal(&zeroRand{}, sender, rx, []byte("secret"), nil, testSealTime)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// A box sealed to recipient must not open under a different key: the signature
	// binds the recipient's x_pub, so the wrong recipient fails at signature check.
	if _, _, err := Open(other, box, nil, testSealTime, testMaxAge); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("Open(other) error = %v, want ErrBadSignature", err)
	}
}

func TestOpenTamperedAndBadAAD(t *testing.T) {
	sender := idFromSeed(1)
	recipient := idFromSeed(2)
	rx := recipient.KEXPublic()

	box, err := Seal(&zeroRand{}, sender, rx, []byte("payload"), []byte("aad"), testSealTime)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Flipping any byte must make Open fail (signature or AEAD tag), never panic.
	for i := range box {
		bad := append([]byte(nil), box...)
		bad[i] ^= 0xff
		if _, _, err := Open(recipient, bad, []byte("aad"), testSealTime, testMaxAge); err == nil {
			t.Fatalf("Open accepted box with byte %d flipped", i)
		}
	}
	// Wrong aad must fail the AEAD tag.
	if _, _, err := Open(recipient, box, []byte("wrong"), testSealTime, testMaxAge); err == nil {
		t.Fatal("Open accepted wrong aad")
	}
}

// TestSealBoxReplayRejected: a captured box re-opened outside the freshness window
// is rejected (ErrExpired), so an eavesdropper cannot replay an old box later. Within the
// window it still opens; a box from the future beyond the skew tolerance is also refused.
func TestSealBoxReplayRejected(t *testing.T) {
	sender := idFromSeed(1)
	recipient := idFromSeed(2)
	rx := recipient.KEXPublic()

	sealedAt := time.Unix(1_700_000_000, 0)
	box, err := Seal(&zeroRand{}, sender, rx, []byte("coordinates"), nil, sealedAt)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	const window = time.Minute

	// Fresh: opens within the window.
	if _, _, err := Open(recipient, box, nil, sealedAt.Add(30*time.Second), window); err != nil {
		t.Fatalf("Open within window: %v", err)
	}
	// Replayed later: rejected.
	if _, _, err := Open(recipient, box, nil, sealedAt.Add(2*time.Minute), window); !errors.Is(err, ErrExpired) {
		t.Fatalf("replayed box error = %v, want ErrExpired", err)
	}
	// From the future beyond skew tolerance: rejected.
	if _, _, err := Open(recipient, box, nil, sealedAt.Add(-2*time.Minute), window); !errors.Is(err, ErrExpired) {
		t.Fatalf("future box error = %v, want ErrExpired", err)
	}
}

func TestOpenTruncated(t *testing.T) {
	sender := idFromSeed(1)
	recipient := idFromSeed(2)
	rx := recipient.KEXPublic()
	box, err := Seal(&zeroRand{}, sender, rx, []byte("payload"), nil, testSealTime)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	for n := range len(box) {
		if _, _, err := Open(recipient, box[:n], nil, testSealTime, testMaxAge); err == nil {
			t.Fatalf("Open accepted truncated box of len %d", n)
		}
	}
}

// TestOpenRejectsTrailingJunk: Open enforces the canonical wire form — box and box||junk
// must not both open to the same plaintext (the signature and AEAD cover only the parsed
// fields, so without the check the suffixed box would open identically). Same rule
// routing.DecodeMsg enforces.
func TestOpenRejectsTrailingJunk(t *testing.T) {
	sender := idFromSeed(1)
	recipient := idFromSeed(2)
	rx := recipient.KEXPublic()

	box, err := Seal(&zeroRand{}, sender, rx, []byte("payload"), nil, testSealTime)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, _, err := Open(recipient, append(box, 0xde), nil, testSealTime, testMaxAge); err == nil {
		t.Error("Open accepted box with trailing junk")
	}
}

// FuzzOpen asserts the sealed-box decoder/decryptor is robust against untrusted
// input: it must never panic on arbitrary bytes. Inputs that happen to verify and
// decrypt are exercised too via valid seed boxes.
func FuzzOpen(f *testing.F) {
	sender := idFromSeed(1)
	recipient := idFromSeed(2)
	rx := recipient.KEXPublic()
	good := func(pt, aad []byte) []byte {
		box, err := Seal(&zeroRand{}, sender, rx, pt, aad, testSealTime)
		if err != nil {
			f.Fatalf("seed Seal: %v", err)
		}
		return box
	}
	f.Add(good(nil, nil))
	f.Add(good([]byte("hello"), []byte("aad")))
	f.Add([]byte{})
	f.Add(make([]byte, 32+32+1+16+64))

	f.Fuzz(func(t *testing.T, box []byte) {
		// Must not panic for any input or aad. A successful Open is fine; we only
		// assert robustness, not a round-trip (arbitrary bytes rarely verify).
		_, _, _ = Open(recipient, box, nil, testSealTime, testMaxAge)
		_, _, _ = Open(recipient, box, []byte("aad"), testSealTime, testMaxAge)
	})
}

func BenchmarkSeal(b *testing.B) {
	sender := idFromSeed(1)
	recipient := idFromSeed(2)
	rx := recipient.KEXPublic()
	pt := []byte("rendezvous coordinates payload")
	for b.Loop() {
		if _, err := Seal(&zeroRand{}, sender, rx, pt, nil, testSealTime); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOpen(b *testing.B) {
	sender := idFromSeed(1)
	recipient := idFromSeed(2)
	rx := recipient.KEXPublic()
	box, err := Seal(&zeroRand{}, sender, rx, []byte("rendezvous coordinates payload"), nil, testSealTime)
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		if _, _, err := Open(recipient, box, nil, testSealTime, testMaxAge); err != nil {
			b.Fatal(err)
		}
	}
}
