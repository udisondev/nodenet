//go:build e2e_real || e2e_nat

package quic

import "github.com/udisondev/nodenet/identity"

// idFromSeed builds a deterministic identity from a one-byte seed, matching
// transporttest.IDFromSeed so the e2e suites can name dial targets by seed.
func idFromSeed(seed byte) *identity.Identity {
	var s [identity.SeedLen]byte
	s[0] = seed
	return identity.FromSeed(s)
}
