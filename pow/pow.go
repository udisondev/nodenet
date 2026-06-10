// Package pow is the proof-of-work gate on the NodeID: an asymmetric cost that
// makes minting an identity expensive while keeping verification almost free.
//
// The invariant is a difficulty d: a NodeID is admissible only if it has at
// least d leading zero bits. Because NodeID = BLAKE2b(ed_pub) and ed_pub is
// derived from a random master-seed, the only way to obtain a conforming
// identity is to grind seeds until one lands below the threshold — about 2^d
// derivations on average. Checking a finished identity, by contrast, is a single
// glance at the high bits (Satisfies). Mint-once, verify-on-every-packet: the
// asymmetry is the whole point.
//
// The gate is enforced at three places in the overlay (all live in higher
// packages that call into here):
//
//   - admission of a live edge — a peer admitted into the neighbour set must
//     clear the threshold, so a fake cannot be wedged into someone's table;
//   - origination of a packet — the sender's ed_pub rides in the packet and any
//     forwarder derives the originator's NodeID as BLAKE2b(ed_pub) and checks
//     the threshold, dropping a sub-threshold originator at the first honest
//     hop;
//   - admission into the knowledge table — a newcomer contact must clear the
//     threshold before it is stored, so a sub-threshold identity is never
//     remembered nor later handed out as a routing candidate.
//
// The threshold check is a self-protecting, verifiable invariant: every node
// enforces it locally on every interaction, with no trust in the peer. Security
// rests on it, so it must never depend on a peer's cooperation — hence Satisfies
// is on the hot path and allocates nothing.
//
// The difficulty value itself is a network-wide constant chosen by the deployer
// (tuned so a phone can join in tolerable time while a Sybil farm stays
// expensive). This package does NOT hardcode it: callers pass d. PoW is a speed
// bump that prices mass identity creation — a deterrent, not a wall.
//
// In the dependency DAG pow sits above identity (pow -> identity -> kad): it
// grinds identities during Solve and measures their NodeIDs with kad's keyspace
// math.
package pow

import (
	"context"
	"errors"
	"io"
	"runtime"
	"sync"

	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/kad"
)

// ErrUnsatisfiable is returned by Solve when the requested difficulty exceeds
// the number of bits in a NodeID, so no identity could ever satisfy it.
var ErrUnsatisfiable = errors.New("pow: difficulty exceeds NodeID bit length")

// LeadingZeros returns the number of leading zero bits of the NodeID, 0..IDBits.
// An all-zero ID has IDBits (256). It allocates nothing.
//
// It reuses kad's common-prefix primitive: the bits a NodeID shares with the
// zero ID are exactly its leading zero bits.
func LeadingZeros(id kad.ID) int {
	return kad.CommonPrefixLen(id, kad.ID{})
}

// Satisfies reports whether id clears difficulty d, i.e. has at least d leading
// zero bits. This is the level-2 self-protection check a forwarder runs on every
// packet's origin and on every admission, so it stays allocation-free. A
// non-positive d admits any ID (PoW disabled).
func Satisfies(id kad.ID, d int) bool {
	return LeadingZeros(id) >= d
}

// Solve grinds random seeds until it derives an identity whose NodeID clears
// difficulty d, then returns that identity — persist its Seed to keep it. It
// reads SeedLen-byte seeds from rand (pass crypto/rand.Reader in production).
//
// The search runs one worker per schedulable CPU (GOMAXPROCS); the first hit
// cancels the rest via ctx.
// Pass a cancellable or deadline-bound ctx to cap the grind: if ctx fires before
// a hit, Solve returns ctx.Err(). A read error from rand aborts with that error.
// A difficulty above the NodeID bit length is rejected up front with
// ErrUnsatisfiable rather than grinding forever; d <= 0 is met by the first seed.
func Solve(ctx context.Context, rand io.Reader, d int) (*identity.Identity, error) {
	if d > kad.IDBits {
		return nil, ErrUnsatisfiable
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		mu     sync.Mutex // guards rand (shared reader) and the result/err handoff
		result *identity.Identity
		failed error
		wg     sync.WaitGroup
	)

	// GOMAXPROCS, not NumCPU: it tracks the scheduler's actual parallelism
	// (cgroup CPU quotas included), so the pool never exceeds what can run.
	for range runtime.GOMAXPROCS(0) {
		wg.Go(func() {
			var seed [identity.SeedLen]byte
			for {
				if ctx.Err() != nil {
					return
				}
				// Serialize reads: a single io.Reader is not generally safe for
				// concurrent use, and the per-attempt key derivation below
				// dominates, so the lock is not on the hot part of the grind.
				mu.Lock()
				_, err := io.ReadFull(rand, seed[:])
				mu.Unlock()
				if err != nil {
					mu.Lock()
					if failed == nil {
						failed = err
					}
					mu.Unlock()
					cancel()
					return
				}

				id := identity.FromSeed(seed)
				if Satisfies(id.ID(), d) {
					mu.Lock()
					if result == nil {
						result = id
					}
					mu.Unlock()
					cancel()
					return
				}
			}
		})
	}
	wg.Wait()

	if result != nil {
		return result, nil
	}
	if failed != nil {
		return nil, failed
	}
	return nil, ctx.Err()
}
