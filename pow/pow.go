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
//
// On a normal return — a hit or a rand error — Solve has joined every worker,
// so rand is no longer in use and a stateful, non-thread-safe reader may be
// reused for the next call. Only when the caller's ctx fires can Solve return
// while a worker is still wedged inside a blocking rand.Read; treat the reader
// as still borrowed by Solve in that case.
func Solve(ctx context.Context, rand io.Reader, d int) (*identity.Identity, error) {
	if d > kad.IDBits {
		return nil, ErrUnsatisfiable
	}

	// ext is the caller's context: the one escape hatch from joining the
	// workers below, kept reachable past the shadowing.
	ext := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var mu sync.Mutex // guards rand: a single io.Reader is not safe for concurrent use

	// outcome carries the first worker's result or read error to the caller. The
	// handoff is by channel (not a shared variable), so the caller never reads
	// worker state under a lock — which matters because a worker wedged inside a
	// blocking rand.Read holds mu indefinitely, and the caller must still return.
	type outcome struct {
		id  *identity.Identity
		err error
	}
	res := make(chan outcome, 1) // buffered: first writer wins, others drop via default

	// GOMAXPROCS, not NumCPU: it tracks the scheduler's actual parallelism
	// (cgroup CPU quotas included), so the pool never exceeds what can run.
	var wg sync.WaitGroup
	for range runtime.GOMAXPROCS(0) {
		wg.Add(1)
		go func() {
			defer wg.Done()
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
					select {
					case res <- outcome{err: err}:
					default:
					}
					cancel()
					return
				}

				// Grind with the NodeID-only derivation: testing the threshold
				// needs just the NodeID, and the full X25519 scalar-mult that
				// FromSeed runs is wasted work for the ~2^d losing seeds. Mint the
				// complete identity once, for the single winning seed.
				if Satisfies(identity.IDFromSeed(seed), d) {
					select {
					case res <- outcome{id: identity.FromSeed(seed)}:
					default:
					}
					cancel()
					return
				}
			}
		}()
	}

	// idle closes once every worker has exited, i.e. no goroutine of this call
	// can touch rand anymore.
	idle := make(chan struct{})
	go func() { wg.Wait(); close(idle) }()

	// join stops the search and waits the workers out, so that on return the
	// caller may immediately reuse a stateful, non-thread-safe reader: mu is
	// per-call and cannot order a straggler from this call against the next
	// call's workers. The single exception is the caller's own ctx firing — a
	// worker wedged inside a blocking rand.Read would otherwise park Solve
	// forever, so join yields and the wedged worker keeps the reader borrowed.
	join := func() {
		cancel()
		select {
		case <-idle:
		case <-ext.Done():
		}
	}
	defer join()

	// Return on the first outcome, or on ctx cancellation. The ctx branch covers
	// both an external deadline/cancel and a worker wedged in a blocking reader:
	// either way Solve returns instead of parking forever. A worker that hit just
	// as ctx fired is still recovered by draining res before reporting ctx.Err().
	select {
	case o := <-res:
		if o.err != nil {
			return nil, o.err
		}
		return o.id, nil
	case <-ctx.Done():
		select {
		case o := <-res:
			if o.err != nil {
				return nil, o.err
			}
			if o.id != nil {
				return o.id, nil
			}
		default:
		}
		return nil, ctx.Err()
	}
}
