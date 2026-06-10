package rendezvous

import (
	"sync"
	"time"

	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/kad"
)

// maxReplayEntries bounds the ReplayCache across its two generations (half each). When
// the current generation fills with still-fresh entries the cache rotates: the previous
// generation is dropped, the full one keeps answering lookups, and inserts continue into
// an empty map — so a freshly opened box is always recorded in O(1) and dedup keeps
// holding at least the most recent maxReplayEntries/2 keys under a fill flood. The bound
// sits well above the box rate any single recipient sustains within a freshness window,
// so honest traffic never reaches a rotation.
const maxReplayEntries = 1 << 16

// ReplayCache closes the within-window replay gap that the freshness timestamp alone
// leaves: it remembers the ephemeral public key of every box it has accepted and rejects
// a second appearance of the same key while it is still fresh. Each box carries a unique
// ephemeral key, so the key is the natural per-box identifier. Entries expire after the
// window, so the set stays bounded by the box rate times the window; two generations cap
// it absolutely at maxReplayEntries even under a flood of distinct valid boxes.
//
// It is safe for concurrent use. Construct it with NewReplayCache; open boxes through its
// Open method, which layers the dedup on top of the stateless sealed-box Open.
type ReplayCache struct {
	maxAge time.Duration
	mu     sync.Mutex
	// cur and prev are the two generations: inserts go to cur, lookups consult both.
	// When cur fills to maxReplayEntries/2, prev is dropped and cur becomes prev — an
	// O(1) rotation, so saturation never costs a scan. A recorded key survives at least
	// one full generation of subsequent inserts before it can be forgotten.
	cur, prev map[[ephPubLen]byte]int64 // ephemeral pub -> expiry (Unix nanoseconds)
	sweepAt   int64                     // next time (Unix nanoseconds) to evict expired entries
}

// NewReplayCache returns a cache whose accepted boxes are remembered for maxAge, which
// is also the freshness window its Open enforces — so an entry lives exactly as long as
// a box can be fresh.
func NewReplayCache(maxAge time.Duration) *ReplayCache {
	return &ReplayCache{maxAge: maxAge, cur: make(map[[ephPubLen]byte]int64)}
}

// Open authenticates and decrypts box like the package-level Open (using this cache's
// maxAge for the freshness window), then enforces single-use: a box whose ephemeral key
// was already accepted within the window returns ErrReplay. Only a box that passes
// signature, freshness and decryption is recorded, so a forged or stale box cannot
// pollute the cache.
func (c *ReplayCache) Open(recipient *identity.Identity, box, aad []byte, now time.Time) (kad.ID, []byte, error) {
	id, pt, err := Open(recipient, box, aad, now, c.maxAge)
	if err != nil {
		return id, pt, err
	}
	// Open succeeded, so box is at least ephPubLen long and its first ephPubLen bytes are
	// the (authenticated-by-signature) ephemeral key.
	var eph [ephPubLen]byte
	copy(eph[:], box[:ephPubLen])
	if !c.record(eph, now) {
		return kad.ID{}, nil, ErrReplay
	}
	return id, pt, nil
}

// record reports whether eph is new (and remembers it); a key still within its window
// returns false. It evicts expired entries opportunistically. A freshly opened box MUST
// always be recorded — otherwise its immediate replay would be accepted — so when the
// current generation is full it rotates (drop prev, cur becomes prev, insert into a new
// map) rather than refusing the insert or scanning for a victim.
func (c *ReplayCache) record(eph [ephPubLen]byte, now time.Time) bool {
	nowN := now.UnixNano()
	c.mu.Lock()
	defer c.mu.Unlock()

	if nowN >= c.sweepAt {
		for k, exp := range c.cur {
			if nowN >= exp {
				delete(c.cur, k)
			}
		}
		for k, exp := range c.prev {
			if nowN >= exp {
				delete(c.prev, k)
			}
		}
		c.sweepAt = nowN + c.maxAge.Nanoseconds()
	}

	if exp, ok := c.cur[eph]; ok && nowN < exp {
		return false // replay within the window
	}
	if exp, ok := c.prev[eph]; ok && nowN < exp {
		return false // replay within the window
	}
	if len(c.cur) >= maxReplayEntries/2 {
		c.prev = c.cur
		c.cur = make(map[[ephPubLen]byte]int64, maxReplayEntries/2)
	}
	c.cur[eph] = nowN + c.maxAge.Nanoseconds()
	return true
}
