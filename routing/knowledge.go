package routing

import (
	"encoding/binary"
	"math/rand/v2"
	"slices"
	"sync"
	"time"

	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/pow"
)

// SubnetCap is the most entries one subnet (/24 or /64) may hold across the whole
// knowledge table. It prices cheap Sybil clusters sharing an address range and
// keeps learned contacts spread over independent failure domains
// (level-2-adjacent self-protection). It is a tunable bound, not a protocol
// constant: a deployer may raise or lower it. Contacts whose address carries no
// subnet (the in-memory transport, hostnames) are exempt — the cap is inert for
// them.
const SubnetCap = 8

// ObserveOutcome is what Observe did with a contact. The table does no I/O and so
// cannot itself resolve a full bucket: that case surfaces as a probe handoff the
// caller runs and reports back via Confirm.
type ObserveOutcome uint8

const (
	// ObserveIgnored: the contact was self. A node never stores itself, so the
	// observation is a no-op — no admission, no refresh, no handoff.
	ObserveIgnored ObserveOutcome = iota
	// ObserveInserted: the contact was admitted as a newcomer or refreshed in place.
	ObserveInserted
	// ObserveNeedProbe: the bucket was full. The newcomer is stashed in the
	// replacement cache and the probe ID Observe returns beside this outcome names
	// the least-recently-seen incumbent for the caller to ping, reporting the result
	// with Confirm.
	ObserveNeedProbe
	// ObserveRejected: the contact was refused — its key does not bind to its
	// claimed ID, its NodeID does not clear the admission-PoW difficulty, or the
	// subnet-diversity cap is full. No handoff follows.
	ObserveRejected
)

// Knowledge is the soft-state k-bucket table: a cheap, lazily maintained pool of
// learned contacts that feeds greedy routing and live-edge replacement. It does
// no I/O — a full bucket surfaces a probe candidate instead of pinging — and it is
// read-dominated, so an RWMutex guards it. Time enters only as an explicit now
// argument; the table never reads the clock itself.
type Knowledge struct {
	self      kad.ID
	subnetf   SubnetFunc
	dmin      int // admission-PoW difficulty a newcomer's NodeID must clear to enter
	mu        sync.RWMutex
	buckets   [BucketCount]bucket
	subnetCnt map[Subnet]uint16 // table-wide admitted-entry count per subnet
	n         int               // total admitted entries
}

// bucket holds the contacts that share a given common-prefix length with self.
// entries is ordered most-recently-seen first (front) to least-recently-seen last
// (back), so the back is the eviction probe candidate. replace is a bounded cache
// of newcomers that arrived while the bucket was full, also MRU-first.
type bucket struct {
	entries  []Contact
	replace  []Contact
	lastRefr time.Time
}

// NewKnowledge creates an empty table owned by self. subnetf derives the diversity
// key of an address; a nil subnetf defaults to NoSubnet (caps inert), which is the
// right choice for the in-memory transport. dmin is the admission-PoW difficulty: a
// newcomer contact whose NodeID does not clear dmin leading zero bits is refused, so
// a sub-threshold Sybil identity never enters the table; 0 admits any NodeID,
// matching pow.Satisfies.
func NewKnowledge(self kad.ID, subnetf SubnetFunc, dmin int) *Knowledge {
	if subnetf == nil {
		subnetf = NoSubnet
	}
	return &Knowledge{self: self, subnetf: subnetf, dmin: dmin, subnetCnt: make(map[Subnet]uint16)}
}

// Observe records a successful interaction with a peer: it is the single
// last-seen-refresh and opportunistic-learning entry point, called for every
// delivered packet (carrying the originator's ed_pub), every learned contact
// list, and every direct exchange. Refreshing an existing contact (the common
// case) is the hot path and allocates nothing; admitting a newcomer or handing
// off a full bucket is the cold path. probe is meaningful only for
// ObserveNeedProbe — it names the incumbent to ping — and is zero otherwise.
func (k *Knowledge) Observe(c Contact, now time.Time) (outcome ObserveOutcome, probe kad.ID) {
	if c.ID == k.self {
		return ObserveIgnored, kad.ID{}
	}
	// level-2 key-binding: refuse a contact whose key does not hash to its claimed NodeID,
	// so the admission-PoW gate cannot be bypassed by pairing an arbitrary or a victim's
	// ID with an unrelated key. Checked before the refresh branch so a forged packet
	// cannot overwrite a verified contact's key. (Keyless ID-only hints bind trivially.)
	if !c.bindsID() {
		return ObserveRejected, kad.ID{}
	}
	// level-2: nothing on the wire binds an X25519 key to a NodeID (the ID hashes only
	// ed_pub), so an XPub arriving with an observation is unauthenticated key material
	// and is never stored — a gossiped contact list could otherwise substitute an
	// attacker's key under a victim's ID. BindXPub is the only entry for the key, for
	// callers that verified an originator-signed channel covering it.
	c.XPub = [32]byte{}
	bi := kad.CommonPrefixLen(k.self, c.ID)
	k.mu.Lock()
	defer k.mu.Unlock()
	b := &k.buckets[bi]

	if i := indexOf(b.entries, c.ID); i >= 0 {
		e := b.entries[i]
		// level-2-adjacent: an address update may move the contact between subnets, so
		// the SubnetCap accounting must follow it — a stale subnet would let updates
		// bypass the cap (admit with no recognizable subnet, then point the entry into
		// a saturated one). Re-derive only when the observation actually brings other
		// addresses, so the common same-address refresh stays free.
		if len(c.Addrs) > 0 && !slices.Equal(e.Addrs, c.Addrs) {
			k.deriveSubnet(&c)
			if c.hasSubnet != e.hasSubnet || c.subnet != e.subnet {
				if c.hasSubnet && k.subnetCnt[c.subnet] >= SubnetCap {
					c.Addrs = nil // new subnet full: refuse the address update, keep the rest
				} else {
					if e.hasSubnet {
						k.decSubnet(e.subnet)
					}
					if c.hasSubnet {
						k.subnetCnt[c.subnet]++
					}
					e.subnet, e.hasSubnet = c.subnet, c.hasSubnet
				}
			}
		}
		mergeLearned(&e, c)
		e.lastSeen = now
		moveToFront(b.entries, i, e)
		return ObserveInserted, kad.ID{}
	}

	// level-2 admission-PoW: a newcomer's NodeID must clear the difficulty before it
	// may enter the table, so a sub-threshold Sybil identity is neither stored nor
	// later handed out by Closest. The NodeID self-certifies its work (leading zeros),
	// so this needs no ed_pub. An already-admitted contact (the refresh branch above)
	// was vetted on entry and is not re-checked, keeping the refresh hot path free.
	if !pow.Satisfies(c.ID, k.dmin) {
		return ObserveRejected, kad.ID{}
	}

	k.deriveSubnet(&c)
	if c.hasSubnet && k.subnetCnt[c.subnet] >= SubnetCap {
		return ObserveRejected, kad.ID{}
	}
	c.lastSeen = now
	if len(b.entries) < K {
		k.admit(b, c)
		return ObserveInserted, kad.ID{}
	}
	// Full bucket: do not evict blindly. Stash the newcomer and surface the
	// least-recently-seen incumbent for the caller to probe — an old verified
	// contact is never displaced by a flood of new IDs (level-2-adjacent
	// anti-eviction-flooding).
	k.stashReplace(b, c)
	return ObserveNeedProbe, b.entries[len(b.entries)-1].ID
}

// Confirm resolves an eviction probe the caller ran after an ObserveNeedProbe
// outcome. If the incumbent is alive it is kept and refreshed to
// most-recently-seen; if it is dead it is evicted and the freshest stashed
// newcomer that still fits the diversity cap is promoted into its slot.
func (k *Knowledge) Confirm(incumbent kad.ID, alive bool, now time.Time) {
	bi := kad.CommonPrefixLen(k.self, incumbent)
	k.mu.Lock()
	defer k.mu.Unlock()
	b := &k.buckets[bi]
	i := indexOf(b.entries, incumbent)
	if i < 0 {
		return
	}
	if alive {
		e := b.entries[i]
		e.lastSeen = now
		moveToFront(b.entries, i, e)
		return
	}
	k.removeEntryAt(b, i)
	k.promote(b)
}

// MarkDead lazily purges a contact that failed to answer: it is removed, and the
// freshest fitting replacement candidate is promoted to keep the bucket full. The
// promoted contact is returned so the caller may choose to dial it. If id is not a
// live entry (it may still be a stashed candidate) it is dropped from the
// replacement cache and ok is false.
func (k *Knowledge) MarkDead(id kad.ID) (promoted Contact, ok bool) {
	bi := kad.CommonPrefixLen(k.self, id)
	k.mu.Lock()
	defer k.mu.Unlock()
	b := &k.buckets[bi]
	i := indexOf(b.entries, id)
	if i < 0 {
		if j := indexOf(b.replace, id); j >= 0 {
			b.replace = slices.Delete(b.replace, j, j+1)
		}
		return Contact{}, false
	}
	k.removeEntryAt(b, i)
	return k.promote(b)
}

// BindXPub records the contact's static X25519 key, learned over an authenticated
// channel. Nothing in the overlay wire format binds an X25519 key to a NodeID — the
// ID hashes only the Ed25519 key — so Observe ignores the XPub of anything it is fed
// and this is the key's single entry point. Only a caller that verified the key
// against an originator signature covering it (the rendezvous Hello/Reply) may bind
// it (level-2: the table never hands out key material a third party could have
// planted). An unknown id is a no-op: the key is soft state and is re-learned the
// same authenticated way.
func (k *Knowledge) BindXPub(id kad.ID, xpub [32]byte) {
	if id == k.self {
		return
	}
	bi := kad.CommonPrefixLen(k.self, id)
	k.mu.Lock()
	defer k.mu.Unlock()
	b := &k.buckets[bi]
	if i := indexOf(b.entries, id); i >= 0 {
		b.entries[i].XPub = xpub
		return
	}
	if i := indexOf(b.replace, id); i >= 0 {
		b.replace[i].XPub = xpub
	}
}

// Get returns the stored contact for id, if any.
func (k *Knowledge) Get(id kad.ID) (Contact, bool) {
	if id == k.self {
		return Contact{}, false
	}
	bi := kad.CommonPrefixLen(k.self, id)
	k.mu.RLock()
	defer k.mu.RUnlock()
	b := &k.buckets[bi]
	if i := indexOf(b.entries, id); i >= 0 {
		return b.entries[i], true
	}
	return Contact{}, false
}

// Len reports the number of admitted contacts (excluding replacement-cache
// candidates).
func (k *Knowledge) Len() int {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.n
}

// Closest returns up to n contacts nearest target under the XOR metric, closest
// first, appended into buf. It is the input to greedy routing and to replacement
// selection. Pass a buf with capacity ≥ n (e.g. make([]Contact, 0, n)) and it
// allocates nothing.
func (k *Knowledge) Closest(target kad.ID, n int, buf []Contact) []Contact {
	buf = buf[:0]
	if n <= 0 {
		return buf
	}
	k.mu.RLock()
	defer k.mu.RUnlock()

	// Buckets are indexed by common-prefix length with self, so for a query target
	// the entries fall into three closeness tiers keyed off b = CPL(self, target):
	//   - bucket b      → CPL(target, entry) > b   (closest)
	//   - buckets > b   → CPL(target, entry) = b
	//   - bucket bi < b → CPL(target, entry) = bi  (farther as bi shrinks)
	// A longer shared prefix with target is unconditionally closer under XOR, so we
	// walk bucket b, then the >b tier, then <b buckets descending, and stop the
	// moment the n-th kept contact out-shares everything the unscanned buckets could
	// hold. The visited contacts — hence the result and its order — are exactly
	// those of a full scan; only provably-farther buckets are skipped.
	b := kad.CommonPrefixLen(k.self, target)

	if b < BucketCount {
		es := k.buckets[b].entries
		for i := range es {
			buf = insertClosest(buf, es[i], target, n)
		}
	}
	// The >b tier all share exactly b bits with target; skip it only once bucket b
	// has filled buf with strictly-closer contacts (n-th shares more than b bits).
	if len(buf) < n || kad.CommonPrefixLen(target, buf[n-1].ID) <= b {
		for bi := b + 1; bi < BucketCount; bi++ {
			es := k.buckets[bi].entries
			for i := range es {
				buf = insertClosest(buf, es[i], target, n)
			}
		}
	}
	// Buckets below b in descending order: bucket bi yields contacts sharing exactly
	// bi bits with target, so once the n-th kept contact shares strictly more, no
	// smaller bucket can beat it.
	for bi := b - 1; bi >= 0; bi-- {
		if len(buf) == n && kad.CommonPrefixLen(target, buf[n-1].ID) > bi {
			break
		}
		es := k.buckets[bi].entries
		for i := range es {
			buf = insertClosest(buf, es[i], target, n)
		}
	}
	return buf
}

// RefreshTarget picks the most-stale populated bucket whose last refresh is at
// least staleAfter old and returns a random ID lying inside its keyspace range, for
// the caller to look up (Kademlia bucket refresh) — and marks that bucket refreshed
// as of now. ok is false when no bucket is due. Empty buckets are skipped: they hold
// nothing to keep fresh, and most of the 256 prefix lengths are unpopulatable in any
// real network, so refreshing them would starve the populated ones (level-3 policy —
// knowledge of empty regions arrives via ordinary lookups instead). rng makes the
// choice of target deterministic for tests.
func (k *Knowledge) RefreshTarget(now time.Time, staleAfter time.Duration, rng *rand.Rand) (kad.ID, bool) {
	threshold := now.Add(-staleAfter)
	k.mu.Lock()
	defer k.mu.Unlock()
	best := -1
	for i := range k.buckets {
		if len(k.buckets[i].entries) == 0 || k.buckets[i].lastRefr.After(threshold) {
			continue
		}
		if best < 0 || k.buckets[i].lastRefr.Before(k.buckets[best].lastRefr) {
			best = i
		}
	}
	if best < 0 {
		return kad.ID{}, false
	}
	k.buckets[best].lastRefr = now
	return k.randomInBucket(best, rng), true
}

// --- internal helpers (caller holds the appropriate lock) ---

// deriveSubnet sets c.subnet from the first of c.Addrs the SubnetFunc accepts.
func (k *Knowledge) deriveSubnet(c *Contact) {
	for _, a := range c.Addrs {
		if s, ok := k.subnetf(a); ok {
			c.subnet, c.hasSubnet = s, true
			return
		}
	}
	c.hasSubnet = false
}

// admit prepends c as the most-recently-seen entry and counts its subnet.
func (k *Knowledge) admit(b *bucket, c Contact) {
	b.entries = slices.Insert(b.entries, 0, c)
	if c.hasSubnet {
		k.subnetCnt[c.subnet]++
	}
	k.n++
}

// stashReplace prepends c into the bounded replacement cache (deduping by ID),
// dropping the least-recently-seen candidate past capacity.
func (k *Knowledge) stashReplace(b *bucket, c Contact) {
	if i := indexOf(b.replace, c.ID); i >= 0 {
		moveToFront(b.replace, i, c)
		return
	}
	b.replace = slices.Insert(b.replace, 0, c)
	if len(b.replace) > K {
		// slices.Delete (not a plain truncate) zeroes the dropped slot, so the evicted
		// candidate's Addrs are not pinned by the backing array.
		b.replace = slices.Delete(b.replace, K, len(b.replace))
	}
}

// removeEntryAt deletes entry i, fixing the subnet count and total. slices.Delete
// zeroes the vacated tail slot, so the removed contact's Addrs are not pinned by
// the backing array.
func (k *Knowledge) removeEntryAt(b *bucket, i int) {
	c := b.entries[i]
	b.entries = slices.Delete(b.entries, i, i+1)
	if c.hasSubnet {
		k.decSubnet(c.subnet)
	}
	k.n--
}

// promote admits the freshest replacement candidate that still fits the diversity
// cap, returning it. The capacity guard runs BEFORE a candidate is taken off the
// cache: both callers free a slot first, so it never fires today, but a guard that
// popped a candidate it then could not place would silently lose it.
func (k *Knowledge) promote(b *bucket) (Contact, bool) {
	if len(b.entries) >= K {
		return Contact{}, false
	}
	for len(b.replace) > 0 {
		c := b.replace[0]
		b.replace = slices.Delete(b.replace, 0, 1)
		if c.hasSubnet && k.subnetCnt[c.subnet] >= SubnetCap {
			continue
		}
		k.admit(b, c)
		return c, true
	}
	return Contact{}, false
}

func (k *Knowledge) decSubnet(s Subnet) {
	if k.subnetCnt[s] <= 1 {
		delete(k.subnetCnt, s)
		return
	}
	k.subnetCnt[s]--
}

// randomInBucket returns a random ID whose common-prefix length with self is
// exactly i: it shares self's first i bits, differs at bit i, and is random
// thereafter — so it lands in bucket i's keyspace range.
func (k *Knowledge) randomInBucket(i int, rng *rand.Rand) kad.ID {
	var id kad.ID
	for o := 0; o < kad.IDLen; o += 8 {
		binary.BigEndian.PutUint64(id[o:], rng.Uint64())
	}
	full := i / 8
	copy(id[:full], k.self[:full])
	if rem := i % 8; rem > 0 {
		mask := byte(0xff) << (8 - rem) // the top rem bits
		id[full] = (k.self[full] & mask) | (id[full] &^ mask)
	}
	// Force bit i to the complement of self's bit i so CommonPrefixLen is exactly i.
	pos := uint(7 - i%8)
	selfBit := (k.self[i/8] >> pos) & 1
	id[i/8] = (id[i/8] &^ (1 << pos)) | ((selfBit ^ 1) << pos)
	return id
}

// indexOf returns the position of id in s, or -1.
func indexOf(s []Contact, id kad.ID) int {
	for i := range s {
		if s[i].ID == id {
			return i
		}
	}
	return -1
}

// moveToFront places e at index 0, shifting s[0:i] right by one. It moves struct
// values within the slice and allocates nothing — the hot-path refresh primitive.
func moveToFront(s []Contact, i int, e Contact) {
	copy(s[1:i+1], s[:i])
	s[0] = e
}

// mergeLearned folds newly-learned fields of c into e without clobbering known
// values with zeros: a refresh from a packet that carries only an address must not
// erase a previously-learned ed_pub. XPub is deliberately absent: it enters the
// table only through BindXPub (see Observe). It copies fixed-size values only — no
// alloc.
func mergeLearned(e *Contact, c Contact) {
	var zero [32]byte
	if c.EdPub != zero {
		e.EdPub = c.EdPub
	}
	if c.Caps != 0 {
		e.Caps = c.Caps
	}
	if len(c.Addrs) > 0 {
		e.Addrs = c.Addrs
	}
}

// insertClosest keeps buf the ≤n contacts nearest target, closest first. With
// cap(buf) ≥ n it allocates nothing.
func insertClosest(buf []Contact, c Contact, target kad.ID, n int) []Contact {
	if len(buf) < n {
		buf = append(buf, c)
		for i := len(buf) - 1; i > 0; i-- {
			if kad.DistanceCmp(target, buf[i].ID, buf[i-1].ID) < 0 {
				buf[i], buf[i-1] = buf[i-1], buf[i]
			} else {
				break
			}
		}
		return buf
	}
	if kad.DistanceCmp(target, c.ID, buf[n-1].ID) < 0 {
		buf[n-1] = c
		for i := n - 1; i > 0; i-- {
			if kad.DistanceCmp(target, buf[i].ID, buf[i-1].ID) < 0 {
				buf[i], buf[i-1] = buf[i-1], buf[i]
			} else {
				break
			}
		}
	}
	return buf
}
