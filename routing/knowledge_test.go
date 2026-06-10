package routing

import (
	"encoding/binary"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/transport"
)

// --- shared test helpers (white-box: tests live in package routing) ---

var t0 = time.Unix(1_700_000_000, 0)

// idInBucket returns a deterministic ID whose common-prefix length with self is
// exactly bi, distinguished by variant. bi must be < 224 so variant (written into
// the trailing bytes) lands after the differing bit and never changes the prefix.
func idInBucket(self kad.ID, bi, variant int) kad.ID {
	var id kad.ID
	copy(id[:], self[:])
	id[bi/8] ^= 1 << uint(7-bi%8) // differ at bit bi
	binary.BigEndian.PutUint32(id[28:], uint32(variant))
	return id
}

// subnetByEndpoint maps each distinct Endpoint string to a distinct subnet, so a
// test can put contacts in the same subnet by giving them the same Endpoint.
func subnetByEndpoint(a transport.Addr) (Subnet, bool) {
	if a.Endpoint == "" {
		return Subnet{}, false
	}
	var s Subnet
	copy(s[:], a.Endpoint)
	return s, true
}

func contactInBucket(self kad.ID, bi, variant int) Contact {
	return Contact{ID: idInBucket(self, bi, variant)}
}

// randID draws a uniformly random NodeID from rng.
func randID(rng *rand.Rand) kad.ID {
	var id kad.ID
	for o := 0; o < kad.IDLen; o += 8 {
		binary.BigEndian.PutUint64(id[o:], rng.Uint64())
	}
	return id
}

// --- tests ---

// TestObservePoWFilter: with a non-zero admission difficulty, a newcomer whose NodeID
// does not clear the leading-zero threshold is refused — it never enters the table and
// so can never be handed out by Closest. A NodeID that clears the threshold is admitted.
func TestObservePoWFilter(t *testing.T) {
	self := kad.ID{0xC0} // MSB set, distinct from the contacts below
	k := NewKnowledge(self, nil, 1)

	sub := kad.ID{0x80, 0x01} // 0 leading zero bits — fails d=1
	if out, _ := k.Observe(Contact{ID: sub}, t0); out != ObserveRejected {
		t.Fatalf("sub-PoW contact: got %v, want ObserveRejected", out)
	}
	if _, ok := k.Get(sub); ok {
		t.Fatal("sub-PoW contact entered the table")
	}
	if c := k.Closest(sub, Siblings, nil); len(c) != 0 {
		t.Fatalf("Closest handed out %d contacts; sub-PoW must not be stored", len(c))
	}

	good := kad.ID{0x40, 0x02} // 1 leading zero bit — clears d=1
	if out, _ := k.Observe(Contact{ID: good}, t0); out != ObserveInserted {
		t.Fatalf("valid contact: got %v, want ObserveInserted", out)
	}
	if _, ok := k.Get(good); !ok {
		t.Fatal("valid contact did not enter the table")
	}
}

func TestObserveAndGet(t *testing.T) {
	var self kad.ID
	k := NewKnowledge(self, nil, 0)

	if k.Len() != 0 {
		t.Fatalf("empty Len = %d", k.Len())
	}
	// self is never stored.
	if out, _ := k.Observe(Contact{ID: self}, t0); out == ObserveInserted {
		t.Fatal("self was admitted")
	}
	if k.Len() != 0 {
		t.Fatalf("Len after observing self = %d", k.Len())
	}

	c := contactInBucket(self, 10, 1)
	if out, _ := k.Observe(c, t0); out != ObserveInserted {
		t.Fatalf("Observe newcomer: %v", out)
	}
	if k.Len() != 1 {
		t.Fatalf("Len = %d, want 1", k.Len())
	}
	got, ok := k.Get(c.ID)
	if !ok || got.ID != c.ID {
		t.Fatalf("Get = %v, %v", got.ID, ok)
	}
	if !got.LastSeen().Equal(t0) {
		t.Fatalf("lastSeen = %v, want %v", got.LastSeen(), t0)
	}
}

func TestObserveRefresh(t *testing.T) {
	var self kad.ID
	k := NewKnowledge(self, nil, 0)
	bi := 10
	a := contactInBucket(self, bi, 1)
	b := contactInBucket(self, bi, 2)
	k.Observe(a, t0)
	k.Observe(b, t0) // b now at front, a at back

	// Refresh a with a newer time (keyless, as a passing-packet refresh would be).
	a2 := a
	t1 := t0.Add(time.Minute)
	if out, _ := k.Observe(a2, t1); out != ObserveInserted {
		t.Fatalf("refresh result: %v", out)
	}
	if k.Len() != 2 {
		t.Fatalf("Len = %d, want 2 (refresh must not grow)", k.Len())
	}
	// a moved to front; its lastSeen updated.
	if k.buckets[bi].entries[0].ID != a.ID {
		t.Fatal("refreshed entry not moved to front")
	}
	got, _ := k.Get(a.ID)
	if !got.LastSeen().Equal(t1) {
		t.Fatalf("lastSeen = %v, want %v", got.LastSeen(), t1)
	}
}

// TestObserveMergesBoundKey: an ID-only hint that is later re-observed with the matching
// Ed25519 key folds the key in (keyless → keyed upgrade), since the key binds to the ID.
func TestObserveMergesBoundKey(t *testing.T) {
	self := kad.ID{0xff}
	k := NewKnowledge(self, nil, 0)

	idn := identity.FromSeed([identity.SeedLen]byte{9})
	id := idn.ID()
	key := edPubOf(idn)

	k.Observe(Contact{ID: id}, t0) // keyless hint
	if got, _ := k.Get(id); got.EdPub != ([32]byte{}) {
		t.Fatal("hint should start keyless")
	}
	if out, _ := k.Observe(Contact{ID: id, EdPub: key}, t0.Add(time.Minute)); out != ObserveInserted {
		t.Fatalf("keyed refresh result: %v", out)
	}
	if got, _ := k.Get(id); got.EdPub != key {
		t.Fatal("bound key was not merged on refresh")
	}
}

func TestMergeLearnedDoesNotClobber(t *testing.T) {
	self := kad.ID{0xff}
	k := NewKnowledge(self, nil, 0)
	idn := identity.FromSeed([identity.SeedLen]byte{11})
	key := edPubOf(idn)
	c := Contact{ID: idn.ID(), EdPub: key, Caps: CanRelay}
	k.Observe(c, t0)

	// A bare refresh (no ed_pub, no caps) must not erase what we know.
	k.Observe(Contact{ID: c.ID}, t0.Add(time.Minute))
	got, _ := k.Get(c.ID)
	if got.EdPub != key {
		t.Fatal("ed_pub erased by bare refresh")
	}
	if !got.Caps.Has(CanRelay) {
		t.Fatal("caps erased by bare refresh")
	}
}

func TestEvictionHandoff(t *testing.T) {
	var self kad.ID
	k := NewKnowledge(self, nil, 0)
	bi := 10
	// Fill the bucket: c0..c(K-1). Each admit prepends, so c0 ends at the back.
	cs := make([]Contact, K)
	for i := range cs {
		cs[i] = contactInBucket(self, bi, i)
		if out, _ := k.Observe(cs[i], t0); out != ObserveInserted {
			t.Fatalf("fill %d: %v", i, out)
		}
	}
	if k.Len() != K {
		t.Fatalf("Len = %d, want %d", k.Len(), K)
	}

	// A newcomer into the full bucket surfaces the LRU (c0) as the probe.
	nc := contactInBucket(self, bi, 100)
	out, probe := k.Observe(nc, t0)
	if out != ObserveNeedProbe || probe != cs[0].ID {
		t.Fatalf("expected probe of LRU %x, got %v/%x", cs[0].ID, out, probe)
	}
	if _, ok := k.Get(nc.ID); ok {
		t.Fatal("newcomer admitted without a free slot")
	}

	// Incumbent alive: kept, moved to front; newcomer stays stashed.
	k.Confirm(cs[0].ID, true, t0.Add(time.Minute))
	if k.buckets[bi].entries[0].ID != cs[0].ID {
		t.Fatal("alive incumbent not moved to front")
	}
	if k.Len() != K {
		t.Fatalf("Len = %d after alive confirm", k.Len())
	}

	// Another newcomer; now the LRU is c1. Confirm it dead → evict + promote.
	nc2 := contactInBucket(self, bi, 101)
	out, probe = k.Observe(nc2, t0)
	if out != ObserveNeedProbe || probe != cs[1].ID {
		t.Fatalf("expected probe of c1, got %v/%x", out, probe)
	}
	k.Confirm(cs[1].ID, false, t0.Add(2*time.Minute))
	if _, ok := k.Get(cs[1].ID); ok {
		t.Fatal("dead incumbent not evicted")
	}
	if _, ok := k.Get(nc2.ID); !ok {
		t.Fatal("newcomer not promoted into freed slot")
	}
	if k.Len() != K {
		t.Fatalf("Len = %d, want %d after promote", k.Len(), K)
	}
}

func TestAntiEvictionFlooding(t *testing.T) {
	var self kad.ID
	k := NewKnowledge(self, nil, 0)
	bi := 10
	incumbents := make([]Contact, K)
	for i := range incumbents {
		incumbents[i] = contactInBucket(self, bi, i)
		k.Observe(incumbents[i], t0)
	}
	// Flood with new IDs without ever confirming a probe.
	for f := range 50 {
		out, _ := k.Observe(contactInBucket(self, bi, 1000+f), t0)
		if out != ObserveNeedProbe {
			t.Fatalf("flood %d not held back: %v", f, out)
		}
		if k.Len() != K {
			t.Fatalf("Len grew to %d under flood", k.Len())
		}
	}
	// Every old verified contact survives the flood.
	for i, c := range incumbents {
		if _, ok := k.Get(c.ID); !ok {
			t.Fatalf("incumbent %d displaced by flood", i)
		}
	}
}

func TestMarkDead(t *testing.T) {
	var self kad.ID
	k := NewKnowledge(self, nil, 0)
	bi := 10
	a := contactInBucket(self, bi, 1)
	k.Observe(a, t0)
	if _, ok := k.MarkDead(a.ID); ok {
		t.Fatal("MarkDead with empty replace cache reported a promotion")
	}
	if _, ok := k.Get(a.ID); ok {
		t.Fatal("dead contact not purged")
	}
	if k.Len() != 0 {
		t.Fatalf("Len = %d after purge", k.Len())
	}

	// Now with a replacement candidate waiting: fill, stash, kill one → promote.
	cs := make([]Contact, K)
	for i := range cs {
		cs[i] = contactInBucket(self, bi, i)
		k.Observe(cs[i], t0)
	}
	cand := contactInBucket(self, bi, 200)
	k.Observe(cand, t0) // full bucket → stashed in replace cache
	promoted, ok := k.MarkDead(cs[5].ID)
	if !ok || promoted.ID != cand.ID {
		t.Fatalf("MarkDead promote = %x, %v; want %x", promoted.ID, ok, cand.ID)
	}
	if _, ok := k.Get(cand.ID); !ok {
		t.Fatal("promoted candidate not admitted")
	}
}

func TestSubnetCap(t *testing.T) {
	var self kad.ID
	k := NewKnowledge(self, subnetByEndpoint, 0)
	hot := []transport.Addr{{Net: "quic", Endpoint: "hot-subnet"}}

	// SubnetCap entries from one subnet, each in a different bucket → table-wide cap.
	for i := range SubnetCap {
		c := contactInBucket(self, 1+i, i)
		c.Addrs = hot
		if out, _ := k.Observe(c, t0); out != ObserveInserted {
			t.Fatalf("admit %d from hot subnet: %v", i, out)
		}
	}
	// One more from the same subnet is rejected.
	over := contactInBucket(self, 1+SubnetCap, 0)
	over.Addrs = hot
	if out, _ := k.Observe(over, t0); out != ObserveRejected {
		t.Fatalf("over-cap contact not rejected: %v", out)
	}
	// A different subnet is still admitted.
	other := contactInBucket(self, 50, 0)
	other.Addrs = []transport.Addr{{Net: "quic", Endpoint: "cool-subnet"}}
	if out, _ := k.Observe(other, t0); out != ObserveInserted {
		t.Fatalf("different subnet rejected: %v", out)
	}
	// Removing a hot-subnet entry frees room for one more.
	first := contactInBucket(self, 1, 0)
	k.MarkDead(first.ID)
	again := contactInBucket(self, 60, 0)
	again.Addrs = hot
	if out, _ := k.Observe(again, t0); out != ObserveInserted {
		t.Fatalf("subnet slot not freed after purge: %v", out)
	}
}

// TestSubnetRecomputedOnAddrUpdate: the SubnetCap accounting must follow address
// updates, or the cap is bypassable — admit a contact with no recognizable subnet
// (or in a cool one), then point its addresses into a saturated subnet on refresh.
// An update into a full subnet is refused (the rest of the refresh still applies);
// an accepted move re-accounts both the old and the new subnet.
func TestSubnetRecomputedOnAddrUpdate(t *testing.T) {
	var self kad.ID
	k := NewKnowledge(self, subnetByEndpoint, 0)
	hot := []transport.Addr{{Net: "quic", Endpoint: "hot-subnet"}}
	cool := []transport.Addr{{Net: "quic", Endpoint: "cool-subnet"}}

	// Saturate the hot subnet (distinct buckets, so only the subnet cap is in play).
	for i := range SubnetCap {
		c := contactInBucket(self, 1+i, i)
		c.Addrs = hot
		if out, _ := k.Observe(c, t0); out != ObserveInserted {
			t.Fatalf("admit %d from hot subnet: %v", i, out)
		}
	}

	// A contact admitted with no subnet must not slip its addresses into the
	// saturated subnet via a later refresh.
	free := contactInBucket(self, 100, 0)
	if out, _ := k.Observe(free, t0); out != ObserveInserted {
		t.Fatalf("admit subnet-less contact: %v", out)
	}
	upd := free
	upd.Addrs = hot
	k.Observe(upd, t0.Add(time.Minute))
	if got, _ := k.Get(free.ID); len(got.Addrs) != 0 {
		t.Fatal("address update into a saturated subnet was accepted")
	}

	// Moving a hot contact to a cool subnet frees a hot slot and charges the cool one.
	moved := contactInBucket(self, 1, 0)
	moved.Addrs = cool
	if out, _ := k.Observe(moved, t0.Add(2*time.Minute)); out != ObserveInserted {
		t.Fatalf("refresh moving subnets: %v", out)
	}
	if got, _ := k.Get(moved.ID); len(got.Addrs) != 1 || got.Addrs[0].Endpoint != "cool-subnet" {
		t.Fatal("accepted address update did not stick")
	}
	fresh := contactInBucket(self, 110, 0)
	fresh.Addrs = hot
	if out, _ := k.Observe(fresh, t0.Add(3*time.Minute)); out != ObserveInserted {
		t.Fatalf("hot-subnet slot not freed by the move: %v", out)
	}

	// The moved contact counts in its new subnet: cool fills to the cap and then refuses.
	for i := range SubnetCap - 1 {
		c := contactInBucket(self, 130+i, i)
		c.Addrs = cool
		if out, _ := k.Observe(c, t0); out != ObserveInserted {
			t.Fatalf("admit %d from cool subnet: %v", i, out)
		}
	}
	overCool := contactInBucket(self, 150, 0)
	overCool.Addrs = cool
	if out, _ := k.Observe(overCool, t0); out != ObserveRejected {
		t.Fatalf("subnet move was not charged to the new subnet: %v", out)
	}
}

// TestPromoteGuardKeepsCandidate (white-box): promote's capacity guard must run
// before a candidate is taken off the replacement cache — a guard that fires after
// the pop would silently lose a good candidate instead of keeping it stashed.
func TestPromoteGuardKeepsCandidate(t *testing.T) {
	var self kad.ID
	k := NewKnowledge(self, nil, 0)
	bi := 10
	for i := range K {
		k.Observe(contactInBucket(self, bi, i), t0)
	}
	cand := contactInBucket(self, bi, 200)
	k.Observe(cand, t0) // full bucket → stashed in the replacement cache
	b := &k.buckets[bi]
	if _, ok := k.promote(b); ok {
		t.Fatal("promote admitted into a full bucket")
	}
	if len(b.replace) != 1 || b.replace[0].ID != cand.ID {
		t.Fatal("promote into a full bucket consumed the stashed candidate")
	}
}

func TestSubnetCapInertWithNoSubnet(t *testing.T) {
	var self kad.ID
	k := NewKnowledge(self, nil, 0) // NoSubnet
	addr := []transport.Addr{{Net: "mem", Endpoint: "node-1"}}
	for i := range SubnetCap + 5 {
		c := contactInBucket(self, 1+i, i)
		c.Addrs = addr
		if out, _ := k.Observe(c, t0); out != ObserveInserted {
			t.Fatalf("NoSubnet should not cap, but %d rejected: %v", i, out)
		}
	}
}

func TestClosest(t *testing.T) {
	self := kad.ID{0xff}
	k := NewKnowledge(self, nil, 0)
	rng := rand.New(rand.NewPCG(1, 2))
	var all []kad.ID
	for range 200 {
		id := randID(rng)
		if id == self {
			continue
		}
		// Only count contacts actually admitted: random IDs cluster in the low
		// buckets and overflow K, and an overflowed ID is legitimately not stored.
		if out, _ := k.Observe(Contact{ID: id}, t0); out == ObserveInserted {
			all = append(all, id)
		}
	}

	target := randID(rng)
	const n = 8
	got := k.Closest(target, n, make([]Contact, 0, n))
	if len(got) != n {
		t.Fatalf("Closest returned %d, want %d", len(got), n)
	}
	// Result must be sorted closest-first.
	for i := 1; i < len(got); i++ {
		if kad.DistanceCmp(target, got[i-1].ID, got[i].ID) > 0 {
			t.Fatalf("result not sorted by distance at %d", i)
		}
	}
	// Brute-force the true nearest distance threshold: the farthest in `got` must
	// be ≤ every node not in `got`.
	inGot := map[kad.ID]bool{}
	for _, c := range got {
		inGot[c.ID] = true
	}
	worst := got[len(got)-1].ID
	for _, id := range all {
		if inGot[id] {
			continue
		}
		if kad.DistanceCmp(target, id, worst) < 0 {
			t.Fatalf("a closer node %x was excluded from Closest", id)
		}
	}
}

func TestClosestFewerThanN(t *testing.T) {
	var self kad.ID
	k := NewKnowledge(self, nil, 0)
	k.Observe(contactInBucket(self, 5, 1), t0)
	k.Observe(contactInBucket(self, 9, 2), t0)
	got := k.Closest(kad.ID{}, 8, make([]Contact, 0, 8))
	if len(got) != 2 {
		t.Fatalf("Closest = %d, want 2", len(got))
	}
	if got := k.Closest(kad.ID{}, 0, nil); len(got) != 0 {
		t.Fatalf("Closest(n=0) = %d, want 0", len(got))
	}
}

func TestRefreshTarget(t *testing.T) {
	var self kad.ID
	k := NewKnowledge(self, nil, 0)
	rng := rand.New(rand.NewPCG(7, 7))

	// An empty table has nothing to keep fresh: every bucket is empty and skipped.
	// (Refreshing empty buckets would round-robin ~256 useless lookups and starve
	// the populated ones; knowledge of empty regions arrives via ordinary lookups.)
	if _, ok := k.RefreshTarget(t0, time.Minute, rng); ok {
		t.Fatal("RefreshTarget picked a bucket in an empty table")
	}

	// Populate buckets 3 and 9. Both are equally stale (zero refresh time), so the
	// lowest-index one comes first; the empty buckets around them are skipped.
	k.Observe(contactInBucket(self, 3, 1), t0)
	k.Observe(contactInBucket(self, 9, 1), t0)
	target, ok := k.RefreshTarget(t0, time.Minute, rng)
	if !ok {
		t.Fatal("RefreshTarget reported nothing stale")
	}
	if cpl := kad.CommonPrefixLen(self, target); cpl != 3 {
		t.Fatalf("target CPL = %d, want bucket 3", cpl)
	}
	// Bucket 3 is now fresh; the next due populated bucket is 9.
	target, ok = k.RefreshTarget(t0, time.Minute, rng)
	if !ok {
		t.Fatal("second RefreshTarget reported nothing stale")
	}
	if cpl := kad.CommonPrefixLen(self, target); cpl != 9 {
		t.Fatalf("second target CPL = %d, want bucket 9", cpl)
	}

	// Both populated buckets are fresh now; nothing is due within the window.
	if _, ok := k.RefreshTarget(t0.Add(time.Second), time.Minute, rng); ok {
		t.Fatal("RefreshTarget returned a fresh bucket as stale")
	}
	// Once the window elapses they come due again, most-stale first.
	if _, ok := k.RefreshTarget(t0.Add(2*time.Minute), time.Minute, rng); !ok {
		t.Fatal("RefreshTarget missed a bucket past its staleness window")
	}
}
