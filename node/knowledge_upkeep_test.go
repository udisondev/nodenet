package node

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/routing"
	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/transport/mem"
)

// ghostContact is a dialable knowledge entry for a peer that does not exist on the
// hub: every dial to it fails fast (ErrNoRoute) — the test stand-in for a contact
// that died and left the network. Keyless contacts bind to any ID, so it enters the
// table freely (dmin is 0 in tests).
func ghostContact(id kad.ID, endpoint string) routing.Contact {
	return routing.Contact{ID: id, Addrs: []transport.Addr{{Net: "mem", Endpoint: endpoint}}}
}

// idNear flips the top bit of self and stamps a variant into the trailing byte:
// every such ID shares a common-prefix length of exactly 0 with self, so they all
// land in the same k-bucket — the way a test fills one bucket to capacity.
func idNear(self kad.ID, variant byte) kad.ID {
	id := self
	id[0] ^= 0x80
	id[31] = variant
	return id
}

// TestKnowledgePurgesUnreachableContact: a contact that keeps failing the dial past
// the full backoff ladder is purged from the knowledge table (the soft-state lazy
// purge), so a permanently-dead peer stops being a fill candidate and stops being
// handed out in lookup answers. Without the purge the maintenance loop re-dials the
// corpse forever.
func TestKnowledgePurgesUnreachableContact(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))

		// A short ladder (1s -> 2s ceiling) so the purge horizon sits inside the test
		// window; lookups/exchanges are pushed out of the way.
		a := spawn(t, ctx, hub, 1, WithMaintenance(Maintenance{
			Tick:            time.Second,
			SelfLookup:      time.Hour,
			SiblingExchange: time.Hour,
			BucketRefresh:   time.Hour,
			DialTimeout:     time.Second,
			BackoffBase:     time.Second,
			BackoffMax:      2 * time.Second,
		}))

		ghost := ghostContact(idNear(a.ID(), 1), "ghost")
		a.Bootstrap([]routing.Contact{ghost})
		if _, ok := a.Knowledge().Get(ghost.ID); !ok {
			t.Fatal("ghost contact did not enter the knowledge table")
		}

		time.Sleep(20 * time.Second)
		synctest.Wait()

		if _, ok := a.Knowledge().Get(ghost.ID); ok {
			t.Fatal("unreachable contact survived the backoff ladder; want it purged from knowledge")
		}
	})
}

// TestKnowledgeProbeEvictsDeadIncumbent: a newcomer observed into a FULL bucket is
// stashed while the least-recently-seen incumbent is probed (dialed); the dead
// incumbent is evicted and the newcomer promoted into its slot. Without the probe
// wiring a fully-dead bucket can never admit a live newcomer — the table ossifies
// under churn.
func TestKnowledgeProbeEvictsDeadIncumbent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))

		// A huge backoff base keeps the lazy purge out of the picture: each corpse
		// fails one fill dial and then waits an hour, so only the probe path can
		// evict. The probe itself must still dial fast.
		a := spawn(t, ctx, hub, 1, WithMaintenance(Maintenance{
			Tick:            time.Second,
			SelfLookup:      time.Hour,
			SiblingExchange: time.Hour,
			BucketRefresh:   time.Hour,
			DialTimeout:     time.Second,
			BackoffBase:     time.Hour,
			BackoffMax:      time.Hour,
		}))

		// Fill one bucket to capacity with dead-but-dialable corpses...
		corpses := make([]routing.Contact, routing.K)
		for i := range corpses {
			corpses[i] = ghostContact(idNear(a.ID(), byte(i)), "ghost-"+string(rune('a'+i)))
		}
		a.Bootstrap(corpses)
		// ...then observe a newcomer into the now-full bucket.
		newcomer := ghostContact(idNear(a.ID(), 200), "newcomer")
		a.Bootstrap([]routing.Contact{newcomer})

		time.Sleep(30 * time.Second)
		synctest.Wait()

		if _, ok := a.Knowledge().Get(newcomer.ID); !ok {
			t.Fatal("newcomer never promoted into the full bucket; want the dead incumbent probed and evicted")
		}
		if _, ok := a.Knowledge().Get(corpses[0].ID); ok {
			t.Fatal("least-recently-seen incumbent survived a failed probe; want it evicted")
		}
	})
}

// TestBucketRefreshLearnsFromNeighbor: a stale bucket triggers a lookup toward a
// random ID in its range; the neighbour closest to that ID answers with its contacts
// and the originator's knowledge is refreshed — it learns a peer it was never told
// about. Self-lookup and sibling exchange are disabled, so the bucket refresh is the
// only path that can teach it.
func TestBucketRefreshLearnsFromNeighbor(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))

		a := spawn(t, ctx, hub, 1, WithMaintenance(Maintenance{
			Tick:             time.Second,
			SelfLookup:       time.Hour,
			SiblingExchange:  time.Hour,
			BucketRefresh:    2 * time.Second,
			BucketStaleAfter: 5 * time.Second,
			DialTimeout:      time.Second,
			BackoffBase:      time.Hour,
			BackoffMax:       time.Hour,
		}))
		b := spawn(t, ctx, hub, 2) // dispatch-only: answers lookups, never dials

		// B knows about C; A only knows about B.
		c := ghostContact(idNear(b.ID(), 7), "c-ghost")
		b.Bootstrap([]routing.Contact{c})
		a.Bootstrap([]routing.Contact{contactOf(b)})

		time.Sleep(15 * time.Second)
		synctest.Wait()

		if _, ok := a.Edges().Conn(b.ID()); !ok {
			t.Fatal("A did not dial B (precondition)")
		}
		if _, ok := a.Knowledge().Get(c.ID); !ok {
			t.Fatal("A never learned C; want the bucket refresh to look up B's range and fold the answer")
		}
	})
}
