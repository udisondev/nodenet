package node

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/udisondev/nodenet/routing"
	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/transport/mem"
)

// testMaint is a maintenance policy with short, fake-clock-friendly intervals so a
// synctest can advance through several rounds quickly and deterministically. The
// backoff ceiling stays well above the partitions these tests stage: exhausting the
// ladder purges the contact from knowledge (the lazy purge — exercised by its own
// tests in knowledge_upkeep_test.go), and here a transiently-partitioned peer must
// survive in knowledge to be re-dialed after the heal, as in production, where the
// purge horizon is minutes, not seconds.
func testMaint() Maintenance {
	return Maintenance{
		Tick:             1 * time.Second,
		KeepaliveSibling: 2 * time.Second,
		KeepaliveFinger:  3 * time.Second,
		DeadSibling:      6 * time.Second,
		DeadFinger:       9 * time.Second,
		SelfLookup:       3 * time.Second,
		SiblingExchange:  3 * time.Second,
		DialTimeout:      2 * time.Second,
		BackoffBase:      1 * time.Second,
		BackoffMax:       60 * time.Second,
		Dialers:          4,
	}
}

// contactOf is a dialable knowledge entry for tn — what a node is bootstrapped with.
func contactOf(tn *testNode) routing.Contact {
	return routing.Contact{ID: tn.ID(), Addrs: []transport.Addr{tn.addr}}
}

// TestChurnFillFromBootstrap: a maintained node, given a set of bootstrap contacts,
// dials them all on its own and keepalive keeps them — its self-maintained degree
// climbs from zero and settles at the number of reachable peers.
func TestChurnFillFromBootstrap(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))

		a := spawn(t, ctx, hub, 1, WithMaintenance(testMaint()))
		const peers = 6
		boot := make([]routing.Contact, 0, peers)
		for s := uint64(2); s <= peers+1; s++ {
			boot = append(boot, contactOf(spawn(t, ctx, hub, s))) // dispatch-only, will pong
		}
		a.Bootstrap(boot)

		time.Sleep(20 * time.Second)
		synctest.Wait()

		if got := a.Edges().Status().OutEdges; got != peers {
			t.Fatalf("OutEdges = %d, want %d (every bootstrap peer dialed and kept alive)", got, peers)
		}
	})
}

// TestChurnReapAndReplace: a maintained node dials a bootstrap peer, the peer is
// then partitioned away (its keepalives go unanswered and re-dial fails), so the
// node reaps the dead edge; when a fresh reachable node appears in knowledge the
// node dials it as a replacement. Exercises keepalive dead-detection + re-fill.
func TestChurnReapAndReplace(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))

		a := spawn(t, ctx, hub, 1, WithMaintenance(testMaint()))
		b := spawn(t, ctx, hub, 2)
		a.Bootstrap([]routing.Contact{contactOf(b)})

		time.Sleep(4 * time.Second)
		synctest.Wait()
		if _, ok := a.Edges().Conn(b.ID()); !ok {
			t.Fatal("A did not dial bootstrap peer B")
		}

		hub.Partition(a.ID(), b.ID()) // B goes dark
		time.Sleep(10 * time.Second)  // > DeadSibling
		synctest.Wait()
		if _, ok := a.Edges().Conn(b.ID()); ok {
			t.Fatal("A kept the edge to partitioned B; keepalive should have reaped it")
		}

		s := spawn(t, ctx, hub, 3)
		a.Bootstrap([]routing.Contact{contactOf(s)})
		time.Sleep(4 * time.Second)
		synctest.Wait()
		if _, ok := a.Edges().Conn(s.ID()); !ok {
			t.Fatal("A did not dial replacement node S")
		}
	})
}

// TestChurnPartitionHeals: two maintained nodes establish mutual edges, a partition
// makes them reap each other, and once healed the maintenance loop re-dials and the
// link comes back — topology re-converges without manual intervention.
func TestChurnPartitionHeals(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))

		a := spawn(t, ctx, hub, 1, WithMaintenance(testMaint()))
		b := spawn(t, ctx, hub, 2, WithMaintenance(testMaint()))
		a.Bootstrap([]routing.Contact{contactOf(b)})
		b.Bootstrap([]routing.Contact{contactOf(a)})

		time.Sleep(4 * time.Second)
		synctest.Wait()
		if _, ok := a.Edges().Conn(b.ID()); !ok {
			t.Fatal("A and B did not establish an edge")
		}

		hub.Partition(a.ID(), b.ID())
		time.Sleep(10 * time.Second)
		synctest.Wait()
		if _, ok := a.Edges().Conn(b.ID()); ok {
			t.Fatal("A kept the edge across the partition")
		}

		hub.Heal(a.ID(), b.ID())
		time.Sleep(10 * time.Second)
		synctest.Wait()
		if _, ok := a.Edges().Conn(b.ID()); !ok {
			t.Fatal("A did not re-establish the edge after the partition healed")
		}
	})
}

// TestChurnGracefulLeave: a node announces it is leaving over its edges, and the
// neighbour drops the edge at once rather than waiting for the dead timeout.
func TestChurnGracefulLeave(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))

		a := spawn(t, ctx, hub, 1)                               // dispatch-only: never re-dials
		b := spawn(t, ctx, hub, 2, WithMaintenance(testMaint())) // maintained: leaves on stop
		dialEdge(t, ctx, a, b)                                   // a -> b: A's edge to B
		dialEdge(t, ctx, b, a)                                   // b -> a: the edge B leaves over

		if _, ok := a.Edges().Conn(b.ID()); !ok {
			t.Fatal("A is missing its edge to B")
		}

		b.stop() // B leaves gracefully
		synctest.Wait()

		if _, ok := a.Edges().Conn(b.ID()); ok {
			t.Fatal("A kept the edge after B's graceful leave")
		}
	})
}
