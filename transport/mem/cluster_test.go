package mem

import (
	"context"
	"fmt"
	"testing"
	"testing/synctest"

	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/transport"
)

// cluster is the minimal N-node bring-up helper: a Hub with n transports on it,
// addressed "n0".."n{n-1}" and given deterministic NodeIDs. The full node-level
// cluster harness lives in package node; this one exercises transport-level
// behaviour across several nodes.
type cluster struct {
	t     *testing.T
	hub   *Hub
	nodes []transport.Transport
	ids   []kad.ID
}

func newCluster(t *testing.T, n int) *cluster {
	t.Helper()
	c := &cluster{t: t, hub: NewHub()}
	for i := range n {
		id := nodeID(byte(i + 1))
		tr, err := c.hub.New(id, addr(fmt.Sprintf("n%d", i)))
		if err != nil {
			t.Fatalf("cluster node %d: %v", i, err)
		}
		c.nodes = append(c.nodes, tr)
		c.ids = append(c.ids, id)
	}
	return c
}

// dial opens an edge from node i to node j.
func (c *cluster) dial(i, j int) transport.Conn {
	c.t.Helper()
	conn, err := c.nodes[i].Dial(context.Background(), c.ids[j], addr(fmt.Sprintf("n%d", j)))
	if err != nil {
		c.t.Fatalf("dial %d->%d: %v", i, j, err)
	}
	return conn
}

func (c *cluster) close() {
	for _, n := range c.nodes {
		n.Close()
	}
}

// A frame relayed hand-to-hand around a ring reaches the last node, with each hop
// receiving on the edge the previous hop dialed — the multi-node shape the
// recursive forwarder is built on.
func TestClusterRingRelay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const n = 5
		c := newCluster(t, n)
		defer c.close()

		// Wire a directed ring 0->1->...->4 and remember each node's outbound edge.
		out := make([]transport.Conn, n)
		for i := range n - 1 {
			out[i] = c.dial(i, i+1)
		}

		// Node 0 originates; each node relays the payload to the next.
		sendFrame(t, out[0], []byte("relay"))
		for i := 1; i < n-1; i++ {
			got, via := recvPayload(t, c.nodes[i])
			if string(got) != "relay" {
				t.Fatalf("node %d got %q, want relay", i, got)
			}
			if via.Remote() != c.ids[i-1] {
				t.Errorf("node %d received from %v, want node %d", i, via.Remote(), i-1)
			}
			sendFrame(t, out[i], got)
		}

		// The last node receives the relayed payload.
		got, via := recvPayload(t, c.nodes[n-1])
		if string(got) != "relay" {
			t.Errorf("final node got %q, want relay", got)
		}
		if via.Remote() != c.ids[n-2] {
			t.Errorf("final node received from %v, want node %d", via.Remote(), n-2)
		}
	})
}
