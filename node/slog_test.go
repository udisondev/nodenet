package node

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/udisondev/nodenet/transport/mem"
)

// syncBuf is a goroutine-safe buffer for capturing log output: the dispatch loop,
// the maintenance goroutine and the test all write through the default slog handler.
type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestSlogNarratesTopology: the node narrates its lifecycle and topology changes
// through the default slog logger, so an embedder gets the story by installing a
// handler — no plumbing. The inbound registration logs "edge established" and a
// dropped edge logs "edge dropped" with the reason that killed it.
func TestSlogNarratesTopology(t *testing.T) {
	var buf syncBuf
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(old)

	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hub := mem.NewHub(mem.WithInboundBuffer(64))

		a := spawn(t, ctx, hub, 1)
		b := spawn(t, ctx, hub, 2)
		link(t, ctx, a, b)
		if err := a.Send(b.ID(), []byte("hi")); err != nil {
			t.Fatalf("Send: %v", err)
		}
		synctest.Wait() // b registers the inbound edge on a's first frame

		b.dropEdge(a.ID(), "test reap")
		synctest.Wait()

		out := buf.String()
		for _, want := range []string{
			`msg="node running"`,
			`msg="edge established"`,
			"direction=inbound",
			`msg="edge dropped"`,
			`reason="test reap"`,
		} {
			if !strings.Contains(out, want) {
				t.Errorf("log output missing %q\n--- captured log ---\n%s", want, out)
			}
		}
	})
}
