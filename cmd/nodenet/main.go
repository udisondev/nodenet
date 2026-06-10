// Command nodenet runs a single overlay node over the QUIC transport: it loads (or
// mints) a persistent identity, binds a socket, seeds the knowledge table from the
// given bootstrap peers, and runs the dispatch and maintenance loops until
// interrupted. It is a thin wiring of the library — identity + transport/quic + node
// — driven by flags with sensible defaults, meant as a runnable entry point and a
// worked example of how the pieces compose.
//
// At least one of -bootstrap (peers to dial into an existing overlay) or -addr (a
// socket to listen on so others can dial in) must be set; usually both. A pure
// -bootstrap node still binds an ephemeral socket so it can dial out and forward.
//
// Bootstrap peers are authenticated by NodeID: the overlay's Dial verifies a peer's
// certificate against the NodeID we expect, so a bare address is not enough — each
// bootstrap entry carries the peer's NodeID. The flag format is therefore
// "<nodeid-hex>@host:port", entries comma-separated.
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/node"
	"github.com/udisondev/nodenet/pow"
	"github.com/udisondev/nodenet/routing"
	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/transport/quic"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("nodenet: ")

	var (
		bootstrap     = flag.String("bootstrap", "", "comma-separated entry peers as <nodeid-hex>@host:port (dial into an existing overlay)")
		addr          = flag.String("addr", "", "UDP address to listen on, e.g. :4242 or 0.0.0.0:4242 (empty = ephemeral, dial-only)")
		seedPath      = flag.String("seed", "", "path to the persisted master-seed (the node's identity); created if absent (default: nodenet.seed under the user config dir)")
		powDifficulty = flag.Int("pow", 0, "network-wide proof-of-work difficulty: leading-zero bits required of a NodeID (must match the network)")
		relay         = flag.Bool("relay", false, "volunteer as a relay for peers that cannot hole-punch")
		maxInbound    = flag.Int("max-inbound", 256, "global cap on concurrent inbound connections (DoS backstop)")
		maxInboundIP  = flag.Int("max-inbound-per-ip", 32, "cap on concurrent inbound connections from one source IP")
	)
	flag.Parse()

	// Require a reason to exist on the overlay: either a way in (bootstrap peers to
	// dial) or a door for others (a listen address). Without either the node would bind
	// an ephemeral socket and sit idle with nothing to connect to.
	if *bootstrap == "" && *addr == "" {
		log.Fatal("need at least one of -bootstrap (peers to dial) or -addr (address to listen on); usually both")
	}

	contacts, err := parseBootstrap(*bootstrap)
	if err != nil {
		log.Fatalf("invalid -bootstrap: %v", err)
	}

	// Ctrl-C / SIGTERM cancels the run context, which unwinds the loops and lets the
	// transport Close cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Identity. Restore from the seed file across restarts so the NodeID is stable; mint
	// and persist a fresh one (clearing the network PoW) on first run.
	seedFile := *seedPath
	if seedFile == "" {
		var err error
		if seedFile, err = defaultSeedPath(); err != nil {
			log.Fatalf("default seed path: %v", err)
		}
	}
	id, err := loadOrCreateIdentity(ctx, seedFile, *powDifficulty)
	if err != nil {
		log.Fatalf("identity: %v", err)
	}
	if !pow.Satisfies(id.ID(), *powDifficulty) {
		log.Fatalf("seed %s yields NodeID %s, which does not clear -pow=%d; delete it to mint a new identity",
			seedFile, id.ID(), *powDifficulty)
	}

	// Transport. An ephemeral socket (":0") when only dialing out; the given address when
	// accepting inbound edges. Inbound caps stay on as a level-2 DoS backstop.
	listen := *addr
	if listen == "" {
		listen = ":0"
	}
	tr, err := quic.Listen(id, listen,
		quic.WithMaxInbound(*maxInbound),
		quic.WithMaxInboundPerIP(*maxInboundIP),
	)
	if err != nil {
		log.Fatalf("listen on %q: %v", listen, err)
	}
	defer tr.Close()

	// Node. Wire identity + transport + routing into the runtime. Enforce the same PoW on
	// every originated packet we forward; volunteer as relay if asked.
	opts := []node.Option{node.WithDmin(*powDifficulty)}
	if *relay {
		opts = append(opts, node.WithRelay())
	}
	n := node.New(id, tr, opts...)
	n.Bootstrap(contacts)

	log.Printf("node %s", n.ID())
	log.Printf("listening on %s (quic)", tr.LocalAddr().Endpoint)
	if len(contacts) > 0 {
		log.Printf("bootstrapping from %d peer(s)", len(contacts))
	}
	if *relay {
		log.Print("relay volunteer: on")
	}

	// Drain deliveries and log what arrives. The dispatch loop hands messages off
	// non-blocking and drops them when the buffer is full, so a sluggish consumer can
	// never wedge the node — prompt draining is about not LOSING messages.
	go func() {
		for msg := range n.Deliveries() {
			log.Printf("message from %s: %q", msg.Originator, msg.Payload)
		}
	}()

	if err := n.Run(ctx); err != nil && ctx.Err() == nil {
		log.Fatalf("run: %v", err)
	}
	log.Print("shutting down")
}

// parseBootstrap turns the comma-separated "<nodeid-hex>@host:port" flag into knowledge
// contacts. Each peer is tagged PublicAnchor — a stable, directly-dialable entry point
// the connectivity floor can lean on as a re-dial anchor. An empty flag yields no
// contacts (the node relies on inbound edges instead).
func parseBootstrap(s string) ([]routing.Contact, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	contacts := make([]routing.Contact, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		at := strings.LastIndexByte(p, '@')
		if at <= 0 || at == len(p)-1 {
			return nil, fmt.Errorf("entry %q is not <nodeid-hex>@host:port", p)
		}
		id, err := kad.ParseID(p[:at])
		if err != nil {
			return nil, fmt.Errorf("entry %q: bad NodeID: %w", p, err)
		}
		// Validate the endpoint shape here: a typo'd address would otherwise pass
		// silently and leave the node sitting forever with nothing to dial (the
		// maintenance loop retries quietly — there is no later error to see).
		if _, _, err := net.SplitHostPort(p[at+1:]); err != nil {
			return nil, fmt.Errorf("entry %q: bad endpoint: %w", p, err)
		}
		contacts = append(contacts, routing.Contact{
			ID:    id,
			Caps:  routing.PublicAnchor,
			Addrs: []transport.Addr{{Net: "quic", Endpoint: p[at+1:]}},
		})
	}
	return contacts, nil
}

// defaultSeedPath is where the master-seed lives when -seed is not given: a 0700
// directory under the user's config dir. The seed is the node's only secret, so the
// default must NOT be a relative path — that would drop it wherever the binary happens
// to run (e.g. into a source tree, one careless `git add .` away from being published).
func defaultSeedPath() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "nodenet")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "nodenet.seed"), nil
}

// loadOrCreateIdentity restores the identity from the seed file, or mints a fresh one
// (clearing difficulty d) and persists its seed 0600 on first run. The seed is the only
// secret of record; everything else is re-derived from it.
func loadOrCreateIdentity(ctx context.Context, path string, d int) (*identity.Identity, error) {
	seed, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(seed) != identity.SeedLen {
			return nil, fmt.Errorf("seed file %s is %d bytes, want %d", path, len(seed), identity.SeedLen)
		}
		var s [identity.SeedLen]byte
		copy(s[:], seed)
		return identity.FromSeed(s), nil
	case !errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("read seed %s: %w", path, err)
	}

	// First run: mint an identity whose NodeID clears the network PoW (grinding seeds
	// when d > 0), then persist the seed so the NodeID survives restarts.
	if d > 0 {
		log.Printf("minting identity clearing pow=%d (this may take a while)...", d)
	}
	id, err := pow.Solve(ctx, rand.Reader, d)
	if err != nil {
		return nil, fmt.Errorf("mint identity: %w", err)
	}
	s := id.Seed()
	if err := os.WriteFile(path, s[:], 0o600); err != nil {
		return nil, fmt.Errorf("write seed %s: %w", path, err)
	}
	log.Printf("minted new identity, seed saved to %s", path)
	return id, nil
}
