# nodenet

**A reusable core for decentralized P2P connectivity.** nodenet is a Go library that finds a
route to any node by its identifier and helps two peers establish a direct, end-to-end
connection - even when both sit behind NAT. It is the *transport substrate*, not the
application: nodenet gets your bytes to the right peer and opens the pipe; what flows through
that pipe is entirely up to you.

Think of it the way a blockchain is to a dApp. A blockchain provides consensus and state;
the dApps decide what to do with it. nodenet provides **decentralized addressing, routing
and NAT traversal**; the apps on top - a messenger, a file-sync tool, a CRDT backend, a
signaling plane for media - decide what to do with the connections it gives them.

> Status: pre-release, under active development. The public API
> (`github.com/udisondev/nodenet/node`) is stabilizing but may still change.

---

## The core idea

Most P2P overlays lean on **public nodes** to carry routing and relaying; nodes behind NAT
are second-class - they can reach the network but the network can't route *through* them.
nodenet's defining decision is the opposite:

**Routing and forwarding are spread across _all_ nodes, not just the public ones.**

A NAT node dials *outbound* and keeps that channel **bidirectional**. The overlay forwards
over that same live edge, so a phone behind a carrier-grade NAT becomes a full router that
carries other peers' traffic - not a leaf that only consumes. Connectivity, not the routing
algorithm, is what's hard in a permissionless overlay, and that's where nodenet puts its
design effort.

### What you get

- **Address by identity, not by location.** A node is its `NodeID` (a 256-bit BLAKE2b hash
  of its public key). You route to an ID; the overlay converges to it hop by hop. No DNS, no
  trackers, no central registry.
- **NAT traversal built in.** Reflexive-address learning -> DCUtR-style hole-punching ->
  packet relay as a last resort, tried cheapest-first. Most peers end up with a direct,
  end-to-end path.
- **End-to-end encryption to a public key you can verify.** Rendezvous returns the target's
  keys authenticated against its NodeID - a forwarder on the path cannot impersonate the
  destination (anti-MITM). Bulk traffic runs directly between endpoints; the multi-hop
  overlay only carries small control and rendezvous frames.
- **Permissionless, with teeth.** No gatekeeper decides who joins. Sybil and Eclipse
  resistance comes from layered, locally-verifiable invariants: proof-of-work on every
  identity, signed routing messages, per-originator rate limits on work-generating
  queries (keyed to the *signed* originator, so a flood can't dodge them by spreading
  across edges), replay protection on handshakes, subnet diversity caps, k-bucket
  eviction rules, and per-IP / global connection limits.
- **Zero-copy hot path.** A transit frame travels onward in the very buffer it arrived in -
  only the TTL byte is patched in place. The routing core targets `0 allocs/op`.

### What it is *not*

- Not a blockchain, ledger, or consensus system - there is no global agreed state.
- Not a storage / DHT-value layer - the DHT is used for *routing to nodes*, not storing
  arbitrary values.
- Not an application protocol - it carries your bytes; it does not define your messages.
- Not a bulk-data overlay - large transfers go directly peer-to-peer over the connection
  nodenet opens for you, never multi-hop through the overlay.

---

## How it compares

There are many ways to move bytes between peers. nodenet occupies a specific niche:
**a structured, identity-addressed overlay where every node - including NAT nodes - routes,
exposed as an embeddable Go library.**

| | **nodenet** | **libp2p** | **Tor / I2P** | **WebRTC** | **Tailscale / WireGuard** | **Hyperswarm (DAT)** |
|---|---|---|---|---|---|---|
| Shape | Embeddable Go library | Modular P2P stack | Anonymity network | Browser RTC + signaling | Mesh VPN | DHT + connector |
| Addressing | NodeID (hash of key) | PeerID (hash of key) | Onion / dest address | Out-of-band (SDP) | IP within tenant | Topic / key |
| Decentralized routing | **Yes, all nodes** | DHT, public relays favored | Volunteer relays | **No** (needs signaling server) | **No** (coordination plane) | DHT lookup only |
| NAT nodes route for others | **Yes (by design)** | Limited (relays/public) | No (clients are leaves) | No | No | No |
| NAT traversal | Reflexive + hole-punch + relay | Hole-punch (DCUtR) + relay | N/A (uses relays) | ICE/STUN/TURN | DERP relays + direct | UDP hole-punch |
| Anonymity | No (not a goal) | No | **Yes** | No | No | No |
| Trust model | Permissionless + PoW/Sybil defenses | Permissionless (app-defined) | Permissionless | App-defined | **Central control plane** | Permissionless |
| E2E crypto | Built in (TLS + sealed-box) | Built in (Noise/TLS) | Built in | DTLS/SRTP | WireGuard | Noise |
| Best for | Decentralized apps needing every node to route | General P2P apps | Censorship resistance | Real-time media in browsers | Private device meshes | P2P file/data apps |

**When to reach for nodenet:** you're building a decentralized app - a messenger, a
collaborative editor, a sync engine - that needs to *find a peer by identity and open a
direct encrypted channel*, with **no central server** for signaling or relay, and you want
NAT nodes to pull their weight as routers. If you need a browser runtime, anonymity, or a
managed control plane, the alternatives above fit better.

---

## Example: a minimal P2P messenger

nodenet handles discovery, routing and NAT traversal; the messenger handles messages. The
flow is: **find the peer by NodeID -> open a direct edge -> send your own bytes over it.**

```go
package main

import (
	"context"
	"crypto/rand"
	"log"

	"github.com/udisondev/nodenet/node"
	"github.com/udisondev/nodenet/pow"
	"github.com/udisondev/nodenet/routing"
	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/transport/quic"
)

const powDifficulty = 16 // network-wide constant: leading-zero bits required of a NodeID

func main() {
	ctx := context.Background()

	// 1. Identity. Mint one that clears the network's proof-of-work, then persist
	//    id.Seed() (the only secret) so the node keeps the same NodeID across restarts.
	id, err := pow.Solve(ctx, rand.Reader, powDifficulty)
	if err != nil {
		log.Fatal(err)
	}
	// On restart instead: id := identity.FromSeed(savedSeed)

	// 2. Transport. A QUIC socket with mutual-TLS authentication to NodeID, plus
	//    inbound caps as a DoS backstop on a public entry point.
	tr, err := quic.Listen(id, ":4242",
		quic.WithMaxInbound(256),
		quic.WithMaxInboundPerIP(32),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer tr.Close()

	// 3. Node. The runtime: identity + routing tables + transport + dispatch loop.
	n := node.New(id, tr,
		node.WithDmin(powDifficulty), // enforce origination-PoW on every received packet
		node.WithRelay(),             // volunteer to relay for peers that can't hole-punch
	)

	// 4. Bootstrap off at least one known contact and start the loops. Tag the
	//    entry point PublicAnchor: it is a stable, directly-dialable peer the
	//    connectivity floor leans on as a re-dial anchor.
	n.Bootstrap([]routing.Contact{{
		ID:    bootstrapID,
		Caps:  routing.PublicAnchor,
		Addrs: []transport.Addr{{Net: "quic", Endpoint: "bootstrap.example:4242"}},
	}})
	go func() {
		if err := n.Run(ctx); err != nil {
			log.Printf("node stopped: %v", err)
		}
	}()

	// 5a. Receive: messages addressed to this node's ID surface on Deliveries().
	go func() {
		for msg := range n.Deliveries() {
			log.Printf("from %s: %s", msg.Originator, msg.Payload)
		}
	}()

	// 5b. Send a small message routed to a peer by NodeID (multi-hop, no direct link).
	//     Origination never blocks, so Send takes no context.
	if err := n.Send(peerID, []byte("hi")); err != nil {
		log.Printf("send: %v", err)
	}

	// 5c. Or open a DIRECT end-to-end edge for a real conversation / bulk data.
	//     Connect discovers + verifies the peer's coordinates (rendezvous), then
	//     dials directly or hole-punches through NAT.
	conn, err := n.Connect(ctx, peerID)
	if err != nil {
		log.Printf("connect: %v", err)
		return
	}
	defer conn.Close()
	// conn is an authenticated, bidirectional channel: your messenger speaks its own
	// protocol over it from here.
}

var bootstrapID, peerID node.ID
```

Three ways to talk to a peer, by intent:

- **`Send(target, payload)`** - fire a small message routed multi-hop to a NodeID. No
  prior connection needed; the overlay converges to the target. Good for control, presence,
  offline-ish nudges. It never blocks on the network, hence no context.
- **`SendDirect(ctx, target, payload)`** - send an application payload over a direct edge,
  dialing or hole-punching one via `Connect` if none is up. The bytes never transit other
  nodes; on the remote side the payload surfaces on `Deliveries()`, same as `Send`.
- **`Connect(ctx, target)`** - establish a direct, authenticated edge (rendezvous ->
  hole-punch/relay) and speak your own protocol over it. Good for a live conversation or
  bulk transfer that should not traverse the overlay.

For connectionless end-to-end content you can also use the **sealed-box** path
(`Rendezvous` + the `rendezvous` package): sender-authenticated encryption to the
recipient's static X25519 key (ephemeral-static ECDH + AEAD + a sender signature),
carried over the overlay, where forwarders see only ciphertext.

---

## Try it: the bundled node binary

The repository ships a runnable node, `cmd/nodenet` - a thin wiring of the library
(identity + `transport/quic` + `node`) and a worked example of how the pieces compose.
On first run it mints an identity that clears the network's proof-of-work and persists
the seed (the only secret) to a file - by default under the user config directory, or
wherever `-seed` points - so the NodeID stays stable across restarts.

Start a first node; it prints its NodeID on startup:

```sh
go run ./cmd/nodenet -addr :4242 -pow 16
# logs "nodenet: node 0000ab12..." - others bootstrap from this ID
```

Join it from a second terminal or machine (a separate seed file = a separate identity):

```sh
go run ./cmd/nodenet -seed peer.seed -addr :4243 -pow 16 \
    -bootstrap <nodeid-hex>@host:4242
```

Bootstrap entries are `<nodeid-hex>@host:port`, comma-separated - the NodeID is required
because peers are *authenticated*, not merely dialed: the QUIC handshake verifies the
peer's certificate against the NodeID you expect, so a bare address is not enough. At
least one of `-bootstrap` (a way into an existing overlay) or `-addr` (a door for others
to dial in) must be set; usually both. Other flags: `-relay` volunteers the node as a
relay for peers that cannot hole-punch; `-max-inbound` / `-max-inbound-per-ip` are the
inbound DoS backstops.

---

## Architecture

nodenet is a set of strictly single-purpose packages forming an acyclic dependency DAG. Each
has a detailed package-doc in its `<pkg>.go` - **read that first**; it explains the package's
role and reasoning. Bottom-up:

| Package | Role |
|---|---|
| **`kad`** | Kademlia keyspace: the `ID` type (256-bit NodeID) and XOR-metric math. Pure, imports only stdlib - the root leaf. |
| **`identity`** | Pure crypto. One master-seed -> HKDF -> independent Ed25519 (signing identity) + static X25519 (e2e key exchange). Only the seed is persisted. |
| **`wire`** | Byte codec for frames (`version \| type \| len \| payload`). The "anti-`bytes.Buffer`": owns no memory, never grows, zero-copy on read, never panics on malformed input. |
| **`pow`** | Proof-of-work gate on the NodeID. Minting an identity is expensive (grind ~2^d seeds); verifying is one glance at the high bits. Prices mass Sybil identity creation. |
| **`transport`** | The one polymorphic boundary. Authenticates peers to their NodeID; opens/accepts **bidirectional** edges; surfaces all inbound frames on a single channel. `Packet` is a pooled, borrow-on-send buffer (zero-copy forwarding). |
| **`transport/mem`** | In-memory transport for deterministic tests (shared `Hub`, with partition/heal primitives). |
| **`transport/quic`** | Production transport: QUIC + mutual-TLS over one shared UDP socket (4-tuple reuse for hole-punching), with inbound DoS caps. |
| **`routing`** | The two overlay tables (soft-state k-bucket **knowledge** vs actively-maintained **live edges**) and the *pure* logic beside them: routing-message codec, greedy `Decide`, control protocol (ping/pong/lookup/neighbors/siblings/leave). No I/O. |
| **`rendezvous`** | Addressing & discovery: signed routed handshake (verify keys against NodeID, anti-MITM) and sealed-box e2e encryption. Sits *beside* routing, not on top. |
| **`nat`** | NAT-traversal logic and codecs: reflexive learning, hole-punching, packet relay. Pure logic; the socket I/O lives in `transport/quic`. |
| **`node`** | Top of the DAG and the public API. Composes everything: the single dispatch loop (recursive greedy forwarding), origination, the control protocol, the churn-maintenance loop, and the NAT orchestration. |

### Cross-cutting models worth knowing

- **`Packet` ownership (zero-alloc).** A `Packet` is a pooled buffer with one lifecycle:
  `transport.Get()` -> fill -> `Send` (which *borrows*: copies synchronously, never takes
  ownership) or hand up -> `Release()` exactly once. Borrowing is what makes zero-copy
  forwarding, free local-repair retries, and one-buffer disjoint-path fan-out possible.
  Build with `-tags transportdebug` to make double-Release / use-after-Release panic instead
  of silently corrupting the pool.
- **Two tables, two recovery models.** *Knowledge* (k-buckets) heals lazily - last-seen
  tracking, periodic refresh of stale buckets, eviction probes that let live newcomers
  displace dead incumbents, opportunistic learning. *Live edges* are maintained actively -
  a dropped sibling is replaced at once, re-running admission-PoW so churn never opens a
  backdoor around the Sybil defenses. A hard connectivity floor (`KMin = 3`) keeps every
  node above zero connectivity.
- **Three tiers of rules (the security foundation).** In a permissionless network you cannot
  assume a peer runs your code. (1) *Protocol consensus* - disagree and you're simply not on
  the same network. (2) *Verifiable invariants* - PoW, signatures, TTL clamps, format
  validity, rate limits - checked locally on **every** interaction, trusting no peer.
  (3) *Local policy* - topology numbers, honor-system. **Security never rests on tier 3.**
  Code comments tag which tier an invariant belongs to.

---

## Requirements

- **Go 1.26+** (uses stdlib `crypto/hkdf`, `crypto/ecdh` X25519, `testing/synctest`).
- Two direct external dependencies: `golang.org/x/crypto` (BLAKE2b, ChaCha20-Poly1305) and,
  for the production transport, `github.com/quic-go/quic-go`.
- No Makefile, no CI scaffolding - everything runs through the `go` toolchain.

## Building and testing

```sh
go build ./...                               # build
go vet ./...                                 # static analysis
go test ./...                                # all tests
go test ./kad -run TestCommonPrefixLen -v    # one test in a package
go test ./... -run '^$' -bench . -benchmem   # all benchmarks, with allocation counts
go test ./kad -fuzz FuzzParseID              # fuzz one target (one per package at a time)
go test -tags transportdebug ./transport/... # enable Packet lifecycle assertions
```

### Development discipline

- **TDD + benchmarks from the start.** Every unit: red -> green -> refactor. Every hot path
  gets a `Benchmark*` immediately; the goal is `0 allocs/op`, regressions caught with
  `-benchmem`.
- **Fuzz every decoder of untrusted input.** Any parser of external bytes (wire frames,
  routing messages, addresses, sealed-box, the X.509 extension) must have a `Fuzz*` target:
  it must not panic on arbitrary input and must round-trip / hold its invariant on success.
- **Determinism in tests.** In-memory transport + fake clock + `testing/synctest`; no real
  time or network in ordinary tests. The real QUIC layer is exercised behind build tags.

## License

MIT - see [LICENSE](LICENSE).
