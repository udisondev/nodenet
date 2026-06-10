# nodenet

**A reusable core for decentralized P2P connectivity.** nodenet is a Go library that finds a
route to any node by its identifier and helps two peers establish a direct, end-to-end
connection - even when both sit behind NAT. It is the *transport substrate*, not the
application: nodenet gets your bytes to the right peer and opens the pipe; what flows through
that pipe is entirely up to you.

Think of it the way a blockchain is to a dApp. A blockchain provides consensus and state;
the dApps decide what to do with it. nodenet provides **decentralized addressing, routing,
NAT traversal and a real-time media channel**; the apps on top - a messenger, a file-sync
tool, a CRDT backend, a voice/video app - decide what to do with the connections it gives
them.

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
  of its public key). You route to an ID; the overlay converges to it hop by hop - routing
  to an ID *is* delivery, so discovery is just a signed message routed to the target, not a
  separate lookup service. No DNS, no trackers, no central registry.
- **Resilient delivery without acknowledgements.** Every routed message launches along up
  to three *disjoint* paths (the copies carry each other's first hops in an avoid-set, so
  they steer apart in the middle and reconverge near the target), every hop falls back to
  its next-best live neighbour when a send fails (local repair), and a hop-TTL bounds
  wandering. Best-effort in contract, redundant in practice - and no single forwarder can
  silently censor a message.
- **NAT traversal with zero external infrastructure.** No STUN and no TURN servers: a node
  learns its own external address from its overlay neighbours (each reports where it saw
  your packets come from; one report is never trusted - corroboration across independent
  subnets confirms it, and *disagreement* is the tell of a symmetric NAT). The confirmed
  address is readable as `Reflexive()`. From there: DCUtR-style hole-punching coordinated
  by any common neighbour -> packet relay through a volunteer peer (which sees only
  ciphertext) as a last resort, tried cheapest-first. Most peers end up with a direct,
  end-to-end path.
- **End-to-end encryption to a public key you can verify.** Rendezvous returns the target's
  keys authenticated against its NodeID - a forwarder on the path cannot impersonate the
  destination (anti-MITM). Bulk traffic runs directly between endpoints; what travels
  multi-hop - control, rendezvous and `Send` messages - is capped at one frame (64 KiB).
- **Permissionless, with teeth.** No gatekeeper decides who joins. Sybil and Eclipse
  resistance comes from layered, locally-verifiable invariants: proof-of-work on every
  identity, signed routing messages, per-originator rate limits on work-generating
  queries (keyed to the *signed* originator, so a flood can't dodge them by spreading
  across edges), replay protection on handshakes, subnet diversity caps, k-bucket
  eviction rules, and per-IP / global connection limits. Every defensive drop is counted
  and exposed via `Stats()`, so an operator sees a flood being shed instead of guessing.
  On top of (never instead of) those, the application gets its own policy hooks: a
  consent gate for inbound calls (`WithMediaConsent`, reject-all by default) and a
  per-peer edge gate (`WithEdgeAdmission`) to refuse keeping edges with specific
  identities - and since any peer can still route messages to you through others,
  content-level filtering by the authenticated `Originator` is always yours.
- **Zero-copy hot path.** A transit frame travels onward in the very buffer it arrived in -
  only the TTL byte is patched in place. The routing core targets `0 allocs/op`.
- **A real-time media channel for calls.** `OpenMedia` opens a per-call session on its own
  connection over the already-proven path (same socket, same NAT mapping - no second
  hole-punch), with two primitives: unreliable, unordered **datagrams** (voice,
  latest-is-best data; a non-blocking send that reports backpressure as the earliest
  congestion signal) and reliable one-shot **messages** (video frames, feedback; one
  message = one stream, so messages never head-of-line block each other). A call and the
  overlay edge have separate fates: a dying call never tears routing down, and edge churn
  never kills the call. Inbound calls pass the same admission discipline as everything
  else - proof-of-work, session caps, and an explicit application consent gate that
  rejects everything by default - and each session's inbound traffic is metered by a
  built-in anti-flood budget (~20 Mbit/s; excess is dropped and counted in `MediaStats`).

### What it is *not*

- Not a blockchain, ledger, or consensus system - there is no global agreed state.
- Not a storage / DHT-value layer - the DHT is used for *routing to nodes*, not storing
  arbitrary values.
- Not an application protocol - it carries your bytes; it does not define your messages.
- Not a bulk-data overlay - large transfers go directly peer-to-peer over the connection
  nodenet opens for you, never multi-hop through the overlay.
- Not a media *stack* - the media channel moves your real-time frames end to end; codecs,
  RTP-style packetization, jitter buffers and bandwidth estimation stay in the application
  (the channel feeds an estimator the signals it cannot get on its own: a receive timestamp
  on every datagram and counters for every drop, local drops included).

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
| Real-time media | Per-call channel (datagrams + messages); media stack is yours | Not a core primitive | No | **Full stack** (codecs, RTP, BWE) | Raw IP (bring your own) | No |
| Best for | Decentralized apps needing every node to route | General P2P apps | Censorship resistance | Real-time media in browsers | Private device meshes | P2P file/data apps |

**When to reach for nodenet:** you're building a decentralized app - a messenger, a
collaborative editor, a sync engine, a voice/video app - that needs to *find a peer by
identity and open a direct encrypted channel*, with **no central server** for signaling or
relay, and you want NAT nodes to pull their weight as routers. If you need a browser
runtime, a batteries-included media stack, anonymity, or a managed control plane, the
alternatives above fit better.

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
	//    The maintenance loop (keepalive, failure detection, edge replacement) is on
	//    by default and tunable via WithMaintenance; WithInboundBuffer sizes the
	//    Deliveries() queue.
	n := node.New(id, tr,
		node.WithDmin(powDifficulty), // enforce origination-PoW on every received packet
		node.WithRelay(),             // volunteer to relay for peers that can't hole-punch
	)

	// 4. Bootstrap off at least one known contact and start the loops. Tag the
	//    entry point PublicAnchor: a stable, directly-dialable peer usable as a
	//    re-dial anchor.
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
	// The edge is authenticated and end-to-end encrypted, but it is frame-oriented,
	// not a byte stream: application bytes travel as node.TypeApp frames (SendDirect
	// does the framing for you) and incoming ones surface on Deliveries() - a Conn
	// has no read method. One frame caps at 64 KiB, so bulk data means chunking.
	if err := n.SendDirect(ctx, peerID, []byte("over the direct edge")); err != nil {
		log.Printf("send direct: %v", err)
	}
}

var bootstrapID, peerID node.ID
```

Four ways to talk to a peer, by intent:

- **`Send(target, payload)`** - fire a small message (one frame, up to 64 KiB) routed
  multi-hop to a NodeID. No prior connection needed; the overlay converges to the target,
  launching the message down up to three disjoint paths with local repair at every hop -
  one dead forwarder does not sink it. Good for control, presence, offline-ish nudges.
  It never blocks on the network, hence no context.
- **`SendDirect(ctx, target, payload)`** - send an application payload over a direct edge,
  dialing or hole-punching one via `Connect` if none is up. The bytes never transit other
  nodes; on the remote side the payload surfaces on `Deliveries()`, same as `Send`.
- **`Connect(ctx, target)`** - establish a direct, authenticated edge (rendezvous ->
  hole-punch/relay) and speak your own protocol over it: `SendDirect` frames your payloads
  as `node.TypeApp`, inbound frames surface on `Deliveries()`. Good for a live conversation
  or bulk transfer (chunked into frames) that should not traverse the overlay.
- **`OpenMedia(ctx, target)`** - open a real-time media session for a call: unreliable
  datagrams (`SendDatagram`, up to 1200 B, never blocks) and reliable one-shot messages
  (`SendMessage`, up to 64 KiB, no head-of-line blocking between messages), received on the
  session's own `Datagrams()` / `Messages()` channels - never through `Deliveries()`. The
  session is yours to close; if the path dies it closes itself within seconds and you
  re-open. The callee takes calls only if it opted in with `node.WithMediaConsent` and
  reads them off `InboundMedia()`.

The three `Deliveries()`-based paths (`Send`, `SendDirect`, `Connect`) are
**best-effort**: no path issues acknowledgements, and a message arriving while the
receiver's `Deliveries()` queue is full is dropped. An application that needs reliability
acknowledges and retries at its own layer. Failures are distinguishable with `errors.Is`:
`ErrUnroutable` (no live edge to launch from), `ErrPoWUnmet` (the peer failed the
admission work), `ErrEdgeRefused` (your own `WithEdgeAdmission` policy said no),
`transport.ErrMediaUnsupported` (the peer predates the media protocol).

For connectionless end-to-end content you can also use the **sealed-box** path
(`Rendezvous` + the `rendezvous` package): sender-authenticated encryption to the
recipient's static X25519 key (ephemeral-static ECDH + AEAD + a sender signature),
carried over the overlay, where forwarders see only ciphertext.

---

## Example: streaming a call

A call is a media session: its own connection over the already-proven path, with its own
congestion control and its own fate - edge churn never kills a call, and a saturated call
never starves the traffic this node routes for others. Audio rides unreliable datagrams
(a late frame is a useless frame), video frames ride reliable one-shot messages that never
head-of-line block each other. The node setup is the messenger example's; only the pieces
a call adds are shown.

```go
package main

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/udisondev/nodenet/node"
	"github.com/udisondev/nodenet/transport"
)

// The first byte of every datagram and message is its channel - the
// application's own convention with itself. 0-15 are reserved by the core,
// 16-255 are yours.
const (
	chAudio uint8 = 16 // unreliable datagrams: one encoded audio frame each
	chVideo uint8 = 17 // reliable one-shot messages: one whole video frame each
)

func main() {
	n := setupNode() // identity, transport, Bootstrap, go n.Run(ctx) - exactly
	// the messenger example, plus one option: taking calls requires opting in
	// (without it every inbound session is refused - secure by default):
	//
	//	node.WithMediaConsent(func(remote node.ID) bool { return true })

	go answerCalls(n)
	if err := streamCall(context.Background(), n, peerID); err != nil {
		log.Printf("call ended: %v", err)
	}
}

// answerCalls serves inbound sessions. Every session surfacing here has
// already cleared proof-of-work, the session caps and the consent gate; it is
// yours to close.
func answerCalls(n *node.Node) {
	for sess := range n.InboundMedia() {
		go func() {
			defer sess.Close()
			for d := range sess.Datagrams() {
				// d.RxTime is stamped at receive - the one delay signal a
				// bandwidth estimator cannot recover on its own.
				playAudio(d.Pkt.Bytes(), d.RxTime)
				d.Pkt.Release() // the receiver owns every delivered packet
			}
			// The session's channels drain shut when the call ends.
		}()
		go func() {
			for m := range sess.Messages() {
				renderVideo(m.Pkt.Bytes())
				m.Pkt.Release()
			}
		}()
	}
}

// streamCall runs the sending half of one call.
func streamCall(ctx context.Context, n *node.Node, peer node.ID) error {
	// The session rides the live overlay edge's path if one is up (same
	// socket, same NAT mapping - no second hole-punch); otherwise the full
	// connect cascade (rendezvous -> direct / punch / relay) runs first.
	sess, err := n.OpenMedia(ctx, peer)
	if err != nil {
		return err // e.g. transport.ErrMediaUnsupported: the peer predates media
	}
	defer sess.Close()

	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	p := transport.GetMedia() // datagram-sized pool class; sends borrow it,
	defer p.Release()         // so one buffer serves the whole call

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-sess.Closed():
			// The path died and the session closed itself within seconds.
			// Re-establishing is a fresh OpenMedia: the cascade runs again
			// and may land on a better path.
			return transport.ErrMediaClosed
		case <-tick.C:
		}

		// Audio: one datagram per frame, at most MaxMediaDatagram (1200 B).
		// A late frame is a useless frame, so losing one is fine by design.
		p.SetLen(copy(p.Buf()[:transport.MaxMediaDatagram], nextAudioFrame()))
		err := sess.SendDatagram(chAudio, p)
		switch {
		case errors.Is(err, transport.ErrMediaBackpressure):
			// The send ring is full - the earliest "past the path's rate"
			// signal, one RTT before any network loss. The frame is dropped;
			// feed it (and Stats().TxDroppedQueue) to your rate estimator.
		case err != nil:
			return err // ErrMediaClosed: the call is over
		}

		// Video: a whole frame as one reliable message = one short-lived
		// stream, so a lost packet inside it never delays the NEXT frame. A
		// write stalled past ~1 s abandons this frame, never the call.
		if frame := nextVideoFrame(); frame != nil {
			q := transport.Get() // message-sized class, up to 64 KiB
			q.SetLen(copy(q.Buf(), frame))
			err := sess.SendMessage(ctx, chVideo, q)
			q.Release()
			if err != nil && !errors.Is(err, transport.ErrMediaBackpressure) {
				return err
			}
		}
	}
}

// The media stack - capture, codecs, jitter buffer, bandwidth estimation - is
// deliberately the application's job; these stand in for yours.
var (
	setupNode      func() *node.Node
	peerID         node.ID
	nextAudioFrame func() []byte
	nextVideoFrame func() []byte
	playAudio      func(frame []byte, rxTime time.Time)
	renderVideo    func(frame []byte)
)
```

Two things worth internalizing: **make-before-break** - several sessions to one peer are
legal, so when a better path matures mid-call you open a second session over it, switch,
and close the old one; and **backpressure as a feature** - `ErrMediaBackpressure` and the
`MediaStats` drop counters reach your rate estimator a round-trip earlier than network
loss ever could.

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
| **`transport`** | The one polymorphic boundary. Authenticates peers to their NodeID; opens/accepts **bidirectional** edges; surfaces all inbound frames on a single channel. `Packet` is a pooled, borrow-on-send buffer (zero-copy forwarding). The optional `Media` capability opens per-call real-time sessions (datagrams + one-shot messages) beside the frame pipe. |
| **`transport/mem`** | In-memory transport for deterministic tests: shared `Hub` with partition/heal primitives and a directed, seeded per-link media model (loss, jitter, reordering, a shaped bottleneck queue, MTU). |
| **`transport/quic`** | Production transport: QUIC + mutual-TLS over one shared UDP socket (4-tuple reuse for hole-punching), with inbound DoS caps. A second ALPN carries per-call media connections over the same socket; relay volunteers shape relayed traffic. |
| **`routing`** | The two overlay tables (soft-state k-bucket **knowledge** vs actively-maintained **live edges**) and the *pure* logic beside them: routing-message codec, greedy `Decide`, control protocol (ping/pong/lookup/neighbors/siblings/leave). No I/O. |
| **`rendezvous`** | Addressing & discovery: signed routed handshake (verify keys against NodeID, anti-MITM) and sealed-box e2e encryption. Sits *beside* routing, not on top. |
| **`nat`** | NAT-traversal logic and codecs: reflexive learning, hole-punching, packet relay. Pure logic; the socket I/O lives in `transport/quic`. |
| **`node`** | Top of the DAG and the public API. Composes everything: the single dispatch loop (recursive greedy forwarding), origination, the control protocol, the churn-maintenance loop, the NAT orchestration, the media admission gates (PoW, caps, consent) with the call/edge liveness coupling, and the application's local policy hooks (`WithMediaConsent`, `WithEdgeAdmission`). |

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
  node above zero connectivity, and a node that shuts down cleanly announces a graceful
  leave so neighbours replace the edge immediately instead of waiting out a timeout.
- **Three tiers of rules (the security foundation).** In a permissionless network you cannot
  assume a peer runs your code. (1) *Protocol consensus* - disagree and you're simply not on
  the same network. (2) *Verifiable invariants* - PoW, signatures, TTL clamps, format
  validity, rate limits - checked locally on **every** interaction, trusting no peer.
  (3) *Local policy* - topology numbers, honor-system. **Security never rests on tier 3.**
  Code comments tag which tier an invariant belongs to.

---

## Requirements

- **Go 1.26.4+** (uses stdlib `crypto/hkdf`, `crypto/ecdh` X25519, `testing/synctest`).
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
go test -tags e2e_nat ./node ./transport/quic # NAT-emulator e2e (punch, relay, calls)
go test -tags e2e_real ./transport/quic      # real-socket gates (incl. media saturation)
```

### Testing *your* app the same way

The determinism is not internal scaffolding - it is part of the library's surface. The
`Transport` interface is the one polymorphic boundary, and `transport/mem` is a public,
drop-in implementation: `mem.NewHub().New(id, addr)` returns the same `transport.Transport`
that `quic.Listen` does, so your application can bring up a whole multi-node cluster of
itself **in memory**, run it under `testing/synctest` on a fake clock, and inject failures
deterministically - `Hub.Partition`/`Heal` for outages, `Hub.SetLinkProfile` for loss,
jitter, reordering and a shaped bottleneck on the media plane. No sockets, no real time,
no flaky sleeps. And if you write your own `Transport`, the shared contract suite in
`transport/transporttest` (`RunContract`) proves it behaves like the two bundled ones.

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
