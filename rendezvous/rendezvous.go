// Package rendezvous is the addressing-and-discovery layer of nodenet: how a node
// finds another node's keys and coordinates by its NodeID, and how a node sends a
// small piece of end-to-end content over the overlay without a direct connection.
//
// Recursive routing to an ID IS delivery (a Msg addressed to NodeID_R converges to
// R), so there is no separate "lookup service". On top of that bare addressability
// rendezvous provides two things:
//
//   - A routed, signed handshake. A routes a signed Hello to NodeID_R carrying its
//     keys and coordinates; R answers (also routed) with its {ed_pub, x_pub,
//     coordinates} under an Ed25519 signature. A checks BLAKE2b(ed_pub_R) ==
//     NodeID_R and the signature — so a forwarder on the path cannot impersonate R
//     (anti-MITM). The forwarder can still drop or misroute; it cannot forge R's
//     identity, because it cannot produce an ed_pub that hashes to NodeID_R nor sign
//     as R. A per-handshake nonce binds the reply to its hello (anti-replay). Once
//     the coordinates are exchanged the two peers move to a DIRECT channel via
//     hole-punching — that step needs real network semantics and lives in the nat
//     package (its I/O in the QUIC transport), so here the handshake stops at "A
//     learned R's verified coordinates".
//
//   - Sealed-box: authenticated anonymous-recipient encryption for a small piece of
//     connectionless content carried over the overlay. An ephemeral X25519 key does
//     ECDH against the recipient's static x_pub; the symmetric key derived from that
//     shared secret keys ChaCha20-Poly1305; the sender adds an Ed25519 signature so
//     the recipient learns and authenticates who sent it. Forwarders see only
//     ciphertext. An authenticated timestamp bounds replays to a freshness window,
//     and a ReplayCache closes the within-window gap, so a box opens at most once.
//     This is the connectionless counterpart to the bulk path (a direct QUIC
//     connection A<->R) — bulk traffic is NOT carried over the multi-hop overlay,
//     only rendezvous and small control content.
//
// # Layering
//
// rendezvous sits above the identity/wire/transport/kad leaves and BESIDE routing,
// not on top of it: it owns the content codecs (Hello, Reply, sealed-box) and the
// pure verification helpers, but it does NOT import routing. The overlay envelope
// (routing.Msg: target, TTL, avoid-set) is applied by the node layer, which composes
// this content codec with the routing envelope and the transport pipe. Keeping
// rendezvous independent of routing keeps the e2e crypto reusable and the dependency
// graph a clean DAG (node -> {routing, rendezvous}; rendezvous -> {identity, wire,
// transport, kad}).
//
// # Frame type space
//
// wire.Type is one byte shared by the whole protocol. rendezvous owns values 8..9
// (TypeHello, TypeReply); the full allocation is recorded in the registry on
// wire.Type. These are routed envelopes — a Hello/Reply rides in the payload of a routing.Msg
// and is forwarded greedily by the same Decide/SetTTL the data path uses; only the
// terminal handling (build a reply, correlate a reply) differs, and that lives in
// node.
//
// The decoders here are defensive against untrusted input exactly like wire/routing:
// strict bounds checks before any allocation, sentinel errors, and they NEVER panic
// on malformed bytes. Every decoder of bytes from the wire has a Fuzz target.
package rendezvous
