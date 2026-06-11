// Package quic is the production transport: QUIC (over UDP) with mutual TLS 1.3,
// authenticating each peer to its NodeID. It is a drop-in transport.Transport
// alongside transport/mem, so routing and node run unchanged on either.
//
// # Identity binding (mutual TLS, libp2p-style)
//
// A node uses a fresh one-time certificate key per process and self-signs an
// X.509 certificate that carries a custom extension binding the long-lived
// Ed25519 identity to that cert key: {ed_pub, sig_ed(cert_pubkey)}. The standard
// CA chain check is disabled; instead VerifyPeerCertificate parses the extension,
// verifies the Ed25519 signature over the peer's cert public key, recomputes
// NodeID = BLAKE2b(ed_pub), and (on dial) checks it against the expected peer.
// Forward secrecy comes from TLS 1.3's ephemeral ECDHE; the static X25519 e2e key
// is not involved here.
//
// # Framing
//
// transport does not import wire — a Packet is an opaque buffer — so this package
// adds its own length delimiting on the single bidirectional stream each edge
// runs: uvarint(len) | packetBytes, with len clamped to transport.MaxPacketLen on
// read (level-2 self-protection). It carries only small control/rendezvous/routed
// frames; bulk goes directly between endpoints, never over the overlay.
//
// # NAT traversal primitives
//
// The transport also implements transport.Puncher and transport.Relayer.
// PunchTo sends a raw non-QUIC datagram over the shared QUIC socket, so the
// punch and the subsequent handshake reuse one 4-tuple — the property
// hole-punching depends on, and the reason listen and dial share a single
// *quic.Transport / UDP socket. AllocateRelay turns this node into a relay
// volunteer: two UDP sockets spliced at the datagram level, forwarding only
// ciphertext without terminating the tunnelled connection. Coordination —
// hole-punch signalling, reflexive-address learning, relay selection — lives a
// layer up, in the nat package and node.
package quic

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"sync"
	"time"

	quicgo "github.com/quic-go/quic-go"
	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/transport"
)

var _ transport.Transport = (*quicTransport)(nil)

// quicTransport is the production transport: one UDP socket multiplexed by a
// single *quic.Transport that both listens for and dials peer connections. Every
// edge's frames surface on one Inbound channel; the accept loop, the punch-drain
// loop, one read loop per edge and the relay-session goroutines are tracked by wg
// so Close can drain them (registration and the wg reservation share one critical
// section with the closed flag, so nothing can slip past a closing transport).
// Sharing one *quic.Transport / UDP socket for listen and dial (rather than a
// socket per connection) keeps the 4-tuple reuse that NAT hole-punching (PunchTo)
// relies on.
type quicTransport struct {
	id        kad.ID
	localAddr transport.Addr

	conn         net.PacketConn // the underlying socket; we own it (quic-go does not close a provided Conn)
	relaySocket  func() (net.PacketConn, error)
	relaySlots   chan struct{} // bounded semaphore: one token per live relay session, cap maxRelaySessions
	inboundSlots chan struct{} // bounded semaphore: one token per admitted inbound connection; nil disables the global cap
	maxPerIP          int           // cap on concurrent inbound connections from one source IP; ≤0 disables it
	sendDeadline      time.Duration // per-frame write bound; a stuck edge is torn down rather than stalling the loop
	firstFrameTimeout time.Duration // inbound-only bound to open a stream and send a first frame; ≤0 disables it
	tr           *quicgo.Transport
	ln           *quicgo.Listener
	tlsConf      *tls.Config
	qconf        *quicgo.Config
	mediaTLS     *tls.Config    // the same identity, media ALPN — for OpenMedia dials
	mediaQConf   *quicgo.Config // datagrams on, in-call idle/keepalive — for OpenMedia dials

	ctx    context.Context // cancelled by Close to unblock Accept/AcceptStream
	cancel context.CancelFunc

	in      chan transport.Delivery
	inMedia chan transport.MediaSession
	done    chan struct{}

	mu        sync.RWMutex
	closed    bool
	conns     map[*quicConn]struct{}
	mediaSess map[*mediaSession]struct{} // live media sessions, torn down by Close
	relays    map[*relaySession]func()   // live relay sessions → their close funcs, torn down by Close
	perIP     map[netip.Addr]int         // concurrent inbound connections per source IP, for maxPerIP

	// relayAgg is the volunteer-wide relay shaper bucket every relay session
	// charges alongside its own (level-2 self-protection; see relay.go).
	relayAgg transport.TokenBucket

	wg        sync.WaitGroup
	closeOnce sync.Once
}

func (t *quicTransport) LocalID() kad.ID                    { return t.id }
func (t *quicTransport) LocalAddr() transport.Addr          { return t.localAddr }
func (t *quicTransport) Inbound() <-chan transport.Delivery { return t.in }

// IPAddressed reports that QUIC endpoints are real IP host:port pairs, so the node layer
// defaults to IP subnet-diversity accounting (see transport.IPAddressed).
func (t *quicTransport) IPAddressed() bool { return true }

// acceptLoop accepts inbound QUIC connections until the transport closes. Each
// connection is handed to its own goroutine: handleAccepted blocks on AcceptStream
// (which only returns once the dialer writes its first frame), so accepting must
// not be serialized behind it.
func (t *quicTransport) acceptLoop(ctx context.Context) {
	defer t.wg.Done()
	for {
		qconn, err := t.ln.Accept(ctx)
		if err != nil {
			return // listener closed or ctx done
		}
		// Admission cap (level-2 self-protection): refuse — and immediately tear down — an
		// inbound connection once the global or per-source-IP ceiling is hit, so a flood of
		// cheap handshakes cannot exhaust goroutines/memory. A refused peer is dropped before
		// a read loop is ever spawned; it retries later or routes around us.
		release, ok := t.admitInbound(remoteIP(qconn.RemoteAddr()))
		if !ok {
			_ = qconn.CloseWithError(appCodeNormal, "")
			continue
		}
		t.wg.Go(func() {
			// One listener serves both protocols; the negotiated ALPN says
			// which plane this connection belongs to. A media connection is a
			// session, not an edge: it hands its admission slot (release) to
			// the session, which frees it when the session ends.
			if qconn.ConnectionState().TLS.NegotiatedProtocol == alpnMedia {
				t.handleAcceptedMedia(qconn, release)
				return
			}
			defer release()
			t.handleAccepted(ctx, qconn)
		})
	}
}

// remoteIP extracts the source IP of an inbound connection for per-IP accounting. A QUIC
// RemoteAddr is a *net.UDPAddr; anything unparsable maps to the zero Addr, which still
// counts (all such connections share one per-IP bucket) so accounting never silently
// disables itself.
func remoteIP(a net.Addr) netip.Addr {
	if ua, ok := a.(*net.UDPAddr); ok {
		if ip, ok := netip.AddrFromSlice(ua.IP); ok {
			return ip.Unmap()
		}
	}
	if ap, err := netip.ParseAddrPort(a.String()); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
}

// admitInbound reserves a slot for a new inbound connection from ip, enforcing the global
// inbound cap and the per-source-IP cap. It returns a release func — call it exactly once
// when the connection ends — and whether the connection was admitted. A refused connection
// must be closed by the caller without spawning a read loop. The release is idempotent and
// safe to defer. Reserving the global slot before taking the per-IP lock keeps the lock
// hold short; on a per-IP rejection the global slot is handed straight back.
func (t *quicTransport) admitInbound(ip netip.Addr) (release func(), ok bool) {
	if t.inboundSlots != nil {
		select {
		case t.inboundSlots <- struct{}{}:
		default:
			return nil, false // global cap reached
		}
	}
	t.mu.Lock()
	if t.maxPerIP > 0 && t.perIP[ip] >= t.maxPerIP {
		t.mu.Unlock()
		if t.inboundSlots != nil {
			<-t.inboundSlots
		}
		return nil, false // per-IP cap reached
	}
	t.perIP[ip]++
	t.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			t.mu.Lock()
			if t.perIP[ip] <= 1 {
				delete(t.perIP, ip)
			} else {
				t.perIP[ip]--
			}
			t.mu.Unlock()
			if t.inboundSlots != nil {
				<-t.inboundSlots
			}
		})
	}, true
}

// handleAccepted authenticates an inbound connection, takes its single bidi
// stream, registers the edge, and runs its read loop until the edge dies.
func (t *quicTransport) handleAccepted(ctx context.Context, qconn *quicgo.Conn) {
	remote, err := peerIDFromConn(qconn.ConnectionState().TLS)
	if err != nil {
		_ = qconn.CloseWithError(appCodeNormal, "")
		return
	}
	// Bound the wait for the peer to open its bidi stream: a connection that finished
	// the handshake but never opens a stream would otherwise block here until the idle
	// timeout, pinning its admission slot. Inbound-only, level-2 self-protection.
	actx := ctx
	if t.firstFrameTimeout > 0 {
		var cancel context.CancelFunc
		actx, cancel = context.WithTimeout(ctx, t.firstFrameTimeout)
		defer cancel()
	}
	str, err := qconn.AcceptStream(actx)
	if err != nil {
		_ = qconn.CloseWithError(appCodeNormal, "")
		return
	}
	c := newQuicConn(t, remote, qconn, str, t.firstFrameTimeout)
	if !t.registerConn(c) {
		_ = qconn.CloseWithError(appCodeNormal, "")
		return
	}
	defer t.wg.Done() // pairs with the read-loop slot registerConn reserved
	// Drain any extra stream the peer opens on this accepted overlay edge (extra bidi
	// or any uni — the overlay uses only the one bidi above). The wg counter is ≥1
	// here (the read-loop slot), so these Adds cannot race Close's Wait at zero; both
	// goroutines exit when the connection or transport closes.
	t.wg.Add(2)
	go func() { defer t.wg.Done(); c.drainExtraStreams(ctx, true) }()
	go func() { defer t.wg.Done(); c.drainExtraStreams(ctx, false) }()
	c.readLoop()
}

// registerConn tracks c for Close cleanup and reserves a WaitGroup slot for the
// edge's read loop in the same critical section as the closed check. That atomicity
// matters: Close marks closed under this mutex before wg.Wait(), so the Add either
// strictly precedes the Wait or the registration is refused — a wg.Add racing an
// in-progress Wait at counter zero (a documented WaitGroup misuse) is impossible.
// It reports false if the transport is already closed, so the caller tears the new
// connection down (and must NOT call wg.Done). On true the caller runs the read
// loop and calls t.wg.Done() when it exits.
func (t *quicTransport) registerConn(c *quicConn) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return false
	}
	t.conns[c] = struct{}{}
	t.wg.Add(1)
	return true
}

// removeConn drops c from the tracking set (called from quicConn.Close).
func (t *quicTransport) removeConn(c *quicConn) {
	t.mu.Lock()
	if t.conns != nil {
		delete(t.conns, c)
	}
	t.mu.Unlock()
}

// deliver pushes one frame onto the inbound stream. It deliberately touches nothing
// but the two channels — no t.mu, in either mode: this is the per-frame hot path of
// every read loop, while t.mu is the connection control plane's lock, write-held on
// every admission, registration and teardown, so even a read lock here would let a
// flood of connection churn add its lock traffic as latency to data delivery on every
// live edge (and a lock held ACROSS the send would outright deadlock against the
// single Inbound consumer, which closes edges synchronously: quicConn.Close →
// removeConn → t.mu.Lock). No closed check is needed for safety either: every deliver
// caller is a wg-tracked read loop, and Close closes t.done before wg.Wait()ing them
// out ahead of close(t.in) — so a send on a closed t.in is impossible and the done arm
// unblocks a backpressured send at shutdown.
func (t *quicTransport) deliver(d transport.Delivery, _ *quicConn) error {
	select {
	case t.in <- d:
		return nil
	case <-t.done:
		return transport.ErrConnClosed
	}
}

// Close shuts the transport down. It mirrors the in-memory transport's ordering:
// signal done first, mark closed and snapshot the conns and relay sessions under the
// write lock, close the listener, every edge and every relay session, then close the
// shared QUIC transport and UDP socket, wait for the accept, read and relay loops to
// drain, and finally close Inbound. It is idempotent. The nil guards let tests drive
// the lifecycle on a partially-constructed transport without a real QUIC stack.
func (t *quicTransport) Close() error {
	t.closeOnce.Do(func() {
		close(t.done)
		if t.cancel != nil {
			t.cancel() // unblock Accept and any in-handshake AcceptStream
		}

		t.mu.Lock()
		t.closed = true
		conns := make([]*quicConn, 0, len(t.conns))
		for c := range t.conns {
			conns = append(conns, c)
		}
		t.conns = nil
		sessions := make([]*mediaSession, 0, len(t.mediaSess))
		for s := range t.mediaSess {
			sessions = append(sessions, s)
		}
		t.mediaSess = nil
		relays := make([]func(), 0, len(t.relays))
		for _, closeFn := range t.relays {
			relays = append(relays, closeFn)
		}
		t.relays = nil
		t.mu.Unlock()

		if t.ln != nil {
			_ = t.ln.Close()
		}
		for _, c := range conns {
			_ = c.Close()
		}
		for _, s := range sessions {
			_ = s.Close()
		}
		// Tear down relay sessions: an active one refreshes its own idle TTL forever,
		// so without this it would outlive the transport, pinning sockets and goroutines.
		for _, closeFn := range relays {
			closeFn()
		}
		if t.tr != nil {
			_ = t.tr.Close()
		}
		if t.conn != nil {
			_ = t.conn.Close() // quic-go does not close a Conn it did not create
		}

		t.wg.Wait()
		close(t.in)
		if t.inMedia != nil {
			close(t.inMedia)
		}
	})
	return nil
}
