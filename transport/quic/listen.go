package quic

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"time"

	quicgo "github.com/quic-go/quic-go"
	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/transport"
)

// config holds the tunable knobs of a quicTransport. Defaults favour the overlay
// owning liveness: QUIC's own keepalive is off and its idle timeout is generous,
// so the node maintenance loop's ping/pong is the single source of liveness truth
// (and the basis for reflexive learning and NAT keepalive).
type config struct {
	idleTimeout      time.Duration
	keepAlivePeriod  time.Duration
	handshakeTimeout time.Duration
	sendDeadline     time.Duration
	inboundBuffer    int
	maxInbound       int                            // global cap on concurrent inbound connections (level-2 self-protection)
	maxInboundPerIP  int                            // cap on concurrent inbound connections from one source IP
	relaySocket      func() (net.PacketConn, error) // factory for relay allocation sockets; nil → bind UDP
}

func defaultConfig() config {
	return config{
		idleTimeout:      5 * time.Minute,
		keepAlivePeriod:  0, // disabled: the overlay keepalive is authoritative
		handshakeTimeout: 10 * time.Second,
		// sendDeadline bounds a single frame write. quic-go's Write blocks while the
		// stream's flow-control window is exhausted (a slow, congested, or silent peer);
		// the dispatch loop forwards synchronously, so an unbounded block would wedge the
		// whole router. A write that cannot drain within this window tears the edge down
		// and the overlay repairs via disjoint paths and re-dial. Generous, so only a
		// genuinely stuck edge trips it, not transient congestion on a healthy link.
		sendDeadline:  5 * time.Second,
		inboundBuffer: 16, // matches transport/mem's default
		// Inbound admission caps. TLS authenticates a peer to its NodeID but does NOT cost
		// it any proof-of-work (PoW is checked a layer up, on the first frame), so the cheap
		// handshake alone is not a barrier: an adversary minting throwaway identities can
		// complete handshakes endlessly and park connections, each holding a goroutine and
		// QUIC state. These caps bound that resource use — a global ceiling and a per-source
		// ceiling so one host (or one NAT) cannot starve every other peer. Level-2
		// self-protection (kept on by default; a deployer may tune them).
		maxInbound:      256,
		maxInboundPerIP: 32,
	}
}

// Option customizes a quicTransport at construction.
type Option func(*config)

// WithIdleTimeout sets QUIC's MaxIdleTimeout — how long a connection may sit with
// no received packet before QUIC tears it down. Keep it well above the overlay's
// keepalive period.
func WithIdleTimeout(d time.Duration) Option { return func(c *config) { c.idleTimeout = d } }

// WithKeepAlive sets QUIC's KeepAlivePeriod. Zero (the default) disables QUIC-level
// keepalive in favour of the overlay's own.
func WithKeepAlive(d time.Duration) Option { return func(c *config) { c.keepAlivePeriod = d } }

// WithHandshakeTimeout bounds how long Dial waits for the QUIC/TLS handshake.
func WithHandshakeTimeout(d time.Duration) Option {
	return func(c *config) { c.handshakeTimeout = d }
}

// WithInboundBuffer sets the capacity of the single Inbound channel.
func WithInboundBuffer(n int) Option { return func(c *config) { c.inboundBuffer = n } }

// WithSendDeadline bounds how long a single frame write may block on a congested or
// silent edge before the edge is torn down. It keeps one stuck peer from wedging the
// node's single dispatch loop. Keep it well below the overlay's dead-edge timeout.
// A non-positive value disables the bound (like the other options' "off" convention
// and net.Conn's zero deadline), leaving a stuck edge to QUIC's idle timeout.
func WithSendDeadline(d time.Duration) Option { return func(c *config) { c.sendDeadline = d } }

// WithMaxInbound sets the global cap on concurrently-admitted inbound connections — the
// level-2 backstop against an adversary parking cheap (non-PoW) handshakes to exhaust
// memory. A non-positive value disables the global cap. Public entry points want this on;
// the default is 256.
func WithMaxInbound(n int) Option { return func(c *config) { c.maxInbound = n } }

// WithMaxInboundPerIP sets the cap on concurrent inbound connections from a single source
// IP, so one host (or one NAT) cannot consume every global slot. A non-positive value
// disables the per-IP cap. The default is 32.
func WithMaxInboundPerIP(n int) Option { return func(c *config) { c.maxInboundPerIP = n } }

// WithRelaySocketFactory sets how a relay volunteer allocates the extra sockets a relay
// session splices over. The default binds fresh UDP sockets on the transport's host;
// a test injects a factory backed by its NAT emulator. Each call returns one socket.
func WithRelaySocketFactory(f func() (net.PacketConn, error)) Option {
	return func(c *config) { c.relaySocket = f }
}

// Listen binds a UDP socket at udpAddr ("host:port", e.g. ":0" or "0.0.0.0:4242")
// and returns a transport that both accepts and dials authenticated QUIC edges
// under id. One *quic.Transport multiplexes the socket for listen and dial so the
// 4-tuple is reused — the seam PunchTo's hole-punching builds on. The caller Closes
// the transport to release the socket and stop the accept loop.
func Listen(id *identity.Identity, udpAddr string, opts ...Option) (transport.Transport, error) {
	uaddr, err := net.ResolveUDPAddr("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	udp, err := net.ListenUDP("udp", uaddr)
	if err != nil {
		return nil, err
	}
	t, err := ListenPacketConn(id, udp, opts...)
	if err != nil {
		_ = udp.Close()
		return nil, err
	}
	return t, nil
}

// ListenPacketConn is Listen over a caller-provided packet connection instead of a
// freshly bound UDP socket — the seam a NAT emulator plugs into for deterministic
// hole-punching and relay tests. The transport takes ownership of pc and Closes it
// when the transport is Closed. pc.LocalAddr should report a *net.UDPAddr.
func ListenPacketConn(id *identity.Identity, pc net.PacketConn, opts ...Option) (transport.Transport, error) {
	cfg := defaultConfig()
	for _, o := range opts {
		o(&cfg)
	}

	cert, err := buildCert(id, rand.Reader)
	if err != nil {
		return nil, err
	}
	tlsConf := tlsConfig(cert)

	// The overlay's dial config: no datagrams (the overlay never uses them —
	// they would let a call starve transit inside one connection), generous
	// idle, overlay-owned keepalive. The LISTENER must serve both planes with
	// one config, so it enables datagrams and the media stream cap. An overlay
	// edge WE dial never negotiates datagrams (this config); on an ACCEPTED
	// overlay edge a foreign dialer may negotiate them, but our overlay code
	// never reads datagrams, so anything it sends dies in quic-go's small
	// bounded receive queue — wasted bytes for the sender, no resource growth
	// here. Per RFC 9000 a media session's effective idle timeout is the min
	// of both ends — the media dialer's 10 s — regardless of the listener's
	// overlay-sized value here.
	qconf := &quicgo.Config{
		MaxIdleTimeout:       cfg.idleTimeout,
		KeepAlivePeriod:      cfg.keepAlivePeriod,
		HandshakeIdleTimeout: cfg.handshakeTimeout,
		EnableDatagrams:      false,
	}
	lconf := qconf.Clone()
	lconf.EnableDatagrams = true
	lconf.MaxIncomingUniStreams = maxMediaUniStreams
	tr := &quicgo.Transport{Conn: pc}
	ln, err := tr.Listen(listenerTLSConfig(tlsConf), lconf)
	if err != nil {
		_ = tr.Close()
		return nil, err
	}

	relaySocket := cfg.relaySocket
	if relaySocket == nil {
		relaySocket = defaultRelaySocket(pc)
	}

	// A nil inboundSlots means the global cap is disabled (admitInbound skips the reserve).
	var inboundSlots chan struct{}
	if cfg.maxInbound > 0 {
		inboundSlots = make(chan struct{}, cfg.maxInbound)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t := &quicTransport{
		id:           id.ID(),
		localAddr:    addrFromNet(pc.LocalAddr()),
		conn:         pc,
		relaySocket:  relaySocket,
		relaySlots:   make(chan struct{}, maxRelaySessions),
		inboundSlots: inboundSlots,
		perIP:        make(map[netip.Addr]int),
		maxPerIP:     cfg.maxInboundPerIP,
		sendDeadline: cfg.sendDeadline,
		tr:           tr,
		ln:           ln,
		tlsConf:      tlsConf,
		qconf:        qconf,
		mediaTLS:     mediaTLSConfig(tlsConf),
		mediaQConf:   mediaQUICConfig(),
		ctx:          ctx,
		cancel:       cancel,
		in:           make(chan transport.Delivery, cfg.inboundBuffer),
		inMedia:      make(chan transport.MediaSession, inMediaBuffer),
		done:         make(chan struct{}),
		conns:        make(map[*quicConn]struct{}),
		mediaSess:    make(map[*mediaSession]struct{}),
		relays:       make(map[*relaySession]func()),
	}
	t.wg.Add(2)
	go t.acceptLoop(ctx)
	go t.punchDrainLoop()
	return t, nil
}

// Dial opens an authenticated bidirectional edge to remoteID at addr. It performs
// the QUIC/TLS handshake, re-derives the peer's NodeID and checks it against
// remoteID (ErrIdentityMismatch on disagreement), opens the single bidi stream,
// registers the edge, and starts its read loop. ctx bounds the whole operation.
// Failures wrap the transport sentinels with %w — callers keep matching them with
// errors.Is, while the underlying cause (resolve, handshake, TLS alert) stays
// diagnosable instead of being erased.
func (t *quicTransport) Dial(ctx context.Context, remoteID kad.ID, addr transport.Addr) (transport.Conn, error) {
	uaddr, err := net.ResolveUDPAddr("udp", addr.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("%w: resolve %s: %v", transport.ErrNoRoute, addr.Endpoint, err)
	}

	qconn, err := t.tr.Dial(ctx, uaddr, t.tlsConf, t.qconf)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%w: dial %s: %v", transport.ErrNoRoute, addr.Endpoint, err)
	}

	remote, err := peerIDFromConn(qconn.ConnectionState().TLS)
	if err != nil {
		_ = qconn.CloseWithError(appCodeNormal, "")
		return nil, fmt.Errorf("%w: %v", transport.ErrIdentityMismatch, err)
	}
	if remote != remoteID {
		_ = qconn.CloseWithError(appCodeNormal, "")
		return nil, fmt.Errorf("%w: peer at %s authenticated as a different NodeID", transport.ErrIdentityMismatch, addr.Endpoint)
	}

	str, err := qconn.OpenStreamSync(ctx)
	if err != nil {
		_ = qconn.CloseWithError(appCodeNormal, "")
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%w: open stream to %s: %v", transport.ErrNoRoute, addr.Endpoint, err)
	}

	c := newQuicConn(t, remote, qconn, str)
	if !t.registerConn(c) {
		_ = qconn.CloseWithError(appCodeNormal, "")
		return nil, transport.ErrConnClosed
	}
	// registerConn reserved the read loop's wg slot atomically with the closed check,
	// so this goroutine cannot race Close's wg.Wait; Done pairs with that reservation.
	go func() {
		defer t.wg.Done()
		c.readLoop()
	}()
	return c, nil
}
