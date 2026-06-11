package quic

import (
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/udisondev/nodenet/transport"
)

var _ transport.Relayer = (*quicTransport)(nil)

const (
	// relayIdleTTL closes a relay session that has carried no traffic for this long, so
	// a session whose tunnelled connection died (or was never established) is reclaimed.
	// Live connections keep it open via their own keepalive. Level-2 self-protection.
	relayIdleTTL = 30 * time.Second

	// maxRelaySessions caps concurrent relay sessions on a volunteer, bounding the
	// sockets and goroutines an abuser can pin. Level-2 self-protection.
	maxRelaySessions = 256

	// The volunteer's traffic shaper (level-2 self-protection, on by default):
	// a token bucket per session (bandwidth + burst + packet rate) and an
	// aggregate one across all sessions. Exceeding traffic is DROPPED, never a
	// teardown: the tunnelled QUIC connection sees loss, and its congestion
	// control — and the application's bandwidth estimator above it — back off,
	// the only semantics compatible with media. The honest consequence is that
	// video through a stranger's relay is modest by design; this protects the
	// volunteer, whose own deployment may raise the numbers.
	relaySessionRate     = 2_000_000 / 8  // bytes/s (2 Mbit/s) per session
	relaySessionBurst    = 128 << 10      // bytes
	relaySessionPPS      = 1000           // packets/s per session
	relaySessionPPSBurst = 256            // packets
	relayAggRate         = 16_000_000 / 8 // bytes/s (16 Mbit/s) across all sessions
	relayAggBurst        = 256 << 10      // bytes
)

// defaultRelaySocket binds fresh UDP sockets on the same host as the main socket — the
// production relay-allocation factory.
func defaultRelaySocket(pc net.PacketConn) func() (net.PacketConn, error) {
	host := net.IPv4zero
	if ua, ok := pc.LocalAddr().(*net.UDPAddr); ok {
		host = ua.IP
	}
	return func() (net.PacketConn, error) {
		return net.ListenUDP("udp", &net.UDPAddr{IP: host, Port: 0})
	}
}

// AllocateRelay opens a relay session: two allocation sockets whose traffic is spliced,
// so a QUIC connection between the caller (dialing callerAddr) and the callee
// (registering on calleeAddr) tunnels through this node without it terminating the
// connection — it forwards raw datagrams and sees only ciphertext. close tears the
// session down; it also self-closes after relayIdleTTL of no traffic, and the
// transport's Close tears every live session down (sessions must not outlive it).
// A volunteer at its session cap refuses with transport.ErrRelayBusy — the transport
// is alive, the requester just picks another volunteer or retries.
func (t *quicTransport) AllocateRelay() (transport.Addr, transport.Addr, func(), error) {
	// Fast-fail on a closed transport. The registration below re-checks atomically;
	// this just avoids binding sockets for a doomed session.
	t.mu.RLock()
	closed := t.closed
	t.mu.RUnlock()
	if closed {
		return transport.Addr{}, transport.Addr{}, nil, transport.ErrConnClosed
	}

	// Reserve a session slot. relaySlots is a bounded semaphore (one token per allowed
	// session), so acquiring is a single non-blocking send: concurrent callers can never
	// collectively exceed the cap, with no load-then-add race. Releasing is the matching
	// receive, so the count cannot drift. level-2 self-protection.
	select {
	case t.relaySlots <- struct{}{}:
	default:
		slog.Debug("relay allocation refused", "reason", "session cap reached")
		return transport.Addr{}, transport.Addr{}, nil, transport.ErrRelayBusy
	}
	release := func() { <-t.relaySlots }

	sa, err := t.relaySocket()
	if err != nil {
		release()
		// Not a cap refusal but a local resource failure (fd limits): the volunteer
		// is degraded as a relay and an operator should notice.
		slog.Warn("relay socket bind failed", "err", err)
		return transport.Addr{}, transport.Addr{}, nil, err
	}
	sb, err := t.relaySocket()
	if err != nil {
		_ = sa.Close()
		release()
		slog.Warn("relay socket bind failed", "err", err)
		return transport.Addr{}, transport.Addr{}, nil, err
	}

	s := &relaySession{a: sa, b: sb, agg: &t.relayAgg, done: make(chan struct{})}
	s.lastActive.Store(time.Now().UnixNano())
	var once sync.Once
	closeFn := func() {
		once.Do(func() {
			close(s.done)
			_ = sa.Close()
			_ = sb.Close()
			t.mu.Lock()
			delete(t.relays, s) // no-op after Close nils the map
			t.mu.Unlock()
			release()
		})
	}

	// Register the session and reserve its goroutines' wg slots in the same critical
	// section as the closed check, so Close — which marks closed, snapshots the
	// sessions, closes them all and wg.Wait()s — can never miss a session or race the
	// Wait: either we register first and Close tears us down, or we observe closed
	// here and abort. The node's relay path deliberately discards closeFn (a session
	// reclaims itself when idle), so this transport-side tracking is the only thing
	// keeping sessions from outliving Close.
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		_ = sa.Close()
		_ = sb.Close()
		release()
		return transport.Addr{}, transport.Addr{}, nil, transport.ErrConnClosed
	}
	t.relays[s] = closeFn
	t.wg.Add(3)
	t.mu.Unlock()

	go func() { defer t.wg.Done(); s.pump(sa, sb, &s.aAddr, &s.bAddr) }() // caller side → callee
	go func() { defer t.wg.Done(); s.pump(sb, sa, &s.bAddr, &s.aAddr) }() // callee side → caller
	go func() { defer t.wg.Done(); s.idleWatch(closeFn) }()

	slog.Debug("relay session opened",
		"callerAddr", sa.LocalAddr(), "calleeAddr", sb.LocalAddr())
	return addrFromNet(sa.LocalAddr()), addrFromNet(sb.LocalAddr()), closeFn, nil
}

// relaySession splices two allocation sockets. Each side PINS to the host (IP) of the
// first datagram it receives; thereafter it forwards only datagrams from that host to the
// other peer's learned address — a transparent UDP relay that never parses the payload.
// Pinning the host is the level-2 self-protection that stops a third party which learns
// an allocation address from a DIFFERENT host hijacking the session or using the relay as
// an open reflector. It still follows a NAT port rebind of the legitimate peer (same IP,
// new port), so an active relayed connection survives a remap; the residual is that an
// attacker sharing the peer's public IP could interpose, a deliberately narrow surface.
type relaySession struct {
	a, b       net.PacketConn
	mu         sync.Mutex
	aAddr      net.Addr // caller's address, pinned on the first datagram on socket a
	bAddr      net.Addr // callee's address, pinned on the first datagram on socket b
	lastActive atomic.Int64
	done       chan struct{}

	// Shaper state (level-2, see the constants above): this session's
	// bandwidth and packet buckets, plus the volunteer-wide aggregate shared
	// with every other session (nil only when a session is built without an
	// owning transport, as the white-box tests do — then only the per-session
	// buckets apply).
	bw  transport.TokenBucket
	pps transport.TokenBucket
	agg *transport.TokenBucket
}

// allowRelay charges one datagram of n bytes against the session's and the
// volunteer's shaper buckets, reporting whether it may be forwarded. A refusal
// is a silent drop — deliberately uncounted, unlike the media plane's own
// queues: to the tunnelled connection the drop IS the signal (loss its
// congestion control reacts to), and the relay keeps no per-flow accounting
// by design — it never even parses what it forwards.
func (s *relaySession) allowRelay(now time.Time, n int) bool {
	if !s.pps.Allow(now, relaySessionPPS, relaySessionPPSBurst) ||
		!s.bw.AllowN(now, float64(n), relaySessionRate, relaySessionBurst) {
		return false
	}
	return s.agg == nil || s.agg.AllowN(now, float64(n), relayAggRate, relayAggBurst)
}

// pump reads datagrams arriving on `in` (facing one peer), pins that peer's address into
// selfAddr on the first datagram, drops any later datagram from a different source, and
// writes the rest to `out` addressed to the other peer's pinned address (peerAddr), once
// known. Only an actually-relayed datagram refreshes lastActive, so a one-sided trickle
// to an allocation that the other peer never joined cannot keep the slot alive past
// relayIdleTTL.
func (s *relaySession) pump(in, out net.PacketConn, selfAddr, peerAddr *net.Addr) {
	buf := make([]byte, 1<<16)
	for {
		n, from, err := in.ReadFrom(buf)
		if err != nil {
			return // socket closed
		}
		s.mu.Lock()
		switch {
		case *selfAddr == nil:
			*selfAddr = from // pin this side to its first sender's host
		case sameHostIP(*selfAddr, from):
			*selfAddr = from // same host — follow a NAT port rebind of the legitimate peer
		default:
			s.mu.Unlock()
			continue // a different host — ignore (anti-hijack / anti-reflection)
		}
		dst := *peerAddr
		s.mu.Unlock()
		if dst == nil {
			continue // the other peer has not shown up yet; nowhere to forward
		}
		// level-2 self-protection: the shaper. An over-budget datagram is
		// dropped, never a teardown — the tunnelled QUIC sees loss and backs
		// off. A dropped datagram does not refresh lastActive either: only
		// actually-relayed traffic keeps the slot alive.
		if !s.allowRelay(time.Now(), n) {
			continue
		}
		s.lastActive.Store(time.Now().UnixNano())
		_, _ = out.WriteTo(buf[:n], dst)
	}
}

// sameHostIP reports whether two addresses are the same host (IP), ignoring the port so
// a NAT port rebind of the legitimate peer is followed. It compares *net.UDPAddr IPs
// directly on the common path (no allocation), falling back to the string form for any
// other address type.
func sameHostIP(a, b net.Addr) bool {
	ua, ok1 := a.(*net.UDPAddr)
	ub, ok2 := b.(*net.UDPAddr)
	if ok1 && ok2 {
		return ua.IP.Equal(ub.IP)
	}
	return a.String() == b.String()
}

// idleWatch closes the session once it has been idle past relayIdleTTL.
func (s *relaySession) idleWatch(closeFn func()) {
	tick := time.NewTicker(relayIdleTTL / 2)
	defer tick.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-tick.C:
			if time.Since(time.Unix(0, s.lastActive.Load())) > relayIdleTTL {
				slog.Debug("relay session reclaimed", "reason", "idle past TTL")
				closeFn()
				return
			}
		}
	}
}
