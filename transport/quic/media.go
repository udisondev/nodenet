package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	quicgo "github.com/quic-go/quic-go"
	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/transport"
)

var _ transport.Media = (*quicTransport)(nil)

// A media session is a SEPARATE QUIC connection with its own ALPN, dialed
// through the same *quic.Transport — hence the same UDP socket and, toward the
// overlay edge's address, the same 4-tuple: the NAT mapping (or relay pinning)
// the edge proved keeps working, no second hole-punch needed, and media
// traffic even refreshes that mapping for the edge. A separate connection
// rather than datagrams on the edge keeps fates and congestion control apart:
// the packer prioritizes DATAGRAM frames over stream data inside one
// connection, so a call sharing the edge would starve transit — a call must
// never break the node's router role. Closing a session never touches the
// edge tables; reaping the edge never touches a call.
const (
	// alpnMedia names the media subprotocol (level-1 of that subprotocol; the
	// overlay stays on alpn). A listener advertises both and tells them apart
	// by the negotiated protocol; an older peer without it fails the TLS
	// handshake, which surfaces as ErrMediaUnsupported — the peer stays a
	// full overlay member.
	alpnMedia = "nodenet-media/1"

	// mediaIdleTimeout / mediaKeepAlive: a session's path death is detected
	// within ~10 s, and the 3 s keepalive (alive only while a session is —
	// no battery cost outside calls) keeps a healthy path from ever idling
	// out. A dialed session advertises this 10 s bound as its QUIC idle. An
	// ACCEPTED session cannot rely on QUIC's negotiated idle — it is the min of
	// both ends, so a hostile dialer advertising a long (or disabled) idle would
	// park the slot far longer — so the accepted side runs its own idle reaper
	// (idleReap) keyed on the same bound, independent of the peer's value.
	// Level-3 policy for the bound; the reaper itself is level-2 self-protection.
	mediaIdleTimeout = 10 * time.Second
	mediaKeepAlive   = 3 * time.Second

	// mediaStreamStall bounds how long one message write (or stream open) may
	// block before THIS stream is reset and the message abandoned — never the
	// session. Block-then-kill per message is what keeps a bufferbloated path
	// from wedging the call. Level-3 policy.
	mediaStreamStall = time.Second

	// mediaMessageReadBound bounds how long an inbound message stream may
	// dribble before its read is cancelled, so a peer cannot pin reader
	// goroutines and pooled buffers with never-finishing streams. Generous —
	// a legitimate message is one flow-controlled burst. Level-2
	// self-protection.
	mediaMessageReadBound = 5 * time.Second

	// maxMediaUniStreams caps the peer's concurrently-open message streams on
	// one session, bounding reader goroutines and pooled buffers a session
	// can pin. Level-2 self-protection.
	maxMediaUniStreams = 256

	// inMediaBuffer is the InboundMedia channel's depth; a session arriving
	// while it is full is refused (the node layer consumes promptly).
	inMediaBuffer = 8

	// appCodeMediaRefused closes an inbound media connection this node will
	// not serve (no datagram support negotiated, or nobody consuming
	// inbound sessions).
	appCodeMediaRefused quicgo.ApplicationErrorCode = 1

	// Stream error codes for an abandoned message: the writer reset the
	// stream because its write stalled past mediaStreamStall, or because the
	// caller's ctx was cancelled ("drop the stale frame"). The reader treats
	// any reset the same — the message never happened.
	streamCodeStalled   quicgo.StreamErrorCode = 1
	streamCodeCancelled quicgo.StreamErrorCode = 2
)

// cryptoErrNoALPN is the TLS no_application_protocol alert (120) as a QUIC
// CRYPTO_ERROR code (0x100 + alert): what an older listener without alpnMedia
// answers a media dial with.
const cryptoErrNoALPN quicgo.TransportErrorCode = 0x100 + 120

// mediaTLSConfig clones the transport's TLS identity for a media dial: same
// certificate and peer verification, media ALPN only.
func mediaTLSConfig(base *tls.Config) *tls.Config {
	c := base.Clone()
	c.NextProtos = []string{alpnMedia}
	return c
}

// listenerTLSConfig clones the transport's TLS identity for the shared
// listener: it advertises both protocols and the accept path demultiplexes by
// the negotiated one.
func listenerTLSConfig(base *tls.Config) *tls.Config {
	c := base.Clone()
	c.NextProtos = []string{alpn, alpnMedia}
	return c
}

// mediaQUICConfig is the dial config of a media connection: datagrams on
// (mandatory within the media subprotocol — checked after the handshake),
// the in-call idle/keepalive pair, and the inbound message-stream cap.
func mediaQUICConfig() *quicgo.Config {
	return &quicgo.Config{
		MaxIdleTimeout:        mediaIdleTimeout,
		KeepAlivePeriod:       mediaKeepAlive,
		EnableDatagrams:       true,
		MaxIncomingUniStreams: maxMediaUniStreams,
	}
}

// OpenMedia opens a media session to remoteID at addr — normally the observed
// address of the live overlay edge to that peer, so the new connection rides
// the proven path and reuses its NAT mapping (same socket, same 4-tuple). The
// cost is one QUIC handshake RTT. An older peer that does not speak the media
// protocol (or negotiated no datagram support) is ErrMediaUnsupported; the
// overlay edge to it is unaffected.
func (t *quicTransport) OpenMedia(ctx context.Context, remoteID kad.ID, addr transport.Addr) (transport.MediaSession, error) {
	uaddr, err := net.ResolveUDPAddr("udp", addr.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("%w: resolve %s: %v", transport.ErrNoRoute, addr.Endpoint, err)
	}
	qconn, err := t.tr.Dial(ctx, uaddr, t.mediaTLS, t.mediaQConf)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var te *quicgo.TransportError
		if errors.As(err, &te) && te.ErrorCode == cryptoErrNoALPN {
			return nil, transport.ErrMediaUnsupported
		}
		return nil, fmt.Errorf("%w: media dial %s: %v", transport.ErrNoRoute, addr.Endpoint, err)
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
	// Level-1 of the media subprotocol: datagrams are mandatory. A peer that
	// negotiated the media ALPN without them is excluded from media (not from
	// the network).
	if !qconn.ConnectionState().SupportsDatagrams.Remote {
		_ = qconn.CloseWithError(appCodeMediaRefused, "media requires datagram support")
		return nil, transport.ErrMediaUnsupported
	}

	s := newMediaSession(t, remote, qconn, nil)
	if !t.registerMediaSession(s) {
		_ = qconn.CloseWithError(appCodeNormal, "")
		return nil, transport.ErrConnClosed
	}
	s.start()
	return s, nil
}

// InboundMedia surfaces media sessions peers opened to this node,
// authenticated but unvetted (admission is the node layer's job). Closed by
// Close.
func (t *quicTransport) InboundMedia() <-chan transport.MediaSession { return t.inMedia }

// handleAcceptedMedia vets an inbound media connection (identity, mandatory
// datagram support), registers the session and announces it on InboundMedia.
// It owns release — the inbound-admission slot — and hands it to the session,
// which releases it when it ends; every refusal path releases it here.
func (t *quicTransport) handleAcceptedMedia(qconn *quicgo.Conn, release func()) {
	refuse := func(code quicgo.ApplicationErrorCode, msg string) {
		_ = qconn.CloseWithError(code, msg)
		release()
	}
	remote, err := peerIDFromConn(qconn.ConnectionState().TLS)
	if err != nil {
		refuse(appCodeNormal, "")
		return
	}
	if !qconn.ConnectionState().SupportsDatagrams.Remote {
		refuse(appCodeMediaRefused, "media requires datagram support")
		return
	}
	s := newMediaSession(t, remote, qconn, release)
	if !t.registerMediaSession(s) {
		refuse(appCodeNormal, "")
		return
	}
	s.start()
	select {
	case t.inMedia <- s:
	default:
		// Nobody is consuming inbound sessions; refuse rather than queue
		// unboundedly. Close releases the admission slot and unregisters; the
		// just-started goroutines observe the closed connection and unwind.
		_ = s.Close()
	}
}

// registerMediaSession tracks s for Close teardown and reserves the WaitGroup
// slots for its three goroutines atomically with the closed check, mirroring
// registerConn: the Add either strictly precedes Close's Wait (Close finds and
// ends this session, the goroutines observe it and Done) or registration is
// refused and nothing starts. It reports false if the transport is already
// closed. On true the caller MUST call s.start() so the reserved slots are
// matched by running goroutines.
func (t *quicTransport) registerMediaSession(s *mediaSession) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return false
	}
	t.mediaSess[s] = struct{}{}
	// Three goroutines for every session (pump, datagram-rx, stream-rx), plus a
	// fourth idle reaper for an ACCEPTED session — its effective QUIC idle is the
	// min of both ends, so it needs a local liveness backstop independent of the
	// peer's advertised value. A dialed session uses our own short media idle, so
	// it needs none.
	if s.accepted() {
		t.wg.Add(4)
	} else {
		t.wg.Add(3)
	}
	return true
}

// removeMediaSession drops s from the tracking set (called from its Close).
func (t *quicTransport) removeMediaSession(s *mediaSession) {
	t.mu.Lock()
	if t.mediaSess != nil {
		delete(t.mediaSess, s)
	}
	t.mu.Unlock()
}

var _ transport.MediaSession = (*mediaSession)(nil)

// mediaSession is one live media connection. Three goroutines run it — the
// datagram pump (tx-ring → connection), the datagram receive loop and the
// message-stream accept loop (plus a short-lived reader per inbound message) —
// all of which unwind when the connection dies, however it dies: Close, the
// peer's close, or path death via the in-call idle timeout. Reception flows
// into the session's own bounded channels, never the transport's Inbound.
type mediaSession struct {
	owner  *quicTransport
	remote kad.ID
	raddr  transport.Addr
	qconn  *quicgo.Conn

	txRing    chan *transport.Packet // encoded media frames awaiting the pump; cap MediaTxRing
	datagrams chan transport.MediaDatagram
	messages  chan transport.MediaMessage

	// txMu guards txClosed; SendDatagram holds RLock across its (non-blocking)
	// enqueue so the pump's shutdown drain — which sets txClosed under the
	// write lock first — can never leave a sender's packet stranded in the
	// ring unreleased.
	txMu     sync.RWMutex
	txClosed bool

	rxBytes transport.TokenBucket // level-2 receive budget: bytes
	rxPPS   transport.TokenBucket // level-2 receive budget: packets
	stats   transport.MediaCounters

	// lastRx is the Unix-nano time of the last frame received from the peer; an
	// accepted session's idle reaper closes it when no frame arrives within
	// mediaIdleTimeout. It exists because the effective QUIC idle of an ACCEPTED
	// session is the min of both ends' advertised timeouts, so a hostile dialer that
	// advertises a long (or disabled) idle could otherwise park an accepted session
	// far past the media budget. The reaper is a local backstop that does not trust
	// the peer's advertised value.
	lastRx atomic.Int64

	msgWG sync.WaitGroup // in-flight message readers; the accept loop drains it before closing messages

	releaseInbound func() // inbound-admission slot for an accepted session; nil when dialed

	closeOnce sync.Once
	closedCh  chan struct{}
}

func newMediaSession(owner *quicTransport, remote kad.ID, qconn *quicgo.Conn, release func()) *mediaSession {
	return &mediaSession{
		owner:          owner,
		remote:         remote,
		raddr:          addrFromNet(qconn.RemoteAddr()),
		qconn:          qconn,
		txRing:         make(chan *transport.Packet, transport.MediaTxRing),
		datagrams:      make(chan transport.MediaDatagram, transport.MediaDatagramQueue),
		messages:       make(chan transport.MediaMessage, transport.MediaMessageQueue),
		releaseInbound: release,
		closedCh:       make(chan struct{}),
	}
}

// accepted reports whether this session was accepted from a peer's dial (it holds
// an inbound-admission slot) rather than dialed by us.
func (s *mediaSession) accepted() bool { return s.releaseInbound != nil }

// start launches the session's goroutines, pairing the wg slots
// registerMediaSession reserved. It must follow a successful registration. An
// accepted session also runs an idle reaper (see idleReap).
func (s *mediaSession) start() {
	s.lastRx.Store(time.Now().UnixNano())
	go func() { defer s.owner.wg.Done(); s.pump() }()
	go func() { defer s.owner.wg.Done(); s.rxDatagrams() }()
	go func() { defer s.owner.wg.Done(); s.rxStreams() }()
	if s.accepted() {
		go func() { defer s.owner.wg.Done(); s.idleReap() }()
	}
}

// idleReap closes an accepted session whose peer has gone silent for longer than
// mediaIdleTimeout — a local liveness backstop that does not trust the dialer's
// advertised QUIC idle. The receive loops stamp lastRx on every frame, so a real
// call (which carries frames) is never reaped; only a session whose peer stops
// sending — a hostile dialer parking a slot, or a dead path — is closed. It checks
// twice per idle window and exits when the session closes.
func (s *mediaSession) idleReap() {
	t := time.NewTicker(mediaIdleTimeout / 2)
	defer t.Stop()
	for {
		select {
		case <-s.closedCh:
			return
		case now := <-t.C:
			if now.UnixNano()-s.lastRx.Load() > mediaIdleTimeout.Nanoseconds() {
				_ = s.Close()
				return
			}
		}
	}
}

func (s *mediaSession) Remote() kad.ID                            { return s.remote }
func (s *mediaSession) RemoteAddr() transport.Addr                { return s.raddr }
func (s *mediaSession) Closed() <-chan struct{}                   { return s.closedCh }
func (s *mediaSession) Stats() transport.MediaStats               { return s.stats.Snapshot() }
func (s *mediaSession) Datagrams() <-chan transport.MediaDatagram { return s.datagrams }
func (s *mediaSession) Messages() <-chan transport.MediaMessage   { return s.messages }

// Close ends the session: the connection closes (the peer and the receive
// loops observe it), the inbound-admission slot frees, and the transport
// forgets the session. Idempotent. It never touches overlay edges.
func (s *mediaSession) Close() error {
	s.closeOnce.Do(func() {
		close(s.closedCh)
		_ = s.qconn.CloseWithError(appCodeNormal, "")
		s.owner.removeMediaSession(s)
		if s.releaseInbound != nil {
			s.releaseInbound()
		}
	})
	return nil
}

// SendDatagram copies ch|payload into a media-class pooled buffer and queues
// it on the tx-ring — never blocking: quic-go's own SendDatagram parks the
// caller when its internal queue fills, so the pump absorbs that and a full
// ring here refuses with ErrMediaBackpressure, the earliest congestion signal.
// It BORROWS p. Reserved channels and oversized payloads panic (programmer
// errors, per the MediaSession contract).
func (s *mediaSession) SendDatagram(ch uint8, p *transport.Packet) error {
	if ch < transport.FirstAppChannel {
		panic("quic: SendDatagram on a reserved media channel")
	}
	if p.Len() > transport.MaxMediaDatagram {
		panic("quic: SendDatagram payload exceeds MaxMediaDatagram")
	}
	select {
	case <-s.closedCh:
		return transport.ErrMediaClosed
	default:
	}
	// Refuse a full ring early, before the pool round-trip and frame copy: a frame the
	// ring rejects is wasted work on the congestion-refusal path. The guarded enqueue
	// below stays authoritative for racing senders (one may fill the ring between this
	// check and the send).
	if len(s.txRing) == cap(s.txRing) {
		s.stats.TxDroppedQueue.Add(1)
		return transport.ErrMediaBackpressure
	}
	q := transport.GetMedia()
	n, err := transport.PutMediaFrame(q.Buf(), ch, p.Bytes())
	if err != nil {
		q.Release()
		return err // unreachable: 1 + MaxMediaDatagram fits the media class
	}
	q.SetLen(n)
	// The enqueue holds txMu so it cannot race the pump's final drain: a
	// sender either lands the packet before txClosed is set (the drain will
	// release it) or observes txClosed and keeps ownership — nothing can
	// strand a pooled buffer in the ring forever. Same discipline as the
	// receive side's rxMu.
	s.txMu.RLock()
	if s.txClosed {
		s.txMu.RUnlock()
		q.Release()
		return transport.ErrMediaClosed
	}
	select {
	case s.txRing <- q:
		s.txMu.RUnlock()
		s.stats.TxDatagrams.Add(1)
		return nil
	default:
		s.txMu.RUnlock()
		q.Release()
		s.stats.TxDroppedQueue.Add(1)
		return transport.ErrMediaBackpressure
	}
}

// pump drains the tx-ring into the connection. A send error NEVER closes the
// session: a datagram that no longer fits (the path MTU shrank) or hits a
// transient error is dropped and counted, and a dead connection is the receive
// loops' signal to end the session — the pump just keeps draining until then.
// On session end it shuts the ring for writers (txClosed under the write lock)
// before the final drain, so every packet ever enqueued is either sent or
// released here.
func (s *mediaSession) pump() {
	for {
		select {
		case <-s.closedCh:
			s.txMu.Lock()
			s.txClosed = true
			s.txMu.Unlock()
			for {
				select {
				case q := <-s.txRing:
					q.Release()
				default:
					return
				}
			}
		case q := <-s.txRing:
			err := s.qconn.SendDatagram(q.Bytes())
			q.Release()
			if err != nil {
				s.stats.TxDroppedSend.Add(1)
			}
		}
	}
}

// SendMessage sends one reliable message as one short-lived unidirectional
// stream. It blocks while the path accepts bytes, bounded by the stall rule:
// a stream open or write that cannot progress within mediaStreamStall resets
// THIS stream and returns ErrMediaBackpressure (the message is abandoned, the
// session lives); cancelling ctx resets the stream likewise and returns
// ctx.Err(). It BORROWS p (quic-go's Write consumes the bytes synchronously).
func (s *mediaSession) SendMessage(ctx context.Context, ch uint8, p *transport.Packet) error {
	if ch < transport.FirstAppChannel {
		panic("quic: SendMessage on a reserved media channel")
	}
	select {
	case <-s.closedCh:
		return transport.ErrMediaClosed
	default:
	}

	// A session at its peer-imposed stream limit is congestion like any
	// other: bound the open by the stall rule rather than parking forever.
	octx, ocancel := context.WithTimeout(ctx, mediaStreamStall)
	str, err := s.qconn.OpenUniStreamSync(octx)
	ocancel()
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Classify by the error itself, not by octx.Err() — after ocancel()
		// that is always non-nil. Only an expired stall bound is
		// backpressure; anything else (the connection died) is the session's
		// end.
		if errors.Is(err, context.DeadlineExceeded) {
			s.stats.TxDroppedStall.Add(1)
			return transport.ErrMediaBackpressure
		}
		return transport.ErrMediaClosed
	}

	// ctx cancel = RESET_STREAM: drop the stale frame mid-write.
	stop := context.AfterFunc(ctx, func() { str.CancelWrite(streamCodeCancelled) })
	defer stop()

	_ = str.SetWriteDeadline(time.Now().Add(mediaStreamStall))
	hdr := [1]byte{ch}
	_, err = str.Write(hdr[:])
	if err == nil {
		_, err = str.Write(p.Bytes())
	}
	if err == nil && !stop() {
		// The cancel watcher already fired mid-write: the stream is (being)
		// reset, the message is void even though the writes succeeded.
		err = ctx.Err()
	}
	if err == nil {
		// The payload is fully written and the watcher is disarmed BEFORE the
		// FIN: a cancel arriving after this point must not abort a message
		// this call reports as sent (CancelWrite after Close would abandon
		// its retransmissions).
		err = str.Close() // FIN; QUIC delivers the rest reliably on its own
	}
	if err != nil {
		str.CancelWrite(streamCodeStalled)
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			// Block-then-kill: the path would not take the message within the
			// stall bound; the stream is reset, the session is untouched.
			s.stats.TxDroppedStall.Add(1)
			return transport.ErrMediaBackpressure
		}
		return transport.ErrMediaClosed
	}
	s.stats.TxMessages.Add(1)
	return nil
}

// rxDatagrams is the per-session datagram receive goroutine: it pulls each
// datagram off the connection, stamps RxTime as early as this layer can see it
// (quic-go holds a small internal queue below us — drops there and queueing
// before this stamp are an accepted upstream limitation), charges the level-2
// receive budget BEFORE copying into a pooled buffer, sheds
// consensus-violating frames, and delivers into the bounded Datagrams channel.
// A receive error means the connection is over: it ends the session and drains
// the channel shut.
func (s *mediaSession) rxDatagrams() {
	defer close(s.datagrams)
	for {
		data, err := s.qconn.ReceiveDatagram(s.owner.ctx)
		if err != nil {
			_ = s.Close()
			return
		}
		now := time.Now()
		s.lastRx.Store(now.UnixNano()) // any frame from the peer is a sign of life (idle reaper)
		// level-2 self-protection: bytes+packets budget, charged before the
		// frame costs a pool buffer or a copy.
		if !s.rxPPS.Allow(now, transport.MediaRxPPSRate, transport.MediaRxPPSBurst) ||
			!s.rxBytes.AllowN(now, float64(len(data)), transport.MediaRxBytesRate, transport.MediaRxBytesBurst) {
			s.stats.RxDroppedBudget.Add(1)
			continue
		}
		ch, payload, err := transport.ParseMediaFrame(data)
		// level-2: frames violating the media consensus — no channel byte, a
		// reserved channel, an over-budget payload — are shed and counted.
		if err != nil || ch < transport.FirstAppChannel || len(payload) > transport.MaxMediaDatagram {
			s.stats.RxDroppedReserved.Add(1)
			continue
		}
		q := transport.GetMedia()
		q.SetLen(copy(q.Buf(), payload))
		select {
		case s.datagrams <- transport.MediaDatagram{Channel: ch, RxTime: now, Pkt: q}:
			s.stats.RxDatagrams.Add(1)
		default:
			s.stats.RxDroppedQueue.Add(1)
			q.Release()
		}
	}
}

// rxStreams accepts inbound message streams (one short-lived stream per
// message; concurrency capped by maxMediaUniStreams at the QUIC layer) and
// hands each to a reader. An accept error means the connection is over: the
// loop ends the session, waits out in-flight readers, and drains Messages
// shut.
func (s *mediaSession) rxStreams() {
	defer func() {
		s.msgWG.Wait()
		close(s.messages)
	}()
	for {
		str, err := s.qconn.AcceptUniStream(s.owner.ctx)
		if err != nil {
			_ = s.Close()
			return
		}
		s.lastRx.Store(time.Now().UnixNano()) // a message stream is a sign of life (idle reaper)
		s.msgWG.Go(func() { s.readMessage(str) })
	}
}

// readMessage reads one whole message stream into a pooled Packet and delivers
// it. The level-2 receive budget is charged per stream (a packet) on accept
// and per byte once the size is known; an over-limit, truncated, dribbling or
// budget-refused message is cancelled/dropped and counted — never delivered
// partially.
func (s *mediaSession) readMessage(str *quicgo.ReceiveStream) {
	now := time.Now()
	if !s.rxPPS.Allow(now, transport.MediaRxPPSRate, transport.MediaRxPPSBurst) {
		str.CancelRead(streamCodeStalled)
		s.stats.RxDroppedBudget.Add(1)
		return
	}
	// level-2: a stream may not dribble forever pinning this reader and its
	// pooled buffer.
	_ = str.SetReadDeadline(now.Add(mediaMessageReadBound))

	var hdr [1]byte
	if _, err := io.ReadFull(str, hdr[:]); err != nil {
		// Reset the stream too: without it an empty/aborted stream would keep
		// its flow-control credit until the peer notices on its own.
		str.CancelRead(streamCodeStalled)
		s.stats.RxDroppedMessages.Add(1)
		return
	}
	ch := hdr[0]
	q := transport.Get()
	n, err := readAllInto(str, q.Buf())
	if err != nil {
		// Reset, deadline, oversize (payload past MaxPacketLen) — the message
		// is void; nothing partial is ever delivered.
		str.CancelRead(streamCodeStalled)
		s.stats.RxDroppedMessages.Add(1)
		q.Release()
		return
	}
	if ch < transport.FirstAppChannel {
		s.stats.RxDroppedReserved.Add(1)
		q.Release()
		return
	}
	if !s.rxBytes.AllowN(time.Now(), float64(n+1), transport.MediaRxBytesRate, transport.MediaRxBytesBurst) {
		s.stats.RxDroppedBudget.Add(1)
		q.Release()
		return
	}
	q.SetLen(n)
	select {
	case s.messages <- transport.MediaMessage{Channel: ch, Pkt: q}:
		s.stats.RxMessages.Add(1)
	default:
		s.stats.RxDroppedMessages.Add(1)
		q.Release()
	}
}

// readAllInto reads str to EOF into buf and returns the byte count. A stream
// longer than buf is an error (the protocol caps a message at MaxPacketLen) —
// detected by the read filling buf without reaching EOF.
func readAllInto(str *quicgo.ReceiveStream, buf []byte) (int, error) {
	n := 0
	for {
		m, err := str.Read(buf[n:])
		n += m
		switch {
		case errors.Is(err, io.EOF):
			return n, nil
		case err != nil:
			return 0, err
		case n == len(buf):
			// Full buffer, no EOF yet: either the message is exactly buf-sized
			// (the next read yields no byte, just io.EOF) or it is oversized.
			// The probe's byte count matters: (1, io.EOF) is a legal Read
			// result and means one byte PAST the cap existed — oversized.
			var probe [1]byte
			if m, perr := str.Read(probe[:]); m == 0 && errors.Is(perr, io.EOF) {
				return n, nil
			}
			return 0, errors.New("quic: media message exceeds MaxPacketLen")
		}
	}
}
