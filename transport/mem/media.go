package mem

import (
	"context"
	"sync"
	"time"

	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/transport"
)

var _ transport.Media = (*memTransport)(nil)

const (
	// mediaIdleTimeout mirrors the QUIC media session's idle timeout: a session
	// whose path has gone dark dies within this bound. On a healthy path QUIC's
	// in-call keepalive always beats the idle timer, so idleness there means
	// "the path is dead", and the deterministic mirror of that is a Hub
	// partition outlasting the timeout — traffic-based idleness never fires.
	mediaIdleTimeout = 10 * time.Second

	// inMediaBuffer is the capacity of the inbound-session channel. The node
	// layer consumes it promptly (its admission gate); a full inbox refuses
	// the open, like a busy listener.
	inMediaBuffer = 8
)

// OpenMedia opens a media session to the peer registered at addr — the in-memory
// mirror of dialing a second QUIC connection over the overlay edge's path. The
// same failures apply as Dial's (ErrNoRoute, ErrIdentityMismatch, a partition
// breaking the handshake), plus ErrMediaUnsupported for a peer the test flagged
// media-less (Hub.SetMediaSupport) — the stand-in for an older node without the
// media protocol. The far end surfaces on the peer's InboundMedia, unvetted;
// admission policy is the consumer's job.
func (t *memTransport) OpenMedia(ctx context.Context, remoteID kad.ID, addr transport.Addr) (transport.MediaSession, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	peer, ok := t.hub.lookup(addr)
	if !ok {
		return nil, transport.ErrNoRoute
	}
	if peer.id != remoteID {
		return nil, transport.ErrIdentityMismatch
	}
	if t.hub.isBlocked(t.id, remoteID) {
		return nil, transport.ErrNoRoute
	}
	if !t.hub.mediaSupported(remoteID) {
		return nil, transport.ErrMediaUnsupported
	}

	e := &edge{closed: make(chan struct{})}
	near := newMemMediaSession(t, peer.id, peer.addr, e)
	far := newMemMediaSession(peer, t.id, t.addr, e)
	near.peer, far.peer = far, near

	if !t.addMediaSession(near) {
		return nil, transport.ErrConnClosed
	}
	if !peer.addMediaSession(far) {
		// The peer transport closed mid-open: undo near's registration (its
		// pump never starts, so nothing else would) and fail like a dial into
		// a closing peer.
		t.removeMediaSession(near)
		e.close()
		return nil, transport.ErrNoRoute
	}
	// Engines start once both ends are registered, so a Close racing this open
	// finds the sessions in the tables and the pumps observe the already-closed
	// edge and unwind at once (deregistering both ends as they go).
	near.start(true)
	far.start(false)
	if err := peer.deliverMedia(far); err != nil {
		// Nobody is consuming the peer's inbound sessions. Mirror the QUIC
		// transport exactly: there the dialer's handshake has already
		// succeeded by the time the acceptor refuses, so the open SUCCEEDS
		// and the session dies at once — the caller observes Closed().
		e.close()
	}
	return near, nil
}

// InboundMedia surfaces sessions peers opened to this transport. Closed by Close.
func (t *memTransport) InboundMedia() <-chan transport.MediaSession { return t.inMedia }

// addMediaSession tracks a session end for Close teardown; it reports false if
// the transport is already closed.
func (t *memTransport) addMediaSession(s *memMediaSession) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return false
	}
	t.media = append(t.media, s)
	return true
}

// removeMediaSession forgets a finished session (called from its pump's
// shutdown), keeping the tracking slice bounded over a transport's life.
func (t *memTransport) removeMediaSession(s *memMediaSession) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i, cur := range t.media {
		if cur == s {
			t.media[i] = t.media[len(t.media)-1]
			t.media = t.media[:len(t.media)-1]
			return
		}
	}
}

// deliverMedia announces an inbound session end on this transport's
// InboundMedia channel. Non-blocking: a full inbox means nobody is consuming
// inbound sessions here, so the open is refused rather than queued unboundedly.
func (t *memTransport) deliverMedia(s *memMediaSession) error {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.closed {
		return transport.ErrConnClosed
	}
	select {
	case t.inMedia <- s:
		return nil
	default:
		return transport.ErrNoRoute
	}
}

var _ transport.MediaSession = (*memMediaSession)(nil)

// plannedFrame is one datagram the link model already judged: the encoded
// frame, the absolute instant the link delivers it (shaper backlog +
// transmission time + jitter, fixed at send time — the moment the frame
// reached the bottleneck queue), and the link model that judged it. Capturing the
// model here pins the frame to the profile in force at send time, so a
// SetLinkProfile between send and delivery cannot retroactively re-judge a frame
// already in flight (and the pump needs no second Hub-lock to re-fetch it).
type plannedFrame struct {
	pkt   *transport.Packet
	at    time.Time
	model *linkModel
}

// memMediaSession is one end of a paired in-memory media session — the
// deterministic mirror of a QUIC media connection. Both ends share one edge,
// so either end's Close (or the idle watchdog) ends the session for both.
//
// The send side mirrors QUIC's exactly: SendDatagram copies into a bounded
// tx-ring (full ring → ErrMediaBackpressure), runs the datagram through the
// directed link model (Hub.SetLinkProfile) — loss, jitter, reorder, shaper
// queue, MTU — and a pump goroutine delivers survivors at their planned
// instants. The receive side charges the level-2 receive budget BEFORE
// accepting a frame, drops reserved channels, stamps RxTime at the moment the
// frame crosses, and delivers into the bounded Datagrams/Messages channels
// (overflow drops the newest and counts it). Messages bypass the link model:
// they are reliable, so the QUIC transport would retransmit them through loss
// and short outages — the mirror just delivers them.
type memMediaSession struct {
	owner      *memTransport
	remote     kad.ID
	remoteAddr transport.Addr
	peer       *memMediaSession
	edge       *edge

	txRing    chan plannedFrame // planned frames awaiting delivery; cap MediaTxRing
	datagrams chan transport.MediaDatagram
	messages  chan transport.MediaMessage

	rxBytes transport.TokenBucket // level-2 receive budget: bytes
	rxPPS   transport.TokenBucket // level-2 receive budget: packets
	stats   transport.MediaCounters

	// rxMu guards rxClosed; writers into the receive channels hold RLock across
	// the (non-blocking) send so the pump's shutdown cannot close a channel
	// underneath them — the same discipline as memTransport.deliver. txMu
	// guards txClosed the same way for the tx-ring, so a sender's packet can
	// never land in the ring after the shutdown drain and sit there
	// unreleased.
	rxMu     sync.RWMutex
	rxClosed bool
	txMu     sync.RWMutex
	txClosed bool

	// Reorder bookkeeping, owned by the pump goroutine alone: the running
	// datagram count toward the next hold, the held-back frame, and how many
	// deliveries it still waits out.
	reorderSeq int
	held       *transport.Packet
	heldWait   int
}

func newMemMediaSession(owner *memTransport, remote kad.ID, remoteAddr transport.Addr, e *edge) *memMediaSession {
	return &memMediaSession{
		owner:      owner,
		remote:     remote,
		remoteAddr: remoteAddr,
		edge:       e,
		txRing:     make(chan plannedFrame, transport.MediaTxRing),
		datagrams:  make(chan transport.MediaDatagram, transport.MediaDatagramQueue),
		messages:   make(chan transport.MediaMessage, transport.MediaMessageQueue),
	}
}

// start launches this end's pump; the dialing end also hosts the pair's idle
// watchdog (one per session is enough — it closes the shared edge).
func (s *memMediaSession) start(watch bool) {
	go s.pump()
	if watch {
		go s.idleWatch()
	}
}

func (s *memMediaSession) Remote() kad.ID              { return s.remote }
func (s *memMediaSession) RemoteAddr() transport.Addr  { return s.remoteAddr }
func (s *memMediaSession) Closed() <-chan struct{}     { return s.edge.closed }
func (s *memMediaSession) Stats() transport.MediaStats { return s.stats.Snapshot() }
func (s *memMediaSession) Datagrams() <-chan transport.MediaDatagram {
	return s.datagrams
}
func (s *memMediaSession) Messages() <-chan transport.MediaMessage { return s.messages }

// Close ends the session for both ends. Idempotent; never touches overlay edges.
func (s *memMediaSession) Close() error {
	s.edge.close()
	return nil
}

// SendDatagram copies ch|payload into a media-class pooled buffer, runs it
// through the directed link model AT SEND TIME — the moment the frame reaches
// the path's bottleneck queue, so shaper backlog (bufferbloat) accumulates
// across a burst the way a real router queue does — and queues the survivor on
// the tx-ring with its planned delivery instant. Never blocking: a full ring
// refuses with ErrMediaBackpressure and counts the drop. It BORROWS p (the
// caller still owns and Releases it). A frame the model refuses is not an
// error: an over-MTU refusal is counted in TxDroppedSend (the mirror of the
// QUIC stack refusing a datagram after the path MTU shrank — a send error
// never closes the session and never surfaces to the caller), and network
// loss/queue overflow is silent, as on a real path. Reserved channels and
// oversized payloads are programmer errors and panic, per the MediaSession
// contract.
func (s *memMediaSession) SendDatagram(ch uint8, p *transport.Packet) error {
	if ch < transport.FirstAppChannel {
		panic("mem: SendDatagram on a reserved media channel")
	}
	if p.Len() > transport.MaxMediaDatagram {
		panic("mem: SendDatagram payload exceeds MaxMediaDatagram")
	}
	select {
	case <-s.edge.closed:
		return transport.ErrMediaClosed
	default:
	}
	// Refuse a full ring BEFORE the link model is consulted: a frame the ring
	// rejects never reaches the modelled bottleneck, so it must not consume
	// shaper backlog or PRNG draws. (Racing senders can still slip past this
	// into the guarded refusal below — that residue charges the model once,
	// an accepted inexactness of the mirror.)
	if len(s.txRing) == cap(s.txRing) {
		s.stats.TxDroppedQueue.Add(1)
		return transport.ErrMediaBackpressure
	}

	now := time.Now()
	at := now
	model := s.owner.hub.link(s.owner.id, s.remote)
	if model != nil {
		verdict, delay := model.plan(now, transport.MediaFrameLen(p.Len()))
		switch verdict {
		case linkDropMTU:
			s.stats.TxDatagrams.Add(1)
			s.stats.TxDroppedSend.Add(1)
			return nil
		case linkDropNet:
			s.stats.TxDatagrams.Add(1)
			return nil
		}
		at = now.Add(delay)
	}

	q := transport.GetMedia()
	n, err := transport.PutMediaFrame(q.Buf(), ch, p.Bytes())
	if err != nil {
		q.Release()
		return err // unreachable: 1 + MaxMediaDatagram fits the media class
	}
	q.SetLen(n)
	// The enqueue holds txMu so it cannot race the pump's final drain — a
	// packet either lands before txClosed (the drain releases it) or the
	// sender keeps ownership. Same discipline as the receive side's rxMu.
	s.txMu.RLock()
	if s.txClosed {
		s.txMu.RUnlock()
		q.Release()
		return transport.ErrMediaClosed
	}
	select {
	case s.txRing <- plannedFrame{pkt: q, at: at, model: model}:
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

// SendMessage delivers one reliable message to the peer end. It BORROWS p. The
// link model does not apply (reliability would retransmit through loss), and a
// partition does not stop it (in-flight reliable data survives a short outage;
// a long one kills the session by idle) — so the mirror stays simple and the
// determinism lives where tests need it, on the datagram path.
func (s *memMediaSession) SendMessage(ctx context.Context, ch uint8, p *transport.Packet) error {
	if ch < transport.FirstAppChannel {
		panic("mem: SendMessage on a reserved media channel")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-s.edge.closed:
		return transport.ErrMediaClosed
	default:
	}
	q := transport.Get()
	q.SetLen(copy(q.Buf(), p.Bytes()))
	s.stats.TxMessages.Add(1)
	s.peer.receiveMessage(ch, q)
	return nil
}

// pump drains the tx-ring in order and delivers each planned frame at its
// planned instant (one timer, reused across frames — Go 1.23+ timers make the
// bare Reset race-free). On session end it performs this end's receive
// shutdown: marks the receive side closed (under the write lock, so no writer
// is mid-send), closes the channels, and releases everything still queued on
// the send side.
func (s *memMediaSession) pump() {
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	for {
		select {
		case <-s.edge.closed:
			s.shutdownRx()
			return
		case f := <-s.txRing:
			s.pumpDatagram(f, timer)
		}
	}
}

// pumpDatagram finishes one planned frame's journey: sleep until its planned
// delivery instant (the link delivers serially, so order is preserved even
// when jitter shrinks a later frame's delay), check the partition — a frame in
// flight when the path goes dark vanishes — apply explicit reordering, and
// hand the survivor to the peer's receive gate.
func (s *memMediaSession) pumpDatagram(f plannedFrame, timer *time.Timer) {
	if delay := time.Until(f.at); delay > 0 {
		timer.Reset(delay)
		select {
		case <-timer.C:
		case <-s.edge.closed:
			timer.Stop()
			f.pkt.Release()
			return
		}
	}
	// A partition blackholes the media path exactly like the overlay's frames:
	// the bytes vanish, and only the idle watchdog eventually notices.
	if s.owner.hub.isBlocked(s.owner.id, s.remote) {
		f.pkt.Release()
		return
	}

	// Explicit reordering: every ReorderEvery-th frame is parked and released
	// only after ReorderHold later frames have gone by — "held back for N
	// deliveries". One frame parks at a time; a trigger while one is parked
	// just delivers normally.
	// Use the model captured at send time, not whatever is installed now: a
	// SetLinkProfile after this frame was planned must not re-judge it (and reading
	// f.model needs no second Hub-lock per datagram).
	var profile LinkProfile
	if f.model != nil {
		profile = f.model.profile // immutable after construction
	}
	if profile.ReorderEvery > 0 {
		s.reorderSeq++
		if s.held == nil && s.reorderSeq%profile.ReorderEvery == 0 {
			s.held, s.heldWait = f.pkt, profile.ReorderHold
			return
		}
	}
	s.peer.receiveDatagram(f.pkt)
	if s.held != nil {
		if s.heldWait--; s.heldWait <= 0 {
			held := s.held
			s.held = nil
			s.peer.receiveDatagram(held)
		}
	}
}

// receiveDatagram is the receiving end's gate, run on the sender's pump
// goroutine at the moment the frame crosses the link. Order mirrors the QUIC
// session: the level-2 receive budget is charged before anything else is spent
// on the frame, reserved channels are shed, and the bounded queue drops the
// newest on overflow — every shed visible in a counter. It owns q.
func (s *memMediaSession) receiveDatagram(q *transport.Packet) {
	now := time.Now()
	// level-2 self-protection: the receive budget (bytes + packets) is charged
	// before the frame costs this end anything further; a flooding peer is
	// shed here, counted.
	if !s.rxPPS.Allow(now, transport.MediaRxPPSRate, transport.MediaRxPPSBurst) ||
		!s.rxBytes.AllowN(now, float64(q.Len()), transport.MediaRxBytesRate, transport.MediaRxBytesBurst) {
		s.stats.RxDroppedBudget.Add(1)
		q.Release()
		return
	}
	// level-2: consensus-violating frames — malformed (no channel byte) or on
	// a reserved channel — are shed and counted, never delivered. Matches the
	// QUIC session's gate, counter for counter.
	ch, payload, err := transport.ParseMediaFrame(q.Bytes())
	if err != nil || ch < transport.FirstAppChannel {
		s.stats.RxDroppedReserved.Add(1)
		q.Release()
		return
	}
	// Slide the payload to the buffer head so the delivered Packet holds the
	// payload alone (the channel travels beside it in MediaDatagram).
	copy(q.Buf(), payload)
	q.SetLen(len(payload))

	s.rxMu.RLock()
	if s.rxClosed {
		s.rxMu.RUnlock()
		q.Release()
		return
	}
	select {
	case s.datagrams <- transport.MediaDatagram{Channel: ch, RxTime: now, Pkt: q}:
		s.rxMu.RUnlock()
		s.stats.RxDatagrams.Add(1)
	default:
		s.rxMu.RUnlock()
		s.stats.RxDroppedQueue.Add(1)
		q.Release()
	}
}

// receiveMessage is the message mirror of receiveDatagram, gate for gate in
// the QUIC session's order: the packet budget at arrival, the reserved check
// (defensive — the send side already panics), the byte budget once the size
// is known, the bounded queue. It owns q.
func (s *memMediaSession) receiveMessage(ch uint8, q *transport.Packet) {
	now := time.Now()
	if !s.rxPPS.Allow(now, transport.MediaRxPPSRate, transport.MediaRxPPSBurst) {
		s.stats.RxDroppedBudget.Add(1)
		q.Release()
		return
	}
	if ch < transport.FirstAppChannel {
		s.stats.RxDroppedReserved.Add(1)
		q.Release()
		return
	}
	if !s.rxBytes.AllowN(now, float64(q.Len()), transport.MediaRxBytesRate, transport.MediaRxBytesBurst) {
		s.stats.RxDroppedBudget.Add(1)
		q.Release()
		return
	}
	s.rxMu.RLock()
	if s.rxClosed {
		s.rxMu.RUnlock()
		q.Release()
		return
	}
	select {
	case s.messages <- transport.MediaMessage{Channel: ch, Pkt: q}:
		s.rxMu.RUnlock()
		s.stats.RxMessages.Add(1)
	default:
		s.rxMu.RUnlock()
		s.stats.RxDroppedMessages.Add(1)
		q.Release()
	}
}

// shutdownRx finishes this end: no more deliveries (rxClosed under the write
// lock drains any in-flight writer first), channels drain shut so the owner
// observes the end, the tx-ring is shut for senders (txClosed) and drained
// back to the pool, and the owner transport forgets the session.
func (s *memMediaSession) shutdownRx() {
	s.rxMu.Lock()
	s.rxClosed = true
	s.rxMu.Unlock()
	close(s.datagrams)
	close(s.messages)
	if s.held != nil {
		s.held.Release()
		s.held = nil
	}
	s.txMu.Lock()
	s.txClosed = true
	s.txMu.Unlock()
	for {
		select {
		case f := <-s.txRing:
			f.pkt.Release()
		default:
			s.owner.removeMediaSession(s)
			return
		}
	}
}

// idleWatch closes the session once its path has been dark for
// mediaIdleTimeout — the deterministic mirror of QUIC's keepalive/idle pair.
// On a real session the 3 s in-call keepalive always beats the 10 s idle
// timer while the path works, so idle death means path death; here "the path
// is dead" is precisely a Hub partition, so the watchdog measures how long the
// pair has stayed partitioned. Traffic refreshes nothing: a healthy path never
// idles out, a dead one cannot be refreshed.
func (s *memMediaSession) idleWatch() {
	tick := time.NewTicker(mediaIdleTimeout / 4)
	defer tick.Stop()
	var darkSince time.Time
	for {
		select {
		case <-s.edge.closed:
			return
		case <-tick.C:
			if !s.owner.hub.isBlocked(s.owner.id, s.remote) {
				darkSince = time.Time{}
				continue
			}
			if darkSince.IsZero() {
				darkSince = time.Now()
				continue
			}
			if time.Since(darkSince) >= mediaIdleTimeout {
				s.edge.close()
				return
			}
		}
	}
}
