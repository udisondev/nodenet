package quic

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"testing"
	"time"

	quicgo "github.com/quic-go/quic-go"
	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/transport/transporttest"
	"github.com/udisondev/nodenet/wire"
)

// mustUDP binds a loopback UDP socket for a raw listener.
func mustUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc
}

// sendTestFrame sends one wire frame (the contract suite's test type) on an
// overlay edge.
func sendTestFrame(t *testing.T, conn transport.Conn, payload []byte) {
	t.Helper()
	p := transport.Get()
	defer p.Release()
	frame, err := wire.EncodeFrame(p.Buf(), transporttest.TestType, payload)
	if err != nil {
		t.Fatalf("EncodeFrame: %v", err)
	}
	p.SetLen(len(frame))
	if err := conn.Send(p); err != nil {
		t.Fatalf("Send: %v", err)
	}
}

// listenLoopback brings up a transport on 127.0.0.1 and closes it at test end.
func listenLoopback(t *testing.T, id *identity.Identity, opts ...Option) transport.Transport {
	t.Helper()
	tr, err := Listen(id, "127.0.0.1:0", opts...)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	return tr
}

// mediaPair opens a media session between two loopback transports and returns
// both ends (near = dialer's).
func mediaPair(t *testing.T) (near, far transport.MediaSession) {
	t.Helper()
	a := listenLoopback(t, idFromByte(1))
	b := listenLoopback(t, idFromByte(2))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	near, err := a.(transport.Media).OpenMedia(ctx, idFromByte(2).ID(), b.LocalAddr())
	if err != nil {
		t.Fatalf("OpenMedia: %v", err)
	}
	select {
	case far = <-b.(transport.Media).InboundMedia():
	case <-ctx.Done():
		t.Fatal("no inbound media session surfaced")
	}
	return near, far
}

// A media session moves datagrams and messages both ways over a real QUIC
// connection, each frame channel-tagged, datagrams RxTime-stamped — and the
// peers authenticate to their NodeIDs exactly like overlay edges.
func TestMediaExchangeQUIC(t *testing.T) {
	near, far := mediaPair(t)
	defer near.Close()

	if near.Remote() != idFromByte(2).ID() || far.Remote() != idFromByte(1).ID() {
		t.Fatalf("session identities wrong: near→%v far→%v", near.Remote(), far.Remote())
	}

	// Datagram near→far. Datagrams are unreliable, so retry a few: the very
	// first ones can race the handshake's datagram-support flush.
	p := transport.GetMedia()
	p.SetLen(copy(p.Buf(), []byte("voice")))
	got := []byte(nil)
	var ch uint8
	var rx time.Time
	deadline := time.After(5 * time.Second)
loop:
	for {
		if err := near.SendDatagram(17, p); err != nil {
			t.Fatalf("SendDatagram: %v", err)
		}
		select {
		case d, ok := <-far.Datagrams():
			if !ok {
				t.Fatal("far Datagrams drained shut")
			}
			got = append(got[:0], d.Pkt.Bytes()...)
			ch, rx = d.Channel, d.RxTime
			d.Pkt.Release()
			break loop
		case <-time.After(50 * time.Millisecond):
		case <-deadline:
			t.Fatal("datagram never arrived")
		}
	}
	p.Release()
	if string(got) != "voice" || ch != 17 {
		t.Errorf("far got (ch %d, %q), want (17, voice)", ch, got)
	}
	if rx.IsZero() {
		t.Error("RxTime not stamped")
	}

	// Message far→near (reliable, no retry needed).
	m := transport.Get()
	m.SetLen(copy(m.Buf(), []byte("keyframe-bytes")))
	if err := far.SendMessage(context.Background(), 20, m); err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	m.Release()
	select {
	case msg, ok := <-near.Messages():
		if !ok {
			t.Fatal("near Messages drained shut")
		}
		if msg.Channel != 20 || string(msg.Pkt.Bytes()) != "keyframe-bytes" {
			t.Errorf("message = (ch %d, %q), want (20, keyframe-bytes)", msg.Channel, msg.Pkt.Bytes())
		}
		msg.Pkt.Release()
	case <-time.After(5 * time.Second):
		t.Fatal("message never arrived")
	}

	if st := far.Stats(); st.RxDatagrams == 0 {
		t.Errorf("far RxDatagrams = 0, want > 0")
	}
	if st := near.Stats(); st.RxMessages != 1 {
		t.Errorf("near RxMessages = %d, want 1", st.RxMessages)
	}

	// The retry loop may have landed duplicate datagrams; the receiver owns
	// and Releases everything delivered.
	near.Close()
	for d := range far.Datagrams() {
		d.Pkt.Release()
	}
}

// An older peer whose listener never advertises the media protocol refuses the
// media dial with ErrMediaUnsupported — and its overlay edge keeps working.
func TestMediaUnsupportedOldPeer(t *testing.T) {
	a := listenLoopback(t, idFromByte(1))

	// An "old" listener: same identity machinery, overlay ALPN only — what a
	// pre-media nodenet node advertises.
	oldID := idFromByte(2)
	cert, err := buildCert(oldID, rand.Reader)
	if err != nil {
		t.Fatalf("buildCert: %v", err)
	}
	raw := &quicgo.Transport{Conn: mustUDP(t)}
	defer raw.Close()
	ln, err := raw.Listen(tlsConfig(cert), &quicgo.Config{})
	if err != nil {
		t.Fatalf("raw Listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			if _, err := ln.Accept(context.Background()); err != nil {
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addr := transport.Addr{Net: "quic", Endpoint: ln.Addr().String()}
	_, err = a.(transport.Media).OpenMedia(ctx, oldID.ID(), addr)
	if !errors.Is(err, transport.ErrMediaUnsupported) {
		t.Fatalf("OpenMedia to an overlay-only peer: err = %v, want ErrMediaUnsupported", err)
	}

	// The overlay plane is untouched: a normal edge to the old peer works.
	conn, err := a.Dial(ctx, oldID.ID(), addr)
	if err != nil {
		t.Fatalf("overlay Dial to the old peer: %v", err)
	}
	_ = conn.Close()
}

// Closing one end ends the session for both: Closed fires, sends refuse with
// ErrMediaClosed, receive channels drain shut — and the overlay edge between
// the same two nodes is untouched (separate fates).
func TestMediaClosePropagatesQUIC(t *testing.T) {
	a := listenLoopback(t, idFromByte(1))
	b := listenLoopback(t, idFromByte(2))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	edge, err := a.Dial(ctx, idFromByte(2).ID(), b.LocalAddr())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	near, err := a.(transport.Media).OpenMedia(ctx, idFromByte(2).ID(), b.LocalAddr())
	if err != nil {
		t.Fatalf("OpenMedia: %v", err)
	}
	far := <-b.(transport.Media).InboundMedia()

	_ = near.Close()
	select {
	case <-far.Closed():
	case <-time.After(5 * time.Second):
		t.Fatal("far Closed() never fired after near.Close")
	}
	if _, ok := <-far.Datagrams(); ok {
		t.Error("far Datagrams delivered after close, want drained shut")
	}
	if _, ok := <-far.Messages(); ok {
		t.Error("far Messages delivered after close, want drained shut")
	}
	p := transport.GetMedia()
	defer p.Release()
	p.SetLen(1)
	if err := far.SendDatagram(16, p); !errors.Is(err, transport.ErrMediaClosed) {
		t.Errorf("SendDatagram after close: err = %v, want ErrMediaClosed", err)
	}

	// Separate fates: the overlay edge still moves frames after the call died.
	sendTestFrame(t, edge, []byte("still alive"))
	select {
	case d := <-b.Inbound():
		d.Pkt.Release()
	case <-time.After(5 * time.Second):
		t.Fatal("overlay edge broken by the media session's close")
	}
}

// A frame on a reserved channel — injected raw, below the public API, which
// refuses to send one — is shed at the receive gate and counted (level-2).
func TestMediaReservedChannelRxDroppedQUIC(t *testing.T) {
	near, far := mediaPair(t)
	defer near.Close()

	raw := near.(*mediaSession)
	deadline := time.After(5 * time.Second)
	for {
		if err := raw.qconn.SendDatagram([]byte{3, 'x'}); err != nil {
			t.Fatalf("raw SendDatagram: %v", err)
		}
		if far.Stats().RxDroppedReserved > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("reserved-channel frame never counted as dropped")
		case <-time.After(50 * time.Millisecond):
		}
	}
	select {
	case <-far.Datagrams():
		t.Fatal("reserved-channel frame was delivered")
	default:
	}
}

// SendMessage with an already-cancelled ctx resets the stream and surfaces the
// caller's error; the session survives.
func TestMediaSendMessageCtxCancelled(t *testing.T) {
	near, far := mediaPair(t)
	defer near.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := transport.Get()
	defer p.Release()
	p.SetLen(64)
	if err := near.SendMessage(ctx, 16, p); !errors.Is(err, context.Canceled) {
		t.Fatalf("SendMessage with cancelled ctx: err = %v, want context.Canceled", err)
	}
	// The session is alive: a normal message still goes through.
	if err := near.SendMessage(context.Background(), 16, p); err != nil {
		t.Fatalf("SendMessage after a cancelled one: %v", err)
	}
	select {
	case m := <-far.Messages():
		m.Pkt.Release()
	case <-time.After(5 * time.Second):
		t.Fatal("message after a cancelled one never arrived")
	}
}

// rawUniStream opens a unidirectional stream on the session's connection below
// the public API, for driving the receiver's defensive paths.
func rawUniStream(t *testing.T, s transport.MediaSession) *quicgo.SendStream {
	t.Helper()
	str, err := s.(*mediaSession).qconn.OpenUniStreamSync(context.Background())
	if err != nil {
		t.Fatalf("OpenUniStreamSync: %v", err)
	}
	return str
}

// waitCounter polls a session-stats counter until it reaches want.
func waitCounter(t *testing.T, read func() uint64, want uint64, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if read() >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s never reached %d (have %d)", what, want, read())
}

// An inbound message past MaxPacketLen is dropped whole and counted; one of
// exactly MaxPacketLen is legal and delivered intact — the boundary the
// oversize probe must not misjudge (a (1, io.EOF) probe read means one byte
// PAST the cap existed).
func TestMediaMessageOversizeDropped(t *testing.T) {
	near, far := mediaPair(t)
	defer near.Close()

	// Oversized by exactly one byte: ch + MaxPacketLen + 1 on the wire.
	str := rawUniStream(t, near)
	if _, err := str.Write(make([]byte, 1+transport.MaxPacketLen+1)); err != nil {
		t.Fatalf("raw write: %v", err)
	}
	_ = str.Close()
	waitCounter(t, func() uint64 { return far.Stats().RxDroppedMessages }, 1, "RxDroppedMessages")
	select {
	case <-far.Messages():
		t.Fatal("oversized message was delivered")
	default:
	}

	// Exactly at the cap: legal, delivered whole.
	p := transport.Get()
	p.SetLen(transport.MaxPacketLen)
	if err := near.SendMessage(context.Background(), 16, p); err != nil {
		t.Fatalf("SendMessage at the cap: %v", err)
	}
	p.Release()
	select {
	case m, ok := <-far.Messages():
		if !ok {
			t.Fatal("far Messages drained shut")
		}
		if m.Pkt.Len() != transport.MaxPacketLen {
			t.Errorf("delivered %d bytes, want exactly MaxPacketLen", m.Pkt.Len())
		}
		m.Pkt.Release()
	case <-time.After(5 * time.Second):
		t.Fatal("cap-sized message never arrived")
	}
}

// A message stream its writer resets mid-flight is void: nothing partial is
// ever delivered, the drop is counted. An empty aborted stream (reset before
// the channel byte) takes the header-error path, which must also reset the
// receiving side rather than leave the stream's flow-control credit hanging.
func TestMediaMessageWriterResetDropped(t *testing.T) {
	near, far := mediaPair(t)
	defer near.Close()

	// Partial payload, then RESET.
	str := rawUniStream(t, near)
	if _, err := str.Write([]byte{16, 'p', 'a', 'r', 't'}); err != nil {
		t.Fatalf("raw write: %v", err)
	}
	str.CancelWrite(streamCodeCancelled)
	waitCounter(t, func() uint64 { return far.Stats().RxDroppedMessages }, 1, "RxDroppedMessages")

	// Reset before even the channel byte: the header-read path.
	str2 := rawUniStream(t, near)
	str2.CancelWrite(streamCodeCancelled)
	waitCounter(t, func() uint64 { return far.Stats().RxDroppedMessages }, 2, "RxDroppedMessages")

	select {
	case <-far.Messages():
		t.Fatal("an aborted message was delivered")
	default:
	}
	// The session survives its peer's aborted messages.
	p := transport.Get()
	p.SetLen(8)
	if err := near.SendMessage(context.Background(), 16, p); err != nil {
		t.Fatalf("SendMessage after aborted streams: %v", err)
	}
	p.Release()
	select {
	case m := <-far.Messages():
		m.Pkt.Release()
	case <-time.After(5 * time.Second):
		t.Fatal("message after aborted streams never arrived")
	}
}

// Closing the transport tears live media sessions down and closes InboundMedia.
func TestMediaTransportCloseQUIC(t *testing.T) {
	a := listenLoopback(t, idFromByte(1))
	b := listenLoopback(t, idFromByte(2))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	near, err := a.(transport.Media).OpenMedia(ctx, idFromByte(2).ID(), b.LocalAddr())
	if err != nil {
		t.Fatalf("OpenMedia: %v", err)
	}
	far := <-b.(transport.Media).InboundMedia()

	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-near.Closed():
	case <-time.After(5 * time.Second):
		t.Fatal("dialer-side session survived its transport's Close")
	}
	select {
	case <-far.Closed():
	case <-time.After(5 * time.Second):
		t.Fatal("acceptor-side session survived the peer transport's Close")
	}
	_ = b.Close()
	if _, ok := <-b.(transport.Media).InboundMedia(); ok {
		t.Error("InboundMedia delivered after Close, want closed channel")
	}
}
