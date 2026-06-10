package quic

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	quicgo "github.com/quic-go/quic-go"
	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/transport"
)

// appCodeNormal is the QUIC application error code used for a clean edge
// teardown. The peer observes it as the connection closing and reaps the edge.
const appCodeNormal quicgo.ApplicationErrorCode = 0

var _ transport.Conn = (*quicConn)(nil)

// quicConn is one live edge: a QUIC connection carrying a single long-lived
// bidirectional stream over which frames flow in both directions. The dialer
// opens the stream and the acceptor takes it, so a node that dialed out can still
// receive — which is what lets a NAT node forward and become a full router.
type quicConn struct {
	owner  *quicTransport
	remote kad.ID
	raddr  transport.Addr

	qconn *quicgo.Conn
	str   *quicgo.Stream
	br    *bufio.Reader // wraps str so readFrameLen can read the uvarint byte-by-byte

	wmu  sync.Mutex                  // serializes Send writes so two frames never interleave on the stream
	whdr [binary.MaxVarintLen64]byte // reused length-prefix scratch (guarded by wmu) — keeps Send 0-alloc

	closeOnce sync.Once
	closedCh  chan struct{}
}

func newQuicConn(owner *quicTransport, remote kad.ID, qconn *quicgo.Conn, str *quicgo.Stream) *quicConn {
	return &quicConn{
		owner:    owner,
		remote:   remote,
		raddr:    addrFromNet(qconn.RemoteAddr()),
		qconn:    qconn,
		str:      str,
		br:       bufio.NewReaderSize(str, 4096),
		closedCh: make(chan struct{}),
	}
}

func (c *quicConn) Remote() kad.ID             { return c.remote }
func (c *quicConn) RemoteAddr() transport.Addr { return c.raddr }

// Send borrows p: it writes uvarint(len) followed by p.Bytes() under the write
// mutex and returns without retaining p. quic-go's Stream.Write consumes the
// bytes synchronously (io.Writer semantics, into a flow-controlled send buffer),
// so once Write returns the caller's buffer is free — the zero-copy forwarding
// contract. Any write error means the edge is down: it maps to ErrConnClosed and
// leaves p untouched.
func (c *quicConn) Send(p *transport.Packet) error {
	select {
	case <-c.closedCh:
		return transport.ErrConnClosed
	default:
	}
	b := p.Bytes()
	if len(b) > transport.MaxPacketLen {
		panic("quic: Send of oversized packet") // same stance as Packet.SetLen
	}

	c.wmu.Lock()
	defer c.wmu.Unlock()
	if err := c.writeFrameLocked(b); err != nil {
		// Any write failure — including a tripped send deadline — means the edge is down.
		// Tear it down (so a partially written, now-desynced frame dies with the
		// connection and the caller's RemoveEdge is matched by a real close) and report
		// it; the forward falls to the next disjoint hop and maintenance re-dials.
		c.Close()
		return transport.ErrConnClosed
	}
	return nil
}

// writeFrameLocked writes one length-prefixed frame under wmu, bounded by the transport's
// send deadline. quic-go's Write blocks while the stream's flow-control window is exhausted
// (a slow, congested, or silent peer); the dispatch loop forwards synchronously, so an
// unbounded block would wedge the whole router. The deadline turns that into a recoverable
// edge failure. A non-positive sendDeadline means "no deadline" (the net.Conn zero-time
// convention, matching WithSendDeadline's docs): the write is left unbounded rather than
// armed with an already-expired deadline that would fail every send instantly.
func (c *quicConn) writeFrameLocked(b []byte) error {
	if d := c.owner.sendDeadline; d > 0 {
		if err := c.str.SetWriteDeadline(time.Now().Add(d)); err != nil {
			return err
		}
		// The deadline scopes this one frame write; clear it afterwards so it cannot linger
		// on the stream and spuriously trip an unrelated later write (each write arms its own).
		defer c.str.SetWriteDeadline(time.Time{})
	}
	n := binary.PutUvarint(c.whdr[:], uint64(len(b)))
	if _, err := c.str.Write(c.whdr[:n]); err != nil {
		return err
	}
	_, err := c.str.Write(b)
	return err
}

// Close tears the edge down. It is idempotent (sync.Once) and propagates: closing
// the QUIC connection makes the peer's read loop and next Send observe the
// connection closing, i.e. ErrConnClosed.
func (c *quicConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closedCh)
		_ = c.qconn.CloseWithError(appCodeNormal, "")
		c.owner.removeConn(c)
	})
	return nil
}

// readLoop pulls length-delimited frames off the stream and pushes each as a
// Delivery onto the transport's single Inbound channel. The caller starts it in a
// goroutine tracked by the transport's WaitGroup; any read error (EOF, reset,
// oversized length, transport closing) ends the loop and closes the edge.
func (c *quicConn) readLoop() {
	defer c.Close()
	for {
		n, err := readFrameLen(c.br)
		if err != nil {
			return
		}
		pkt := transport.Get()
		if _, err := io.ReadFull(c.br, pkt.Buf()[:n]); err != nil {
			pkt.Release()
			return
		}
		pkt.SetLen(n)
		if err := c.owner.deliver(transport.Delivery{Conn: c, Pkt: pkt}, c); err != nil {
			pkt.Release()
			return
		}
	}
}

// addrFromNet renders a net.Addr as a transport.Addr. For a UDP connection the
// String form is "ip:port", which routing.SubnetFromHostPort parses for
// subnet-diversity accounting.
func addrFromNet(a net.Addr) transport.Addr {
	if a == nil {
		return transport.Addr{}
	}
	return transport.Addr{Net: "quic", Endpoint: a.String()}
}
