package transport

import "sync"

// MaxPacketLen is the largest frame a Packet can hold, and the size of every
// pooled buffer. Because every implementation moves frames as Packets — the QUIC
// transport clamps its on-the-wire framing to this value — it is the effective
// frame budget of the system: nodes must agree on it to interoperate. It is also
// a level-2 self-protection bound: a peer cannot make us hold a buffer larger
// than this. The overlay only carries small control and rendezvous frames, so
// 64 KiB is generous.
//
// wire.MaxFrameLen is a separate, higher ceiling on what the frame *parser*
// accepts. The layering invariant is that it stays >= any payload a Packet can
// carry, so wire never rejects a frame the transport could deliver; the binding
// limit on a frame's size is this constant, not the parser cap.
const MaxPacketLen = 1 << 16 // 64 KiB

// Packet is a single wire frame in transit, backed by a buffer drawn from a pool.
// It is the unit a Conn sends and receives. The lifecycle is: Get a Packet, lay
// a frame into Buf() and mark its length with SetLen (or fill it some other way),
// then either Send it or hand it to the overlay, and finally Release it exactly
// once. Release returns the buffer to the pool, so a steady send/recv loop
// allocates nothing.
//
// Packet holds no pool pointer: a single package-level pool (pktPool) backs every
// Packet, which keeps the type a thin {buffer, length} pair and the API
// allocation-free.
//
// Ownership across a Send/receive is defined by Conn (see conn.go): Send BORROWS
// the Packet — the caller keeps ownership and Releases it exactly once after Send
// returns; a received Packet is owned by whoever reads it off Transport.Inbound
// and must be Released after use. Double-Release and use-after-Release are bugs;
// build with -tags transportdebug to have them panic instead of corrupting the pool.
type Packet struct {
	buf []byte // backing array from the pool; len == cap == MaxPacketLen
	n   int    // number of valid bytes; the payload window is buf[:n]
}

// pktPool hands out MaxPacketLen-sized Packets. One package-level pool keeps Get
// allocation-free after warmup and avoids a per-Packet pool pointer.
var pktPool = sync.Pool{
	New: func() any { return &Packet{buf: make([]byte, MaxPacketLen)} },
}

// Get returns a Packet with a full-capacity buffer and zero length. Fill it via
// Buf() + SetLen, then Send it or hand it on; Release it exactly once when done.
func Get() *Packet {
	p := pktPool.Get().(*Packet)
	p.n = 0
	dbgGet(p)
	return p
}

// Buf returns the full backing buffer (length MaxPacketLen) for in-place frame
// encoding — e.g. frame, _ := wire.EncodeFrame(p.Buf(), t, payload); then
// p.SetLen(len(frame)). The returned slice aliases the Packet and is valid only
// until Release.
func (p *Packet) Buf() []byte {
	dbgLive(p)
	return p.buf
}

// SetLen marks the first n bytes of the buffer as the valid payload window. It
// panics if n is negative or exceeds MaxPacketLen — an oversized frame is a
// programmer error, exactly like a slice bounds violation.
func (p *Packet) SetLen(n int) {
	dbgLive(p)
	if n < 0 || n > len(p.buf) {
		panic("transport: Packet.SetLen out of range")
	}
	p.n = n
}

// Len reports the length of the valid payload window.
func (p *Packet) Len() int {
	dbgLive(p)
	return p.n
}

// Bytes returns the valid payload window buf[:n] — a slice ALIASING the Packet's
// buffer, valid only until Release. Copy it to retain the bytes past Release.
// This is the zero-copy read window the overlay parses with wire.ParseFrame.
func (p *Packet) Bytes() []byte {
	dbgLive(p)
	return p.buf[:p.n]
}

// Release returns the Packet's buffer to the pool. Call it exactly once, after
// the last use of Bytes(). After Release the Packet must not be touched.
func (p *Packet) Release() {
	dbgRelease(p)
	p.n = 0
	pktPool.Put(p)
}
