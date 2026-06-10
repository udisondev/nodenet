package nattest

import (
	"net"
	"sync"
	"time"
)

// conn is one endpoint on a Fabric, implementing net.PacketConn so the QUIC transport
// can run over it. A public endpoint (nat == nil) sends from its own fixed address and
// admits every inbound datagram. A NAT endpoint rewrites the source to an external
// mapping on the way out and filters inbound against that mapping on the way in.
type conn struct {
	f    *Fabric
	self *net.UDPAddr // public address, or the internal address for a NAT endpoint
	nat  *NAT         // nil for a public endpoint

	mu     sync.Mutex
	shared *mapping            // Independent mapping: one external port for all peers
	perDst map[string]*mapping // Dependent mapping: one external port per destination

	in           chan packet
	readDeadline time.Time
	deadlineCh   chan struct{} // closed and replaced on each SetReadDeadline to wake a blocked ReadFrom
	closed       chan struct{}
	closeOnce    sync.Once
}

// mapping is one NAT session: the external address peers see, the set of remote
// endpoints allowed to send back through it (per the filter granularity, each entry
// timestamped and subject to the same idle TTL), and the last time the node sent
// through it. Only outbound traffic refreshes idle expiry — inbound does not — which
// is why keeping a hole open takes outbound keepalives.
type mapping struct {
	ext      *net.UDPAddr
	perms    map[string]time.Time
	lastUsed time.Time
}

// packet is a datagram queued for ReadFrom: the payload and the source address the
// receiver should see.
type packet struct {
	src  *net.UDPAddr
	data []byte
}

func newConn(f *Fabric, self *net.UDPAddr, nat *NAT) *conn {
	return &conn{
		f:          f,
		self:       self,
		nat:        nat,
		perDst:     make(map[string]*mapping),
		in:         make(chan packet, 1024),
		deadlineCh: make(chan struct{}),
		closed:     make(chan struct{}),
	}
}

// WriteTo sends b to dst. For a NAT endpoint it allocates/refreshes the mapping for
// dst, opens the inbound permission for dst, and stamps the source as the external
// address; the fabric then routes it (dropping it if dst is unmapped).
func (c *conn) WriteTo(b []byte, dst net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	ua, err := toUDP(dst)
	if err != nil {
		return 0, err
	}
	data := append([]byte(nil), b...)

	src := c.self
	if c.nat != nil {
		now := time.Now()
		c.mu.Lock()
		m := c.mappingFor(ua, now)
		m.lastUsed = now
		if c.nat.Filter != FullCone {
			m.perms[c.permKey(ua)] = now
		}
		src = m.ext
		c.mu.Unlock()
	}
	c.f.route(ua, src, data)
	return len(b), nil
}

// ReadFrom returns the next admitted datagram, honouring any read deadline. A
// SetReadDeadline that arrives while ReadFrom is already blocked wakes it (via
// deadlineCh) so it re-evaluates — the mechanism quic-go uses to unblock the read
// loop on Close.
func (c *conn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		c.mu.Lock()
		dl := c.readDeadline
		dch := c.deadlineCh
		c.mu.Unlock()

		// The timer is stopped explicitly in every select arm rather than deferred:
		// a defer inside the loop would pile up one live timer per deadline change
		// for as long as this ReadFrom stays blocked.
		var timer *time.Timer
		var timeout <-chan time.Time
		if !dl.IsZero() {
			if !time.Now().Before(dl) {
				return 0, nil, timeoutError{}
			}
			timer = time.NewTimer(time.Until(dl))
			timeout = timer.C
		}

		select {
		case p := <-c.in:
			if timer != nil {
				timer.Stop()
			}
			n := copy(b, p.data)
			return n, p.src, nil
		case <-timeout:
			return 0, nil, timeoutError{} // the timer has already fired
		case <-c.closed:
			if timer != nil {
				timer.Stop()
			}
			return 0, nil, net.ErrClosed
		case <-dch:
			// Deadline changed under us; drop this iteration's timer and recompute.
			if timer != nil {
				timer.Stop()
			}
		}
	}
}

// deliver is the fabric's inbound hook: it applies NAT mapping-expiry and filtering,
// then queues the datagram (dropping it if the receive buffer is full).
func (c *conn) deliver(m *mapping, src *net.UDPAddr, data []byte) {
	if c.nat != nil {
		now := time.Now()
		c.mu.Lock()
		ok := m != nil && !c.expired(m, now)
		if ok && c.nat.Filter != FullCone {
			t, seen := m.perms[c.permKey(src)]
			ok = seen && (c.nat.TTL == 0 || now.Sub(t) <= c.nat.TTL)
		}
		c.mu.Unlock()
		if !ok {
			return
		}
	}
	select {
	case c.in <- packet{src: src, data: data}:
	case <-c.closed:
	default: // receive buffer full: drop, as a real socket does under overload
	}
}

// mappingFor returns the external mapping for dst, allocating one (and registering it
// with the fabric) on first use and replacing an idle-expired one. Caller holds c.mu.
func (c *conn) mappingFor(dst *net.UDPAddr, now time.Time) *mapping {
	if c.nat.Mapping == Independent {
		if c.shared != nil && c.expired(c.shared, now) {
			c.f.unbind(c.shared.ext)
			c.shared = nil
		}
		if c.shared == nil {
			c.shared = c.newMapping(now)
		}
		return c.shared
	}
	key := dst.String()
	m := c.perDst[key]
	if m != nil && c.expired(m, now) {
		c.f.unbind(m.ext)
		delete(c.perDst, key)
		m = nil
	}
	if m == nil {
		m = c.newMapping(now)
		c.perDst[key] = m
	}
	return m
}

// newMapping allocates a fresh external address and binds it on the fabric so return
// traffic routes back here. Caller holds c.mu.
func (c *conn) newMapping(now time.Time) *mapping {
	ext := &net.UDPAddr{IP: net.ParseIP(c.nat.ExtIP), Port: c.f.allocPort()}
	m := &mapping{ext: ext, perms: make(map[string]time.Time), lastUsed: now}
	c.f.bind(ext, binding{c: c, m: m})
	return m
}

func (c *conn) expired(m *mapping, now time.Time) bool {
	return c.nat.TTL > 0 && now.Sub(m.lastUsed) > c.nat.TTL
}

// permKey is the inbound-permission key for remote at this NAT's filter granularity.
func (c *conn) permKey(remote *net.UDPAddr) string {
	switch c.nat.Filter {
	case AddrRestricted:
		return remote.IP.String()
	case AddrPortRestricted:
		return remote.String()
	default:
		return ""
	}
}

// Close unbinds the endpoint's addresses and unblocks any pending ReadFrom. Idempotent.
func (c *conn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.nat == nil {
			c.f.unbind(c.self)
			return
		}
		if c.shared != nil {
			c.f.unbind(c.shared.ext)
		}
		for _, m := range c.perDst {
			c.f.unbind(m.ext)
		}
	})
	return nil
}

func (c *conn) LocalAddr() net.Addr { return c.self }

func (c *conn) SetDeadline(t time.Time) error {
	return c.SetReadDeadline(t)
}

func (c *conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	close(c.deadlineCh) // wake any ReadFrom blocked under the old deadline
	c.deadlineCh = make(chan struct{})
	c.mu.Unlock()
	return nil
}

func (c *conn) SetWriteDeadline(time.Time) error { return nil } // writes never block

func toUDP(a net.Addr) (*net.UDPAddr, error) {
	if ua, ok := a.(*net.UDPAddr); ok {
		return ua, nil
	}
	return resolveUDP(a.String())
}
