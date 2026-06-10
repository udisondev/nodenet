package nattest

import (
	"net"
	"sync"
)

// Fabric is the shared in-process "internet": it routes datagrams between endpoints
// by destination address. Endpoints register the addresses they own (a public node
// its fixed address; a NAT box each external mapping it allocates), and a datagram to
// an unregistered address is silently dropped, exactly as the real internet black-holes
// a packet to an unmapped port. It is safe for concurrent use.
type Fabric struct {
	mu       sync.Mutex
	binds    map[string]binding // address string -> who receives it
	nextPort int
}

// binding is what a registered address points at: the receiving conn and, for a NAT
// external address, the specific mapping the inbound packet must satisfy (nil for a
// public endpoint, which admits everyone).
type binding struct {
	c *conn
	m *mapping
}

// NewFabric returns an empty fabric. External ports are handed out from a high base
// so they never collide with the well-known ranges a test might hard-code.
func NewFabric() *Fabric {
	return &Fabric{binds: make(map[string]binding), nextPort: 30000}
}

// Public registers a directly-reachable endpoint at addr (a "host:port") with no NAT
// in front: every inbound datagram is admitted. It is how an entry point, coordinator,
// or relay joins the fabric.
func (f *Fabric) Public(addr string) (net.PacketConn, error) {
	ua, err := resolveUDP(addr)
	if err != nil {
		return nil, err
	}
	c := newConn(f, ua, nil)
	f.bind(ua, binding{c: c})
	return c, nil
}

// BehindNAT registers an endpoint at internal (its own "host:port", as the node sees
// itself) fronted by the NAT box n. The node's external mappings are allocated lazily
// on first send and registered with the fabric so return traffic can find them.
func (f *Fabric) BehindNAT(internal string, n NAT) (net.PacketConn, error) {
	ua, err := resolveUDP(internal)
	if err != nil {
		return nil, err
	}
	return newConn(f, ua, &n), nil
}

// allocPort hands out a unique external port for a new NAT mapping.
func (f *Fabric) allocPort() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.nextPort
	f.nextPort++
	return p
}

func (f *Fabric) bind(addr *net.UDPAddr, b binding) {
	f.mu.Lock()
	f.binds[addr.String()] = b
	f.mu.Unlock()
}

func (f *Fabric) unbind(addr *net.UDPAddr) {
	f.mu.Lock()
	delete(f.binds, addr.String())
	f.mu.Unlock()
}

// route delivers data to whoever owns dst, tagging it with the source address the
// receiver should see (src — already the sender's external address). A datagram to an
// unregistered address is dropped.
func (f *Fabric) route(dst, src *net.UDPAddr, data []byte) {
	f.mu.Lock()
	b, ok := f.binds[dst.String()]
	f.mu.Unlock()
	if !ok {
		return
	}
	b.c.deliver(b.m, src, data)
}
