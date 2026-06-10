//go:build e2e_nat

// These tests exercise the NAT emulator itself under real time (real read deadlines
// and TTL sleeps with tight margins), so — like the package doc promises for
// everything real-time here — they are gated behind the e2e_nat build tag and
// excluded from the default deterministic `go test ./...`. Run them with:
//
//	go test -tags e2e_nat ./transport/quic/nattest
package nattest

import (
	"net"
	"testing"
	"time"
)

// send writes one datagram from pc to dst (a "host:port").
func send(t *testing.T, pc net.PacketConn, dst, data string) {
	t.Helper()
	ua, err := net.ResolveUDPAddr("udp", dst)
	if err != nil {
		t.Fatalf("resolve %s: %v", dst, err)
	}
	if _, err := pc.WriteTo([]byte(data), ua); err != nil {
		t.Fatalf("WriteTo %s: %v", dst, err)
	}
}

// recv reads one datagram from pc within a short deadline, returning its payload and
// the source address the receiver saw. ok is false on timeout (nothing admitted).
func recv(t *testing.T, pc net.PacketConn) (data string, src string, ok bool) {
	t.Helper()
	_ = pc.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1500)
	n, from, err := pc.ReadFrom(buf)
	if err != nil {
		if ne, isNet := err.(net.Error); isNet && ne.Timeout() {
			return "", "", false
		}
		t.Fatalf("ReadFrom: %v", err)
	}
	return string(buf[:n]), from.String(), true
}

func mustPublic(t *testing.T, f *Fabric, addr string) net.PacketConn {
	t.Helper()
	pc, err := f.Public(addr)
	if err != nil {
		t.Fatalf("Public %s: %v", addr, err)
	}
	return pc
}

func mustNAT(t *testing.T, f *Fabric, internal string, n NAT) net.PacketConn {
	t.Helper()
	pc, err := f.BehindNAT(internal, n)
	if err != nil {
		t.Fatalf("BehindNAT %s: %v", internal, err)
	}
	return pc
}

// TestPublicToPublic: two directly-reachable endpoints exchange a datagram and each
// sees the other's real address.
func TestPublicToPublic(t *testing.T) {
	f := NewFabric()
	a := mustPublic(t, f, "100.0.0.1:9000")
	b := mustPublic(t, f, "100.0.0.2:9000")

	send(t, a, "100.0.0.2:9000", "hi")
	data, src, ok := recv(t, b)
	if !ok || data != "hi" || src != "100.0.0.1:9000" {
		t.Fatalf("got (%q, %q, %v), want (hi, 100.0.0.1:9000, true)", data, src, ok)
	}
}

// TestReflexiveAddressSeen: a NAT node's outbound datagram reaches a public peer with
// the source rewritten to the external mapping — the reflexive address the peer learns.
func TestReflexiveAddressSeen(t *testing.T) {
	f := NewFabric()
	c := mustPublic(t, f, "100.0.0.9:9000")
	a := mustNAT(t, f, "10.0.0.2:1111", RestrictedConeNAT("200.0.0.1"))

	send(t, a, "100.0.0.9:9000", "ping")
	_, src, ok := recv(t, c)
	if !ok {
		t.Fatal("public peer received nothing")
	}
	if host, _, _ := net.SplitHostPort(src); host != "200.0.0.1" {
		t.Fatalf("reflexive IP = %q, want 200.0.0.1 (the external mapping, not the internal 10.0.0.2)", host)
	}
}

// TestConeReusesOnePort: an Independent (cone) NAT presents the same external address
// to every destination, so a reflexive address learned from one peer is valid for all.
func TestConeReusesOnePort(t *testing.T) {
	f := NewFabric()
	c := mustPublic(t, f, "100.0.0.1:9000")
	d := mustPublic(t, f, "100.0.0.2:9000")
	a := mustNAT(t, f, "10.0.0.2:1111", RestrictedConeNAT("200.0.0.1"))

	send(t, a, "100.0.0.1:9000", "x")
	_, srcC, _ := recv(t, c)
	send(t, a, "100.0.0.2:9000", "y")
	_, srcD, _ := recv(t, d)

	if srcC != srcD {
		t.Fatalf("cone NAT used different ports per destination: %q vs %q", srcC, srcD)
	}
}

// TestSymmetricPerDestPort: a Dependent (symmetric) NAT allocates a fresh external
// port per destination, so the reflexive address learned from one peer does not apply
// to another — the property that makes it unpunchable.
func TestSymmetricPerDestPort(t *testing.T) {
	f := NewFabric()
	c := mustPublic(t, f, "100.0.0.1:9000")
	d := mustPublic(t, f, "100.0.0.2:9000")
	a := mustNAT(t, f, "10.0.0.2:1111", SymmetricNAT("200.0.0.1"))

	send(t, a, "100.0.0.1:9000", "x")
	_, srcC, _ := recv(t, c)
	send(t, a, "100.0.0.2:9000", "y")
	_, srcD, _ := recv(t, d)

	if srcC == srcD {
		t.Fatalf("symmetric NAT reused a port across destinations: %q", srcC)
	}
}

// TestRestrictedFilterBlocksUnsolicited: a restricted-cone NAT drops inbound from a
// peer the node has not sent to, then admits it once the node has — the hole-punch
// precondition.
func TestRestrictedFilterBlocksUnsolicited(t *testing.T) {
	f := NewFabric()
	c := mustPublic(t, f, "100.0.0.1:9000") // A learns its mapping by talking to C
	x := mustPublic(t, f, "100.0.0.7:9000") // X is the would-be unsolicited sender
	a := mustNAT(t, f, "10.0.0.2:1111", RestrictedConeNAT("200.0.0.1"))

	send(t, a, "100.0.0.1:9000", "open")
	_, ext, ok := recv(t, c)
	if !ok {
		t.Fatal("C received nothing")
	}

	// X sends to A's external address before A ever sent to X: dropped.
	send(t, x, ext, "unsolicited")
	if _, _, ok := recv(t, a); ok {
		t.Fatal("restricted NAT admitted an unsolicited datagram")
	}

	// A punches toward X, opening the permission; now X's datagram is admitted.
	send(t, a, "100.0.0.7:9000", "punch")
	send(t, x, ext, "now allowed")
	if data, _, ok := recv(t, a); !ok || data != "now allowed" {
		t.Fatalf("after punch got (%q, %v), want (now allowed, true)", data, ok)
	}
}

// TestFullConeAdmitsUnsolicited: once a full-cone mapping exists, any sender may use
// it without the node having sent to them first.
func TestFullConeAdmitsUnsolicited(t *testing.T) {
	f := NewFabric()
	c := mustPublic(t, f, "100.0.0.1:9000")
	x := mustPublic(t, f, "100.0.0.7:9000")
	a := mustNAT(t, f, "10.0.0.2:1111", NAT{ExtIP: "200.0.0.1", Mapping: Independent, Filter: FullCone})

	send(t, a, "100.0.0.1:9000", "open")
	_, ext, _ := recv(t, c)

	send(t, x, ext, "hello")
	if data, _, ok := recv(t, a); !ok || data != "hello" {
		t.Fatalf("full-cone got (%q, %v), want (hello, true)", data, ok)
	}
}

// TestMappingExpiry: a mapping idle past its TTL stops admitting inbound; fresh
// outbound traffic re-opens it. This is what keepalive relies on.
func TestMappingExpiry(t *testing.T) {
	f := NewFabric()
	c := mustPublic(t, f, "100.0.0.1:9000")
	x := mustPublic(t, f, "100.0.0.7:9000")
	a := mustNAT(t, f, "10.0.0.2:1111", NAT{
		ExtIP: "200.0.0.1", Mapping: Independent, Filter: FullCone, TTL: 50 * time.Millisecond,
	})

	send(t, a, "100.0.0.1:9000", "open")
	_, ext, _ := recv(t, c)

	time.Sleep(80 * time.Millisecond) // let the mapping idle out
	send(t, x, ext, "stale")
	if _, _, ok := recv(t, a); ok {
		t.Fatal("expired mapping still admitted inbound")
	}

	send(t, a, "100.0.0.1:9000", "refresh") // re-open the mapping
	_, ext2, _ := recv(t, c)
	send(t, x, ext2, "fresh")
	if data, _, ok := recv(t, a); !ok || data != "fresh" {
		t.Fatalf("after refresh got (%q, %v), want (fresh, true)", data, ok)
	}
}
