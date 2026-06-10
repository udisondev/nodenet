package quic

import (
	"net/netip"
	"sync"
	"testing"
)

// TestInboundCapGlobal: the accept path must bound how many inbound connections it admits
// concurrently. Without a cap an attacker minting cheap (non-PoW) identities can complete
// the cheap TLS handshake endlessly and park half-open connections, each holding a
// goroutine and QUIC state, until the node exhausts memory — a resource-exhaustion DoS on
// a public entry point. admitInbound is the gate; here we flood it from DISTINCT source
// IPs so only the global cap is in play.
func TestInboundCapGlobal(t *testing.T) {
	const capN = 8
	tr := &quicTransport{
		inboundSlots: make(chan struct{}, capN),
		perIP:        make(map[netip.Addr]int),
		maxPerIP:     0, // disable per-IP so only the global cap bounds the flood
	}

	const goroutines = capN + 64
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		releases []func()
		admitted int
		start    = make(chan struct{})
	)
	wg.Add(goroutines)
	for i := range goroutines {
		ip := netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1}) // a distinct IP per caller
		go func() {
			defer wg.Done()
			<-start
			release, ok := tr.admitInbound(ip)
			if !ok {
				return
			}
			mu.Lock()
			admitted++
			releases = append(releases, release)
			mu.Unlock()
		}()
	}
	close(start)
	wg.Wait()

	if admitted > capN {
		t.Fatalf("admitted %d inbound connections, global cap is %d", admitted, capN)
	}
	if admitted != capN {
		t.Fatalf("admitted %d, want exactly %d (cap saturated, none released)", admitted, capN)
	}
	if got := len(tr.inboundSlots); got != capN {
		t.Fatalf("held %d inbound slots, want %d", got, capN)
	}

	// Releasing frees slots for new admissions.
	for _, r := range releases {
		r()
	}
	if got := len(tr.inboundSlots); got != 0 {
		t.Fatalf("after release held %d slots, want 0", got)
	}
}

// TestInboundCapPerIP: a single source IP must not be able to consume all global slots —
// the per-IP cap bounds one address well below the global cap, so a single host (or a
// single NAT) cannot starve every other peer. Flood from ONE IP and assert admissions are
// bounded by maxPerIP, not the (larger) global cap.
func TestInboundCapPerIP(t *testing.T) {
	const capN, perIP = 64, 4
	tr := &quicTransport{
		inboundSlots: make(chan struct{}, capN),
		perIP:        make(map[netip.Addr]int),
		maxPerIP:     perIP,
	}

	ip := netip.AddrFrom4([4]byte{203, 0, 113, 7})
	const goroutines = capN
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		releases []func()
		admitted int
		start    = make(chan struct{})
	)
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			<-start
			release, ok := tr.admitInbound(ip)
			if !ok {
				return
			}
			mu.Lock()
			admitted++
			releases = append(releases, release)
			mu.Unlock()
		}()
	}
	close(start)
	wg.Wait()

	if admitted > perIP {
		t.Fatalf("admitted %d connections from one IP, per-IP cap is %d", admitted, perIP)
	}
	if admitted != perIP {
		t.Fatalf("admitted %d from one IP, want exactly %d", admitted, perIP)
	}

	// After releasing, the same IP can be admitted again (the counter is decremented).
	for _, r := range releases {
		r()
	}
	if _, ok := tr.admitInbound(ip); !ok {
		t.Fatal("after release a fresh connection from the same IP was refused")
	}
}
