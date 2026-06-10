package mem

import (
	"context"
	"errors"
	"testing"

	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/transport"
	"github.com/udisondev/nodenet/wire"
)

const testType wire.Type = 7

// nodeID derives a deterministic NodeID from a one-byte seed, so tests get
// stable, distinct identities without touching randomness.
func nodeID(seed byte) kad.ID {
	var s [identity.SeedLen]byte
	s[0] = seed
	return identity.FromSeed(s).ID()
}

func addr(name string) transport.Addr {
	return transport.Addr{Net: "mem", Endpoint: name}
}

// sendFrame encodes payload as a wire frame into a pooled Packet and sends it on
// conn. Send borrows the Packet, so the caller Releases it after Send returns.
func sendFrame(t *testing.T, conn transport.Conn, payload []byte) {
	t.Helper()
	p := transport.Get()
	frame, err := wire.EncodeFrame(p.Buf(), testType, payload)
	if err != nil {
		p.Release()
		t.Fatalf("EncodeFrame: %v", err)
	}
	p.SetLen(len(frame))
	err = conn.Send(p)
	p.Release()
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
}

// recvPayload reads one delivery, parses the frame, returns the payload (copied)
// and the Conn it arrived on, and Releases the Packet.
func recvPayload(t *testing.T, tr transport.Transport) ([]byte, transport.Conn) {
	t.Helper()
	d := <-tr.Inbound()
	typ, payload, _, err := wire.ParseFrame(d.Pkt.Bytes())
	if err != nil {
		d.Pkt.Release()
		t.Fatalf("ParseFrame: %v", err)
	}
	if typ != testType {
		t.Errorf("frame type = %d, want %d", typ, testType)
	}
	out := append([]byte(nil), payload...)
	d.Pkt.Release()
	return out, d.Conn
}

func TestPartitionBlackholesAndHeals(t *testing.T) {
	h := NewHub()
	idA, idB := nodeID(1), nodeID(2)
	a, err := h.New(idA, addr("a"))
	if err != nil {
		t.Fatalf("New a: %v", err)
	}
	bt, err := h.New(idB, addr("b"))
	if err != nil {
		t.Fatalf("New b: %v", err)
	}
	defer a.Close()
	defer bt.Close()
	conn, err := a.Dial(context.Background(), idB, addr("b"))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	// Baseline: the frame gets through.
	sendFrame(t, conn, []byte("hi"))
	if got, _ := recvPayload(t, bt); string(got) != "hi" {
		t.Fatalf("baseline payload = %q, want hi", got)
	}

	// Partitioned: Send reports no error (the edge is up) but nothing is delivered.
	h.Partition(idA, idB)
	sendFrame(t, conn, []byte("lost"))
	select {
	case d := <-bt.Inbound():
		d.Pkt.Release()
		t.Fatal("frame delivered during partition; it should be blackholed")
	default:
	}

	// Healed: delivery resumes.
	h.Heal(idA, idB)
	sendFrame(t, conn, []byte("back"))
	if got, _ := recvPayload(t, bt); string(got) != "back" {
		t.Fatalf("post-heal payload = %q, want back", got)
	}
}

func TestHubRegister(t *testing.T) {
	h := NewHub()
	idA, idB := nodeID(1), nodeID(2)

	if _, err := h.New(idA, addr("a")); err != nil {
		t.Fatalf("New a: %v", err)
	}
	if _, err := h.New(idB, addr("b")); err != nil {
		t.Fatalf("New b: %v", err)
	}
	if _, err := h.New(nodeID(3), addr("a")); err == nil {
		t.Error("duplicate addr accepted, want error")
	}
	if _, err := h.New(idA, addr("c")); err == nil {
		t.Error("duplicate id accepted, want error")
	}
}

// After Close, Dial to the closed transport's address fails (it is deregistered).
// This exercises hub deregistration specifically; the generic ErrNoRoute sentinel
// is covered by the shared contract suite (see contract_test.go).
func TestDialAfterPeerClose(t *testing.T) {
	h := NewHub()
	a, _ := h.New(nodeID(1), addr("a"))
	b, _ := h.New(nodeID(2), addr("b"))
	defer a.Close()
	b.Close()

	_, err := a.Dial(context.Background(), nodeID(2), addr("b"))
	if !errors.Is(err, transport.ErrNoRoute) {
		t.Errorf("Dial to closed peer: err = %v, want ErrNoRoute", err)
	}
}
