package quic

import (
	"testing"
	"time"

	"github.com/udisondev/nodenet/transport"
)

// TestDeliverDoesNotHoldMuAcrossSend (regression): deliver must not hold t.mu across
// the blocking send into the Inbound channel. The single Inbound consumer (the node's
// dispatch loop) closes edges synchronously — quicConn.Close → removeConn → t.mu.Lock —
// so a deliver parked on a full channel while holding even a read lock deadlocks the
// whole transport: the consumer waits for the lock, the lock waits for the parked
// deliver, and the parked deliver waits for the consumer to read.
func TestDeliverDoesNotHoldMuAcrossSend(t *testing.T) {
	tr := &quicTransport{
		in:    make(chan transport.Delivery), // unbuffered: deliver parks immediately
		done:  make(chan struct{}),
		conns: make(map[*quicConn]struct{}),
	}

	delivered := make(chan error, 1)
	go func() { delivered <- tr.deliver(transport.Delivery{}, nil) }()
	// Let the deliver goroutine park on the channel send. The sleep only orders the
	// interleaving toward the buggy schedule; the assertion itself is the watchdog.
	time.Sleep(10 * time.Millisecond)

	consumerDone := make(chan struct{})
	go func() {
		tr.removeConn(&quicConn{}) // what the consumer does when it closes an edge
		<-tr.in                    // and only then drains the channel
		close(consumerDone)
	}()

	select {
	case <-consumerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("deliver holds t.mu across a blocking send: a consumer-side removeConn deadlocks")
	}
	if err := <-delivered; err != nil {
		t.Fatalf("deliver returned %v, want nil", err)
	}
}

// TestDeliverAvoidsTransportMutex (regression): deliver is the per-frame hot path —
// every read loop calls it for every inbound frame — while t.mu is the connection
// control plane's lock, write-held on every admission, registration and teardown.
// Frame delivery must not acquire t.mu at all, or a flood of connection churn would
// add its lock traffic as latency to data delivery on every live edge.
func TestDeliverAvoidsTransportMutex(t *testing.T) {
	tr := &quicTransport{
		in:   make(chan transport.Delivery, 1),
		done: make(chan struct{}),
	}
	tr.mu.Lock() // the control plane mid-churn (admission/teardown holds the write lock)
	defer tr.mu.Unlock()

	delivered := make(chan error, 1)
	go func() { delivered <- tr.deliver(transport.Delivery{}, nil) }()
	select {
	case err := <-delivered:
		if err != nil {
			t.Fatalf("deliver returned %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("deliver blocked on t.mu: the per-frame path takes the control-plane lock")
	}
}
