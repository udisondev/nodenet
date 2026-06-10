package mem

import (
	mrand "math/rand/v2"
	"sync"
	"time"
)

// LinkProfile is the deterministic model of ONE DIRECTION of a media-plane
// link: what happens to each datagram travelling from one node to another.
// Tests set it with Hub.SetLinkProfile to reproduce loss, delay variation,
// reordering, a bandwidth bottleneck with a bounded queue (deterministic
// bufferbloat) and a path-MTU ceiling — the conditions a real call meets —
// while staying fully deterministic: every random draw comes from a PRNG
// seeded with Seed, and every delay runs on the test's fake clock.
//
// The model shapes DATAGRAMS only. Messages are reliable (the QUIC transport
// retransmits them through loss and short outages), so the mirror delivers
// them unmodified; and overlay frames are untouched entirely — churn tests
// keep Partition/Heal for those. The zero profile is an ideal link.
type LinkProfile struct {
	// Seed seeds the link's private PRNG (loss and jitter draws). Two runs
	// with the same seed and schedule see identical fates.
	Seed uint64

	// Loss is the probability in [0, 1) that a datagram vanishes on the link.
	Loss float64

	// Jitter adds a uniform extra delay in [0, Jitter) to each datagram.
	// Delivery order is still preserved (a serial link); reordering is
	// modelled explicitly below, so each effect is testable on its own.
	Jitter time.Duration

	// ReorderEvery holds back every Nth datagram (0 disables reordering),
	// releasing it only after ReorderHold subsequent datagrams have been
	// delivered — "held back for N deliveries", the deterministic mirror of
	// packets overtaking each other on a real path.
	ReorderEvery int
	ReorderHold  int

	// RateBytesPerSec is the link's drain rate (0 = unshaped). Datagrams
	// queue behind each other and each delivery is delayed by the backlog in
	// front of it — bufferbloat a delay-based estimator can observe. The
	// backlog is capped at QueueBytes (0 = unbounded): a datagram arriving to
	// a full queue is tail-dropped, exactly like a saturated router.
	RateBytesPerSec int
	QueueBytes      int

	// MTU caps the wire size of one datagram (channel byte + payload;
	// 0 = no cap). An oversized datagram is refused at send (the sender's
	// pump counts it in TxDroppedSend) — the mirror of the QUIC stack
	// refusing a datagram after the path MTU shrank.
	MTU int
}

// linkVerdict is one datagram's fate on a link.
type linkVerdict uint8

const (
	linkDeliver linkVerdict = iota // deliver after the returned delay
	linkDropMTU                    // refused at send: over the link MTU (sender-visible)
	linkDropNet                    // lost in the network: loss draw or queue tail-drop (invisible)
)

// linkModel is the live state of one directed link: its profile plus the PRNG
// and the shaper backlog. It is shared by every media session crossing that
// direction (they share the one modelled path), so it carries its own mutex;
// per-session pump goroutines call plan concurrently.
type linkModel struct {
	mu       sync.Mutex
	profile  LinkProfile
	rng      *mrand.Rand
	nextFree time.Time // when the shaper queue drains; backlog = nextFree - now
}

func newLinkModel(p LinkProfile) *linkModel {
	return &linkModel{
		profile: p,
		rng:     mrand.New(mrand.NewPCG(p.Seed, ^p.Seed)),
	}
}

// plan decides one datagram's fate at now: the verdict, and for a delivered
// datagram the delay (shaper backlog + transmission time + jitter) its pump
// must sleep before handing it to the receiver. It mutates the shaper backlog,
// so each datagram sees the queue the previous ones built up.
func (m *linkModel) plan(now time.Time, frameLen int) (linkVerdict, time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.profile

	if p.MTU > 0 && frameLen > p.MTU {
		return linkDropMTU, 0
	}
	if p.Loss > 0 && m.rng.Float64() < p.Loss {
		return linkDropNet, 0
	}

	var delay time.Duration
	if p.RateBytesPerSec > 0 {
		backlog := max(m.nextFree.Sub(now), 0)
		if p.QueueBytes > 0 {
			backlogBytes := backlog.Seconds() * float64(p.RateBytesPerSec)
			if int(backlogBytes)+frameLen > p.QueueBytes {
				return linkDropNet, 0 // queue overflow: tail-drop, like a saturated router
			}
		}
		tx := time.Duration(float64(frameLen) / float64(p.RateBytesPerSec) * float64(time.Second))
		delay = backlog + tx
		m.nextFree = now.Add(delay)
	}
	if p.Jitter > 0 {
		delay += time.Duration(m.rng.Int64N(int64(p.Jitter)))
	}
	return linkDeliver, delay
}
