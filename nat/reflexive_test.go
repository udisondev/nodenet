package nat

import (
	"testing"

	"github.com/udisondev/nodenet/kad"
	"github.com/udisondev/nodenet/transport"
)

func id(b byte) kad.ID {
	var k kad.ID
	k[0] = b
	return k
}

func addr(ep string) transport.Addr {
	return transport.Addr{Net: "quic", Endpoint: ep}
}

// sub builds a distinct failure-domain key from a byte, so a test can place reporters in
// the same subnet (same byte) or independent ones (different bytes).
func sub(b byte) SubnetKey {
	var k SubnetKey
	k[0] = b
	return k
}

type report struct {
	reporter kad.ID
	subnet   SubnetKey
	addr     transport.Addr
}

func TestReflexiveConsensus(t *testing.T) {
	pub := addr("203.0.113.7:4242")
	alt := addr("203.0.113.7:5555")

	tests := []struct {
		name      string
		reports   []report
		want      transport.Addr
		wantOK    bool
		symmetric bool
	}{
		{
			name:    "empty",
			reports: nil,
			wantOK:  false,
		},
		{
			name:    "single report is not enough",
			reports: []report{{id(1), sub(1), pub}},
			wantOK:  false,
		},
		{
			name:    "two neighbours agree is below quorum",
			reports: []report{{id(1), sub(1), pub}, {id(2), sub(2), pub}},
			wantOK:  false,
		},
		{
			name:    "three across two subnets confirms",
			reports: []report{{id(1), sub(1), pub}, {id(2), sub(2), pub}, {id(3), sub(1), pub}},
			want:    pub,
			wantOK:  true,
		},
		{
			name:    "three in one subnet does NOT confirm (sybil cluster)",
			reports: []report{{id(1), sub(1), pub}, {id(2), sub(1), pub}, {id(3), sub(1), pub}},
			wantOK:  false,
		},
		{
			name:      "three disagree is symmetric",
			reports:   []report{{id(1), sub(1), pub}, {id(2), sub(2), alt}, {id(3), sub(3), addr("203.0.113.7:6000")}},
			wantOK:    false,
			symmetric: true,
		},
		{
			name:    "diverse majority wins over a lone dissenter",
			reports: []report{{id(1), sub(1), pub}, {id(2), sub(2), pub}, {id(3), sub(3), pub}, {id(4), sub(4), alt}},
			want:    pub,
			wantOK:  true,
		},
		{
			name:    "latest report from a neighbour replaces earlier",
			reports: []report{{id(1), sub(1), alt}, {id(2), sub(2), pub}, {id(3), sub(3), pub}, {id(1), sub(1), pub}},
			want:    pub,
			wantOK:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := NewReflexive()
			for _, rep := range tc.reports {
				r.Record(rep.reporter, rep.subnet, true, rep.addr)
			}
			got, ok := r.Consensus()
			if ok != tc.wantOK {
				t.Fatalf("Consensus ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && got != tc.want {
				t.Fatalf("Consensus addr = %v, want %v", got, tc.want)
			}
			if sym := r.Symmetric(); sym != tc.symmetric {
				t.Fatalf("Symmetric = %v, want %v", sym, tc.symmetric)
			}
		})
	}
}

// A tie in votes must resolve deterministically: a confirmed (subnet-diverse) address
// beats an unconfirmed one with the same count, regardless of map iteration order, so a
// single-subnet sybil cluster cannot even probabilistically displace an honest quorum
// by levelling the score.
func TestReflexiveConsensusTieBreakPrefersConfirmed(t *testing.T) {
	honest := addr("203.0.113.7:4242")
	sybil := addr("198.51.100.1:6666")

	orders := [][]report{
		{ // honest quorum first
			{id(1), sub(1), honest}, {id(2), sub(2), honest}, {id(3), sub(3), honest},
			{id(4), sub(9), sybil}, {id(5), sub(9), sybil}, {id(6), sub(9), sybil},
		},
		{ // sybil cluster first
			{id(4), sub(9), sybil}, {id(5), sub(9), sybil}, {id(6), sub(9), sybil},
			{id(1), sub(1), honest}, {id(2), sub(2), honest}, {id(3), sub(3), honest},
		},
	}
	for oi, reps := range orders {
		r := NewReflexive()
		for _, rep := range reps {
			r.Record(rep.reporter, rep.subnet, true, rep.addr)
		}
		// Map iteration order varies per call: repeat to catch a random winner.
		for i := range 64 {
			got, ok := r.Consensus()
			if !ok || got != honest {
				t.Fatalf("order %d, call %d: Consensus = %v ok=%v, want %v true", oi, i, got, ok, honest)
			}
		}
	}
}

// When the tie is exact (same count, same confirmation), the winner is still fixed:
// the lexicographically smaller address. Different insertion orders and repeated calls
// must agree.
func TestReflexiveConsensusTieBreakIsDeterministic(t *testing.T) {
	a := addr("198.51.100.1:1111")
	b := addr("203.0.113.7:4242") // a < b lexicographically

	orders := [][]report{
		{
			{id(1), sub(1), a}, {id(2), sub(2), a}, {id(3), sub(3), a},
			{id(4), sub(4), b}, {id(5), sub(5), b}, {id(6), sub(6), b},
		},
		{
			{id(4), sub(4), b}, {id(5), sub(5), b}, {id(6), sub(6), b},
			{id(1), sub(1), a}, {id(2), sub(2), a}, {id(3), sub(3), a},
		},
	}
	for oi, reps := range orders {
		r := NewReflexive()
		for _, rep := range reps {
			r.Record(rep.reporter, rep.subnet, true, rep.addr)
		}
		for i := range 64 {
			got, ok := r.Consensus()
			if !ok || got != a {
				t.Fatalf("order %d, call %d: Consensus = %v ok=%v, want %v true", oi, i, got, ok, a)
			}
		}
	}
}

// Without subnet info (the in-memory transport), the consolidator falls back to a
// plain distinct-reporter quorum.
func TestReflexiveConsensusNoSubnetInfo(t *testing.T) {
	pub := addr("203.0.113.7:4242")
	r := NewReflexive()
	r.Record(id(1), SubnetKey{}, false, pub)
	r.Record(id(2), SubnetKey{}, false, pub)
	if _, ok := r.Consensus(); ok {
		t.Fatal("two reports must not reach the quorum of three")
	}
	r.Record(id(3), SubnetKey{}, false, pub)
	if got, ok := r.Consensus(); !ok || got != pub {
		t.Fatalf("three no-subnet reports should confirm: got %v ok=%v", got, ok)
	}
}

func TestReflexiveIgnoresZeroAddr(t *testing.T) {
	r := NewReflexive()
	r.Record(id(1), sub(1), true, transport.Addr{})
	r.Record(id(2), sub(2), true, transport.Addr{})
	if _, ok := r.Consensus(); ok {
		t.Fatal("zero-addr reports must not reach consensus")
	}
	if r.Symmetric() {
		t.Fatal("zero-addr reports must not flag symmetric")
	}
}

func TestStrategyString(t *testing.T) {
	for s, want := range map[Strategy]string{
		Direct:      "direct",
		Punch:       "punch",
		Relay:       "relay",
		Strategy(9): "unknown",
	} {
		if got := s.String(); got != want {
			t.Fatalf("Strategy(%d).String() = %q, want %q", s, got, want)
		}
	}
}
