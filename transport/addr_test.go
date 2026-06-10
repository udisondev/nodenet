package transport

import (
	"bytes"
	"errors"
	"slices"
	"testing"
)

func TestAddrString(t *testing.T) {
	tests := []struct {
		name string
		addr Addr
		want string
	}{
		{"mem", Addr{Net: "mem", Endpoint: "node-7"}, "mem://node-7"},
		{"quic", Addr{Net: "quic", Endpoint: "203.0.113.4:443"}, "quic://203.0.113.4:443"},
		{"zero", Addr{}, "://"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.addr.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Addr must be usable as a map key: the mem hub indexes transports by Addr, so
// the type has to stay comparable (no slices/maps inside).
func TestAddrMapKey(t *testing.T) {
	m := map[Addr]int{
		{Net: "mem", Endpoint: "a"}: 1,
		{Net: "mem", Endpoint: "b"}: 2,
	}
	if m[Addr{Net: "mem", Endpoint: "a"}] != 1 {
		t.Errorf("lookup a = %d, want 1", m[Addr{Net: "mem", Endpoint: "a"}])
	}
	// Equal value, independently constructed, hits the same slot.
	k := Addr{Net: "mem", Endpoint: "b"}
	if m[k] != 2 {
		t.Errorf("lookup b = %d, want 2", m[k])
	}
	// Distinct Net with same Endpoint is a different key.
	if _, ok := m[Addr{Net: "quic", Endpoint: "a"}]; ok {
		t.Error("quic://a should not collide with mem://a")
	}
}

// codecAddrs covers the shapes the codec must round-trip: the zero Addr, the two
// real families, and strings long enough to need a multi-byte uvarint header.
var codecAddrs = []struct {
	name string
	addr Addr
}{
	{"zero", Addr{}},
	{"mem", Addr{Net: "mem", Endpoint: "node-7"}},
	{"quic", Addr{Net: "quic", Endpoint: "203.0.113.4:443"}},
	{"empty net", Addr{Endpoint: "x"}},
	{"empty endpoint", Addr{Net: "quic"}},
	{"long", Addr{Net: "quic", Endpoint: string(bytes.Repeat([]byte{'e'}, 300))}},
}

func TestAddrCodecRoundTrip(t *testing.T) {
	for _, tt := range codecAddrs {
		t.Run(tt.name, func(t *testing.T) {
			enc := AppendAddr(nil, tt.addr)
			if got, want := len(enc), AddrWireLen(tt.addr); got != want {
				t.Errorf("encoded %d bytes, AddrWireLen = %d", got, want)
			}
			a, n, err := ParseAddr(enc)
			if err != nil {
				t.Fatalf("ParseAddr: %v", err)
			}
			if a != tt.addr {
				t.Errorf("round-trip = %+v, want %+v", a, tt.addr)
			}
			if n != len(enc) {
				t.Errorf("consumed %d of %d bytes", n, len(enc))
			}
		})
	}
}

// ParseAddr stops at the end of the address: trailing bytes are not an error,
// they belong to the caller (list decoders advance by n).
func TestParseAddrTrailingBytes(t *testing.T) {
	want := Addr{Net: "quic", Endpoint: "h:1"}
	enc := AppendAddr(nil, want)
	encLen := len(enc)
	enc = append(enc, "tail junk"...)
	a, n, err := ParseAddr(enc)
	if err != nil {
		t.Fatalf("ParseAddr: %v", err)
	}
	if a != want || n != encLen {
		t.Errorf("ParseAddr = %+v, n=%d; want %+v, n=%d", a, n, want, encLen)
	}
}

func TestParseAddrMalformed(t *testing.T) {
	tests := []struct {
		name string
		b    []byte
	}{
		{"empty", nil},
		{"missing endpoint header", []byte{0}},
		{"net length past buffer", []byte{5, 'a', 'b'}},
		{"endpoint length past buffer", []byte{1, 'q', 3, 'a'}},
		{"truncated varint", []byte{0x80}},
		{"varint overflow", bytes.Repeat([]byte{0xff}, 10)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, n, err := ParseAddr(tt.b)
			if !errors.Is(err, ErrBadAddr) {
				t.Fatalf("ParseAddr(%x): err = %v, want ErrBadAddr", tt.b, err)
			}
			if a != (Addr{}) || n != 0 {
				t.Errorf("ParseAddr(%x) = %+v, n=%d on error; want zero Addr, n=0", tt.b, a, n)
			}
		})
	}
}

func TestAddrsCodecRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		addrs []Addr
	}{
		{"nil", nil},
		{"one", []Addr{{Net: "mem", Endpoint: "a"}}},
		{"several", []Addr{
			{Net: "quic", Endpoint: "203.0.113.4:443"},
			{},
			{Net: "mem", Endpoint: "node-7"},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc := AppendAddrs(nil, tt.addrs)
			if got, want := len(enc), AddrsWireLen(tt.addrs); got != want {
				t.Errorf("encoded %d bytes, AddrsWireLen = %d", got, want)
			}
			got, n, err := ParseAddrs(enc)
			if err != nil {
				t.Fatalf("ParseAddrs: %v", err)
			}
			if !slices.Equal(got, tt.addrs) {
				t.Errorf("round-trip = %+v, want %+v", got, tt.addrs)
			}
			if n != len(enc) {
				t.Errorf("consumed %d of %d bytes", n, len(enc))
			}
		})
	}
}

func TestParseAddrsMalformed(t *testing.T) {
	// A one-address list whose count byte is patched to 2: the count passes the
	// size bound but the second address is missing.
	short := AppendAddrs(nil, []Addr{{Net: "quic", Endpoint: "h:1"}})
	short[0] = 2
	tests := []struct {
		name string
		b    []byte
	}{
		{"empty", nil},
		{"truncated count varint", []byte{0x80}},
		{"hostile count, no body", []byte{0xff, 0xff, 0xff, 0xff, 0x0f}},
		{"count exceeds remaining", []byte{2, 0}},
		{"count larger than list", short},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addrs, n, err := ParseAddrs(tt.b)
			if !errors.Is(err, ErrBadAddr) {
				t.Fatalf("ParseAddrs(%x): err = %v, want ErrBadAddr", tt.b, err)
			}
			if addrs != nil || n != 0 {
				t.Errorf("ParseAddrs(%x) = %+v, n=%d on error; want nil, 0", tt.b, addrs, n)
			}
		})
	}
}

// An empty list is one count byte; bytes after it belong to the caller.
func TestParseAddrsEmptyWithTail(t *testing.T) {
	addrs, n, err := ParseAddrs([]byte{0, 'j', 'u', 'n', 'k'})
	if err != nil {
		t.Fatalf("ParseAddrs: %v", err)
	}
	if addrs != nil || n != 1 {
		t.Errorf("ParseAddrs = %+v, n=%d; want nil, n=1", addrs, n)
	}
}
