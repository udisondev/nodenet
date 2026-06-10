// Package kad holds the Kademlia keyspace primitives of nodenet: the node
// identifier type ID and the XOR-metric arithmetic built on it (distance,
// common-prefix length).
//
// It is the root leaf of the dependency DAG — it imports nothing from the
// project, only the standard library — so every higher package (identity,
// wire, transport, pow, routing, nat, rendezvous, node) can depend on it
// without a cycle. Keep it that way: kad is pure keyspace math, never network
// or topology policy. In particular the mapping "common-prefix length ->
// k-bucket slot" lives in routing, not here; kad only supplies CommonPrefixLen.
//
// ID is BLAKE2b(ed_pub) — a full 256-bit identifier. The 32-byte
// blob is interpreted big-endian: byte 0 is the most-significant byte, so a
// "long common prefix" is a run of equal high bits and distance comparison is
// unsigned big-endian lexicographic order.
package kad

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/bits"
)

const (
	// IDLen is the identifier length in bytes.
	IDLen = 32
	// IDBits is the identifier length in bits; also the value CommonPrefixLen
	// returns for two equal IDs.
	IDBits = IDLen * 8
)

// ID is a node identifier: BLAKE2b(ed_pub), 256 bits.
//
// It is a fixed-size array, not a slice, on purpose: it lives on the stack,
// is comparable with == (so it can key a map directly), and copies cheaply by
// value. The XOR-metric operations on it allocate nothing.
type ID [32]byte

// The primitives below process the ID as 4 big-endian uint64 words. BigEndian
// keeps word 0 the most significant, which is required wherever the blob is
// treated as a 256-bit number: unsigned word comparison then matches the
// big-endian-number ordering of the XOR metric, and leading-zero counting
// measures the shared high-bit prefix.

// Distance returns the XOR distance a ^ b. The result is the materialized
// 256-bit distance, useful for diagnostics or distance-bucketing; the routing
// hot path should prefer DistanceCmp, which compares two candidates without
// materializing either distance.
func Distance(a, b ID) ID {
	var d ID
	for i := 0; i < IDLen; i += 8 {
		wa := binary.BigEndian.Uint64(a[i:])
		wb := binary.BigEndian.Uint64(b[i:])
		binary.BigEndian.PutUint64(d[i:], wa^wb)
	}
	return d
}

// DistanceCmp reports which of a, b is closer to target under the XOR metric:
// -1 if a is strictly closer, +1 if b is strictly closer, 0 if equidistant.
//
// This is the greedy-routing hot path ("pick the neighbour nearest the
// target"). It folds the XOR into the comparison and returns at the first
// word where the two distances differ, so it never builds the intermediate
// distances. Unsigned word comparison on big-endian words is exactly the
// big-endian-number ordering the XOR metric needs.
func DistanceCmp(target, a, b ID) int {
	for i := 0; i < IDLen; i += 8 {
		t := binary.BigEndian.Uint64(target[i:])
		da := binary.BigEndian.Uint64(a[i:]) ^ t
		db := binary.BigEndian.Uint64(b[i:]) ^ t
		if da != db {
			if da < db {
				return -1
			}
			return 1
		}
	}
	return 0
}

// CommonPrefixLen returns the number of leading bits a and b share, 0..IDBits.
// Two equal IDs share all IDBits bits. This is the Kademlia "closeness as a
// long shared prefix" measure; routing derives its bucket index from it.
func CommonPrefixLen(a, b ID) int {
	for i := 0; i < IDLen; i += 8 {
		if x := binary.BigEndian.Uint64(a[i:]) ^ binary.BigEndian.Uint64(b[i:]); x != 0 {
			// First differing word: count the equal high bits within it.
			return i*8 + bits.LeadingZeros64(x)
		}
	}
	return IDBits
}

// String returns the lowercase hex encoding of the identifier (64 chars). It
// allocates, so it is for logs and tests, not the hot path.
func (id ID) String() string {
	return hex.EncodeToString(id[:])
}

// ParseID decodes a hex string (exactly IDLen bytes) into an ID. It is the
// inverse of String and is meant for test vectors and config.
func ParseID(s string) (ID, error) {
	var id ID
	b, err := hex.DecodeString(s)
	if err != nil {
		return id, fmt.Errorf("kad: parse ID: %w", err)
	}
	if len(b) != IDLen {
		return id, fmt.Errorf("kad: bad ID length %d, want %d", len(b), IDLen)
	}
	copy(id[:], b)
	return id, nil
}
