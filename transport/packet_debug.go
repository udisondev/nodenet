//go:build transportdebug

package transport

import "sync"

// This file is compiled only with -tags transportdebug. It instruments the
// Packet lifecycle to catch the two classic pool bugs — releasing a Packet twice
// (which would hand the same buffer to two owners) and touching a Packet after
// Release — and turns them into immediate panics with a clear message, instead of
// silent pool corruption that surfaces as a baffling data race later.
//
// Liveness is tracked in a side table keyed by the Packet pointer, so the default
// build needs no extra struct field and stays a thin {buffer, length} pair.

var dbgLiveSet sync.Map // *Packet -> struct{}, present while checked out of the pool

func dbgGet(p *Packet) {
	dbgLiveSet.Store(p, struct{}{})
}

func dbgRelease(p *Packet) {
	if _, ok := dbgLiveSet.LoadAndDelete(p); !ok {
		panic("transport: Packet released twice or never obtained from Get")
	}
}

func dbgLive(p *Packet) {
	if _, ok := dbgLiveSet.Load(p); !ok {
		panic("transport: use of a Packet after Release")
	}
}
