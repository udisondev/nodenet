//go:build !transportdebug

package transport

// In the default build the Packet lifecycle hooks are no-ops; they inline to
// nothing, so Get/Release/Bytes have zero overhead and the hot path stays at
// 0 allocs/op. Build with -tags transportdebug to turn on double-Release and
// use-after-Release detection (see packet_debug.go).

func dbgGet(*Packet)     {}
func dbgRelease(*Packet) {}
func dbgLive(*Packet)    {}
