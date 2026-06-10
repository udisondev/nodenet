//go:build transportdebug

package transport

import "testing"

// Under -tags transportdebug the lifecycle guard must turn the ownership bugs
// into panics rather than silent pool corruption.

func TestDebugDoubleRelease(t *testing.T) {
	p := Get()
	p.Release()
	defer func() {
		if recover() == nil {
			t.Error("double Release did not panic under transportdebug")
		}
	}()
	p.Release()
}

func TestDebugUseAfterRelease(t *testing.T) {
	p := Get()
	p.Release()
	defer func() {
		if recover() == nil {
			t.Error("use after Release did not panic under transportdebug")
		}
	}()
	_ = p.Bytes()
}
