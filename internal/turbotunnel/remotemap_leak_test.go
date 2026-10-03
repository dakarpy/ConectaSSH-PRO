package turbotunnel

import (
	"runtime"
	"testing"
	"time"
)

// TestQueuePacketConnCloseStopsGoroutine is the regression test for the local
// fork's reason to exist: upstream's RemoteMap expiry goroutine runs forever,
// so creating and discarding many QueuePacketConns (as DNSTT restart does)
// leaks one goroutine each. After Close(), the count must return to baseline.
func TestQueuePacketConnCloseStopsGoroutine(t *testing.T) {
	// Let any goroutines from earlier settle.
	settle := func() {
		for i := 0; i < 50; i++ {
			runtime.GC()
			time.Sleep(2 * time.Millisecond)
		}
	}
	settle()
	base := runtime.NumGoroutine()

	const n = 200
	for i := 0; i < n; i++ {
		// Short timeout so the goroutine is definitely started (timeout > 0).
		c := NewQueuePacketConn(DummyAddr{}, 50*time.Millisecond)
		if err := c.Close(); err != nil {
			t.Fatalf("Close returned error: %v", err)
		}
	}
	settle()

	got := runtime.NumGoroutine()
	// Allow a small slack for scheduler/runtime goroutines; the key point is we
	// are nowhere near base+n (which is what the upstream leak would produce).
	if got > base+20 {
		t.Fatalf("goroutine leak: baseline=%d after %d create/close cycles=%d (want <= baseline+20)", base, n, got)
	}
}

// TestRemoteMapCloseIdempotent verifies Close can be called repeatedly.
func TestRemoteMapCloseIdempotent(t *testing.T) {
	m := NewRemoteMap(10 * time.Millisecond)
	if err := m.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
