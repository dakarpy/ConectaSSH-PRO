package main

import (
	"testing"
	"time"
)

func TestSSHIdleTimeoutDisabledByDefault(t *testing.T) {
	for _, raw := range []string{"", "0", "0s", "off", "disabled"} {
		if got := parseSSHIdleTimeout(raw); got != 0 {
			t.Fatalf("parseSSHIdleTimeout(%q) = %s, want disabled", raw, got)
		}
	}
}

func TestSSHIdleTimeoutExplicitValue(t *testing.T) {
	if got := parseSSHIdleTimeout("30m"); got != 30*time.Minute {
		t.Fatalf("got %s, want 30m", got)
	}
}

// The connected-session sweeper is the backstop that reaps XHTTP->SSH sessions
// whose stream-down GET context never fires (silent client drop behind a CDN).
// Without it those sessions leak fds/goroutines until a process restart, which
// is what produced the recurring reboot-only XHTTP 502s. It must stay enabled;
// the window is generous so only zero-traffic (dead) sessions are reaped.
func TestNativeXHTTPConnectedIdleSweepEnabled(t *testing.T) {
	got := nativeXHTTPIdleTimeout()
	if got <= 0 {
		t.Fatalf("native XHTTP idle timeout = %s, want a positive backstop window", got)
	}
	if got != 20*time.Minute {
		t.Fatalf("native XHTTP idle timeout = %s, want 20m backstop", got)
	}
}
