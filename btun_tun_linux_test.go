//go:build linux

package main

// These tests exercise the parts of BTUN that only exist on Linux and need real
// privileges: creating the TUN interface, and installing and removing the
// NAT/forward rules that let clients reach the internet. Nothing else in the
// suite can reach that code, so without these it ships unexecuted.
//
// They are opt-in because they need NET_ADMIN and /dev/net/tun. Run them with:
//
//   docker run --rm --cap-add NET_ADMIN --device /dev/net/tun \
//     -v "$PWD:/src" conecta-build tun

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/dakarpy/ConectaSSH-PRO/internal/btun"
)

// requireTUN skips unless the environment can actually create a TUN device.
func requireTUN(t *testing.T) {
	t.Helper()
	if os.Getenv("BTUN_TUN_TESTS") == "" {
		t.Skip("set BTUN_TUN_TESTS=1 and grant NET_ADMIN + /dev/net/tun to run this")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skipf("/dev/net/tun is unavailable: %v", err)
	}
}

// OpenTUN is the call that fails on a container without /dev/net/tun and is the
// single most common reason BTUN does not start. This checks that it really
// creates the interface it names, and really releases it on Close.
func TestBTUNOpenTUNCreatesAndReleasesTheInterface(t *testing.T) {
	requireTUN(t)

	const name = "btuntest0"
	device, err := btun.OpenTUN(name)
	if err != nil {
		t.Fatalf("OpenTUN(%q): %v", name, err)
	}
	if device.Name() != name {
		t.Fatalf("device name = %q, want %q", device.Name(), name)
	}
	if !interfaceExists(t, name) {
		t.Fatalf("interface %s was not created in the kernel", name)
	}

	if err := device.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// The kernel removes the interface once the last handle is gone, which may
	// take a moment.
	deadline := time.Now().Add(5 * time.Second)
	for interfaceExists(t, name) {
		if time.Now().After(deadline) {
			t.Fatalf("interface %s survived the device being closed", name)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// An interface name the kernel cannot accept has to fail cleanly rather than
// leaving a half-open device behind.
func TestBTUNOpenTUNRejectsInvalidNames(t *testing.T) {
	requireTUN(t)

	for _, name := range []string{"", "this-name-is-far-too-long"} {
		if device, err := btun.OpenTUN(name); err == nil {
			_ = device.Close()
			t.Fatalf("OpenTUN(%q) succeeded, want an error", name)
		}
	}
}

// The managed-routing path configures the interface and installs NAT. This runs
// it for real and then checks the rules it claims to have added are present,
// and that removing them leaves the tables as they were.
func TestBTUNManagedRoutingInstallsAndRemovesItsRules(t *testing.T) {
	requireTUN(t)
	if _, err := exec.LookPath("iptables"); err != nil {
		t.Skip("iptables is not installed")
	}

	const name = "btuntest1"
	const subnet = "10.79.0.0/24"
	device, err := btun.OpenTUN(name)
	if err != nil {
		t.Fatalf("OpenTUN: %v", err)
	}
	defer device.Close()

	cfg := &BTUNConfig{
		TCPListen:     "127.0.0.1:0",
		Subnet:        subnet,
		TUNName:       name,
		MTU:           1400,
		ManageRouting: true,
		WANInterface:  "eth0",
	}
	normalizeBTUNConfig(cfg)
	if cfg.Gateway != "10.79.0.1/24" {
		t.Fatalf("derived gateway = %q, want 10.79.0.1/24", cfg.Gateway)
	}

	spec, err := applyBTUNRouting(cfg, device.Name())
	if err != nil {
		t.Fatalf("applyBTUNRouting: %v", err)
	}
	t.Cleanup(func() { removeBTUNRouting(spec) })

	if !interfaceHasAddress(t, name, "10.79.0.1") {
		t.Fatalf("gateway address was not configured on %s", name)
	}
	if !natRuleExists(t, subnet) {
		t.Fatalf("MASQUERADE rule for %s was not installed", subnet)
	}
	if got := readSysctl(t, "net.ipv4.ip_forward"); got != "1" {
		t.Fatalf("net.ipv4.ip_forward = %q, want 1", got)
	}

	// Re-applying must not stack duplicates, which is what would happen on
	// every panel restart if the rules were added unconditionally.
	if _, err := applyBTUNRouting(cfg, device.Name()); err != nil {
		t.Fatalf("second applyBTUNRouting: %v", err)
	}
	if count := natRuleCount(t, subnet); count != 1 {
		t.Fatalf("MASQUERADE rule appears %d times after re-applying, want 1", count)
	}

	removeBTUNRouting(spec)
	if natRuleExists(t, subnet) {
		t.Fatalf("MASQUERADE rule for %s survived removal", subnet)
	}
}

func interfaceExists(t *testing.T, name string) bool {
	t.Helper()
	return exec.Command("ip", "link", "show", name).Run() == nil
}

func interfaceHasAddress(t *testing.T, name, address string) bool {
	t.Helper()
	out, err := exec.Command("ip", "-4", "addr", "show", "dev", name).CombinedOutput()
	if err != nil {
		t.Fatalf("ip addr show %s: %v (%s)", name, err, out)
	}
	return strings.Contains(string(out), address)
}

func natRuleCount(t *testing.T, subnet string) int {
	t.Helper()
	out, err := exec.Command("iptables", "-t", "nat", "-S", "POSTROUTING").CombinedOutput()
	if err != nil {
		t.Fatalf("iptables -S POSTROUTING: %v (%s)", err, out)
	}
	count := 0
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, subnet) && strings.Contains(line, "MASQUERADE") {
			count++
		}
	}
	return count
}

func natRuleExists(t *testing.T, subnet string) bool {
	t.Helper()
	return natRuleCount(t, subnet) > 0
}

func readSysctl(t *testing.T, key string) string {
	t.Helper()
	path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return strings.TrimSpace(string(data))
}
