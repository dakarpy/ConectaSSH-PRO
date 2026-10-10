package main

import (
	"net"
	"testing"
)

func TestTLSListenerPoolDisabledEntryIsNotOpened(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	probe.Close()
	disabled := false
	pool := newTLSListenerPool()
	if errs := pool.Sync([]TLSForwarderConfig{{Listen: addr, CertFile: "missing-cert", KeyFile: "missing-key", Enabled: &disabled}}); len(errs) != 0 {
		t.Fatalf("disabled entry should not load cert or bind port: %v", errs)
	}
	if pool.Has(addr) {
		t.Fatal("disabled TLS listener unexpectedly opened")
	}
	if !pool.HasAll([]TLSForwarderConfig{{Listen: addr, Enabled: &disabled}}) {
		t.Fatal("disabled entry should count as satisfied")
	}
}
