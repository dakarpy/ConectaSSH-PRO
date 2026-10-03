package main

import "testing"

func TestNormalizeLocalSSHListen(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "empty uses safe default", input: "", want: defaultLocalSSHListen},
		{name: "whitespace uses safe default", input: "  ", want: defaultLocalSSHListen},
		{name: "IPv4 loopback", input: "127.0.0.1:2200", want: "127.0.0.1:2200"},
		{name: "other IPv4 loopback", input: "127.10.20.30:2222", want: "127.10.20.30:2222"},
		{name: "IPv6 loopback", input: "[::1]:2222", want: "[::1]:2222"},
		{name: "wildcard IPv4 rejected", input: "0.0.0.0:2222", want: defaultLocalSSHListen, wantErr: true},
		{name: "wildcard IPv6 rejected", input: "[::]:2222", want: defaultLocalSSHListen, wantErr: true},
		{name: "public address rejected", input: "192.0.2.10:2222", want: defaultLocalSSHListen, wantErr: true},
		{name: "hostname rejected", input: "localhost:2222", want: defaultLocalSSHListen, wantErr: true},
		{name: "missing port rejected", input: "127.0.0.1", want: defaultLocalSSHListen, wantErr: true},
		{name: "zero port rejected", input: "127.0.0.1:0", want: defaultLocalSSHListen, wantErr: true},
		{name: "large port rejected", input: "127.0.0.1:65536", want: defaultLocalSSHListen, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeLocalSSHListen(tt.input)
			if got != tt.want {
				t.Fatalf("normalizeLocalSSHListen(%q) address = %q, want %q", tt.input, got, tt.want)
			}
			if (err != nil) != tt.wantErr {
				t.Fatalf("normalizeLocalSSHListen(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestNormalizeDNSTTListenDefault(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		want     string
		migrated bool
	}{
		{name: "empty uses IPv4 default", input: "", want: "0.0.0.0:5300"},
		{name: "whitespace uses IPv4 default", input: "  ", want: "0.0.0.0:5300"},
		{name: "legacy IPv6 wildcard migrates", input: "[::]:5300", want: "0.0.0.0:5300", migrated: true},
		{name: "expanded legacy wildcard migrates", input: "[0:0:0:0:0:0:0:0]:5300", want: "0.0.0.0:5300", migrated: true},
		{name: "explicit IPv4 remains", input: "192.0.2.10:53", want: "192.0.2.10:53"},
		{name: "IPv4 wildcard remains", input: "0.0.0.0:5300", want: "0.0.0.0:5300"},
		{name: "concrete IPv6 remains", input: "[2001:db8::10]:53", want: "[2001:db8::10]:53"},
		{name: "IPv6 wildcard on custom port remains", input: "[::]:5301", want: "[::]:5301"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, migrated := normalizeDNSTTListenDefault(tt.input)
			if got != tt.want || migrated != tt.migrated {
				t.Fatalf("normalizeDNSTTListenDefault(%q) = (%q, %v), want (%q, %v)", tt.input, got, migrated, tt.want, tt.migrated)
			}
		})
	}
}
