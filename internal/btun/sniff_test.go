package btun

import "testing"

// Everything BTUN shares a port with has to be rejected, and the marker itself
// has to be accepted, or sharing the port would break SSH and HTTP clients.
func TestSniffClientHello(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  Verdict
	}{
		{name: "exact marker", input: string(ClientHello), want: VerdictYes},
		{name: "marker then payload", input: string(ClientHello) + "\x01\x02", want: VerdictYes},
		{name: "partial marker", input: "DTUNNEL/1.1 CLI", want: VerdictMore},
		{name: "first byte only", input: "D", want: VerdictMore},
		{name: "empty", input: "", want: VerdictMore},
		{name: "SSH identification", input: "SSH-2.0-OpenSSH_9.6\r\n", want: VerdictNo},
		{name: "HTTP GET", input: "GET / HTTP/1.1\r\n\r\n", want: VerdictNo},
		{name: "HTTP DELETE shares a first byte", input: "DELETE / HTTP/1.1\r\n\r\n", want: VerdictNo},
		{name: "TLS client hello", input: "\x16\x03\x01\x02\x00", want: VerdictNo},
		{name: "BHTTP frame", input: "\x00\x01\x02\x03", want: VerdictNo},
		{name: "wrong version", input: "DTUNNEL/2.0 CLIENT_HELLO\r\n", want: VerdictNo},
		{name: "marker not at offset zero", input: "xxDTUNNEL/1.1 CLIENT_HELLO\r\n", want: VerdictNo},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SniffClientHello([]byte(tt.input)); got != tt.want {
				t.Fatalf("SniffClientHello(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// A partial marker must never be mistaken for a complete one, however it is
// split across reads.
func TestSniffClientHelloIsProgressive(t *testing.T) {
	for cut := 0; cut < len(ClientHello); cut++ {
		if got := SniffClientHello(ClientHello[:cut]); got != VerdictMore {
			t.Fatalf("SniffClientHello(first %d bytes) = %v, want VerdictMore", cut, got)
		}
	}
	if got := SniffClientHello(ClientHello); got != VerdictYes {
		t.Fatalf("SniffClientHello(full marker) = %v, want VerdictYes", got)
	}
}
