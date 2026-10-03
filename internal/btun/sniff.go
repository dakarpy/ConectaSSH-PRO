package btun

import "bytes"

// Verdict is the result of inspecting the first bytes of a connection.
type Verdict int

const (
	// VerdictNo means the bytes cannot begin a BTUN handshake.
	VerdictNo Verdict = iota
	// VerdictMore means the bytes so far are consistent with one but more are
	// needed to decide. The caller should peek further and ask again.
	VerdictMore
	// VerdictYes means the bytes begin a BTUN handshake.
	VerdictYes
)

// SniffLimit is the largest number of bytes SniffClientHello ever needs.
var SniffLimit = len(ClientHello)

// SniffClientHello reports whether data begins with the BTUN client hello, so
// a listener shared with other protocols can route the connection without
// consuming anything.
//
// The hello is a fixed 25-byte ASCII marker, which makes this decisive in a
// way a length or range check never is: no SSH identification and no HTTP
// request line can match it, and the very first byte already rejects both in
// the overwhelming majority of cases.
//
// The match is anchored at offset zero. A TCP client may legitimately prepend
// cover bytes before its hello, and ServeTCP still tolerates that on a
// dedicated BTUN port, but a shared port cannot buffer an unbounded prefix
// while some other protocol waits to be recognised. Cover that is itself an
// HTTP request is still handled: the panel's HTTP cleanup consumes it, which
// leaves the hello at offset zero for a second look.
func SniffClientHello(data []byte) Verdict {
	if len(data) >= len(ClientHello) {
		if bytes.Equal(data[:len(ClientHello)], ClientHello) {
			return VerdictYes
		}
		return VerdictNo
	}
	if bytes.Equal(data, ClientHello[:len(data)]) {
		return VerdictMore
	}
	return VerdictNo
}
