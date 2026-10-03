package bhttp

import (
	"encoding/binary"
	"testing"
)

// frame builds a wire frame for the sniffer to inspect.
func frame(mode byte, sid SessionID, sequence uint64, clear []byte) []byte {
	payload := Crypt(clear, sid, mode, sequence, false)
	out := make([]byte, HeaderSize+len(payload))
	out[0] = mode
	copy(out[1:17], sid[:])
	binary.BigEndian.PutUint64(out[17:25], sequence)
	binary.BigEndian.PutUint32(out[25:29], uint32(len(payload)))
	copy(out[HeaderSize:], payload)
	return out
}

func probeClear(magic string, submode byte, parameter uint32) []byte {
	clear := make([]byte, 10)
	copy(clear[:4], magic)
	clear[4] = 1
	clear[5] = submode
	binary.BigEndian.PutUint32(clear[6:10], parameter)
	return clear
}

// Everything BHTTP shares a port with has to be rejected on the first byte,
// otherwise sharing the port would break SSH and HTTP-injection clients.
func TestSniffRejectsTheProtocolsItSharesPortsWith(t *testing.T) {
	tests := map[string]string{
		"SSH identification": "SSH-2.0-OpenSSH_9.6\r\n",
		"HTTP GET":           "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
		"HTTP POST":          "POST /path HTTP/1.1\r\n\r\n",
		"HTTP HEAD":          "HEAD / HTTP/1.0\r\n\r\n",
		"HTTP CONNECT":       "CONNECT host:443 HTTP/1.1\r\n\r\n",
		"HTTP OPTIONS":       "OPTIONS / HTTP/1.1\r\n\r\n",
		"HTTP PATCH":         "PATCH / HTTP/1.1\r\n\r\n",
		"HTTP status line":   "HTTP/1.1 200 OK\r\n\r\n",
		"TLS client hello":   "\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03",
		"bare CRLF":          "\r\n\r\n",
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if got := SniffFrame([]byte(input)); got != VerdictNo {
				t.Fatalf("SniffFrame(%q) = %v, want VerdictNo", input, got)
			}
		})
	}
}

func TestSniffAcceptsProbeFrames(t *testing.T) {
	var sid SessionID
	copy(sid[:], "sniff-probe-sid1")

	bhp1 := frame(ModeProbe, sid, 0, probeClear("BHP1", ModeUpload, 0))
	if got := SniffFrame(bhp1); got != VerdictYes {
		t.Fatalf("BHP1 probe = %v, want VerdictYes", got)
	}

	capability := make([]byte, 10)
	copy(capability[:4], "BHP2")
	capability[4] = 2
	bhp2 := frame(ModeProbe, sid, 3, capability)
	if got := SniffFrame(bhp2); got != VerdictYes {
		t.Fatalf("BHP2 probe = %v, want VerdictYes", got)
	}
}

func TestSniffAcceptsLaneAndDataFrames(t *testing.T) {
	var sid SessionID
	copy(sid[:], "sniff-lane-sid01")

	hello := make([]byte, 12)
	copy(hello[:4], "BLN2")
	hello[4] = 2
	hello[5] = laneUpload
	binary.BigEndian.PutUint32(hello[8:], 4)
	if got := SniffFrame(frame(ModeLane, sid, 9, hello)); got != VerdictYes {
		t.Fatalf("v2 lane hello = %v, want VerdictYes", got)
	}

	// Modes 2 and 4 carry no payload; a sane header is the whole signal.
	if got := SniffFrame(frame(ModeDownload, sid, 1, nil)); got != VerdictYes {
		t.Fatalf("download frame = %v, want VerdictYes", got)
	}
	if got := SniffFrame(frame(ModeACK, sid, 2, nil)); got != VerdictYes {
		t.Fatalf("ACK frame = %v, want VerdictYes", got)
	}
	if got := SniffFrame(frame(ModeUpload, sid, 0, nil)); got != VerdictYes {
		t.Fatalf("session-open upload frame = %v, want VerdictYes", got)
	}
}

// An injection client may prepend arbitrary junk, and some of that junk starts
// with a low byte. The magic check on the frame types that carry one is what
// keeps such a connection out of BHTTP.
func TestSniffRejectsLowByteJunk(t *testing.T) {
	var sid SessionID
	copy(sid[:], "sniff-junk-sid01")

	// A probe-shaped frame whose payload is not a BHP probe at all.
	bogus := frame(ModeProbe, sid, 0, []byte("not-a-probe-payload"))
	if got := SniffFrame(bogus); got != VerdictNo {
		t.Fatalf("probe with wrong magic = %v, want VerdictNo", got)
	}

	// A lane-shaped frame whose payload is not a BLN2 hello.
	bogusLane := frame(ModeLane, sid, 0, make([]byte, 12))
	if got := SniffFrame(bogusLane); got != VerdictNo {
		t.Fatalf("lane with wrong magic = %v, want VerdictNo", got)
	}

	// Unencrypted plaintext magic must also fail: the sniff decrypts with the
	// session ID from the same header, so a copied magic string does not pass.
	plaintext := make([]byte, HeaderSize+10)
	plaintext[0] = ModeProbe
	copy(plaintext[1:17], sid[:])
	binary.BigEndian.PutUint32(plaintext[25:29], 10)
	copy(plaintext[HeaderSize:], "BHP1")
	if got := SniffFrame(plaintext); got != VerdictNo {
		t.Fatalf("plaintext magic = %v, want VerdictNo", got)
	}

	// A declared payload larger than the protocol allows is not a frame.
	oversized := make([]byte, HeaderSize)
	oversized[0] = ModeUpload
	binary.BigEndian.PutUint32(oversized[25:29], MaxPayload+1)
	if got := SniffFrame(oversized); got != VerdictNo {
		t.Fatalf("oversized payload = %v, want VerdictNo", got)
	}

	// A probe claiming more payload than a probe can hold is not a probe.
	longProbe := make([]byte, HeaderSize)
	longProbe[0] = ModeProbe
	binary.BigEndian.PutUint32(longProbe[25:29], SniffLimit)
	if got := SniffFrame(longProbe); got != VerdictNo {
		t.Fatalf("over-long probe = %v, want VerdictNo", got)
	}
}

func TestSniffAsksForMoreBytesWhenUndecided(t *testing.T) {
	var sid SessionID
	copy(sid[:], "sniff-partial-s1")
	full := frame(ModeProbe, sid, 0, probeClear("BHP1", ModeUpload, 0))

	if got := SniffFrame(nil); got != VerdictMore {
		t.Fatalf("empty input = %v, want VerdictMore", got)
	}
	if got := SniffFrame(full[:1]); got != VerdictMore {
		t.Fatalf("mode byte only = %v, want VerdictMore", got)
	}
	if got := SniffFrame(full[:HeaderSize-1]); got != VerdictMore {
		t.Fatalf("partial header = %v, want VerdictMore", got)
	}
	// Header complete but the probe payload still missing.
	if got := SniffFrame(full[:HeaderSize]); got != VerdictMore {
		t.Fatalf("header without payload = %v, want VerdictMore", got)
	}
	if got := SniffFrame(full); got != VerdictYes {
		t.Fatalf("complete probe = %v, want VerdictYes", got)
	}
}
