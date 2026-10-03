package hcr

import (
	"encoding/binary"
	"testing"
)

// hcrHeader builds a valid 62-byte request header.
func hcrHeader(code, version byte, payloadLen uint32) []byte {
	b := make([]byte, RequestHeaderSize)
	b[0] = code
	b[1] = version
	b[2] = 0xAB // session id byte
	binary.BigEndian.PutUint32(b[58:62], payloadLen)
	return b
}

func TestSniffRejectsOtherProtocols(t *testing.T) {
	cases := map[string]string{
		"SSH":         "SSH-2.0-x\r\n",
		"HTTP GET":    "GET / HTTP/1.1\r\n",
		"BTUN":        "DTUNNEL/1.1 CLIENT_HELLO\r\n",
		"BHTTP probe": "\x00\x11\x22\x33",
		"TLS hello":   "\x16\x03\x01\x00",
	}
	for name, in := range cases {
		if got := SniffFrame([]byte(in)); got != VerdictNo {
			t.Fatalf("%s: SniffFrame = %v, want VerdictNo", name, got)
		}
	}
}

func TestSniffAcceptsValidHeaders(t *testing.T) {
	for code := byte(1); code <= 6; code++ {
		if got := SniffFrame(hcrHeader(code, ProtoVersion, 100)); got != VerdictYes {
			t.Fatalf("code %d: SniffFrame = %v, want VerdictYes", code, got)
		}
	}
}

// A BHTTP frame whose session UUID happens to start 0x01 must NOT be stolen:
// its bytes at [58:62] are not a valid HCR payload length.
func TestSniffRejectsBhttpLookalike(t *testing.T) {
	b := make([]byte, RequestHeaderSize)
	b[0] = 0x01                                             // BHTTP upload / HCR connect
	b[1] = 0x01                                             // UUID happens to start 0x01
	binary.BigEndian.PutUint32(b[58:62], MaxPayloadLimit+1) // invalid HCR len
	if got := SniffFrame(b); got != VerdictNo {
		t.Fatalf("lookalike: SniffFrame = %v, want VerdictNo", got)
	}
}

// A clean BHTTP frame (byte1 != 0x01) is rejected at two bytes — no 62-byte wait.
func TestSniffFastRejectsCleanBhttp(t *testing.T) {
	if got := SniffFrame([]byte{0x01, 0x7A}); got != VerdictNo {
		t.Fatalf("clean BHTTP: SniffFrame(2B) = %v, want VerdictNo", got)
	}
}

func TestSniffProgressive(t *testing.T) {
	full := hcrHeader(1, ProtoVersion, 10)
	if got := SniffFrame(nil); got != VerdictMore {
		t.Fatalf("empty = %v, want More", got)
	}
	if got := SniffFrame(full[:1]); got != VerdictMore {
		t.Fatalf("1 byte = %v, want More", got)
	}
	if got := SniffFrame(full[:2]); got != VerdictMore {
		t.Fatalf("2 bytes (ver=1) = %v, want More", got)
	}
	if got := SniffFrame(full[:RequestHeaderSize-1]); got != VerdictMore {
		t.Fatalf("61 bytes = %v, want More", got)
	}
	if got := SniffFrame(full); got != VerdictYes {
		t.Fatalf("full = %v, want Yes", got)
	}
}

func TestSniffRejectsWrongVersion(t *testing.T) {
	if got := SniffFrame(hcrHeader(1, 0x02, 10)); got != VerdictNo {
		t.Fatalf("version 2 = %v, want No", got)
	}
}
