package bhttp

import (
	"bytes"
	"encoding/binary"
)

// Verdict is the result of inspecting the first bytes of a connection.
type Verdict int

const (
	// VerdictNo means the bytes cannot begin a BHTTP frame.
	VerdictNo Verdict = iota
	// VerdictMore means the bytes so far are consistent with BHTTP but more
	// are needed to decide. The caller should peek further and ask again.
	VerdictMore
	// VerdictYes means the bytes begin a BHTTP frame.
	VerdictYes
)

// SniffLimit is the largest number of bytes SniffFrame will ever ask for. It
// covers a full frame header plus a probe/lane payload, which is where the
// magic strings that make the decision conclusive live.
const SniffLimit = HeaderSize + 4096

// SniffFrame reports whether data begins a BHTTP frame, so a listener shared
// with other protocols can route the connection without consuming anything.
//
// The first byte alone already separates BHTTP from the protocols it shares a
// port with: a BHTTP frame opens with a mode number (0..5), while SSH opens
// with 'S' (0x53) and an HTTP request or status line opens with a method or
// version letter. Every one of those is far above ModeLane, so a single byte
// rejects them outright and costs nothing.
//
// A low first byte is not proof on its own, because HTTP-injection clients may
// prepend arbitrary junk. So the frame header is range-checked, and for the two
// modes that carry a magic string — the probe that opens every client session
// and the v2 lane hello — the magic is decrypted and verified. That check is
// keyed by the session ID in the same header, so junk cannot pass it by chance.
func SniffFrame(data []byte) Verdict {
	if len(data) == 0 {
		return VerdictMore
	}
	mode := data[0]
	if mode > ModeLane {
		return VerdictNo
	}
	if len(data) < HeaderSize {
		return VerdictMore
	}

	request := Request{Mode: mode}
	copy(request.SID[:], data[1:17])
	request.Seq = binary.BigEndian.Uint64(data[17:25])
	request.Value = binary.BigEndian.Uint32(data[25:29])

	// Modes 2 and 4 overload Value as a size hint and an empty cumulative ACK,
	// so they carry no payload to verify.
	if mode == ModeDownload || mode == ModeACK {
		return VerdictYes
	}
	if request.Value > MaxPayload {
		return VerdictNo
	}

	magic, ok := frameMagic(mode)
	if !ok {
		// Modes 1 and 3 have no magic string. A sane header is all there is.
		return VerdictYes
	}
	// An oversized payload cannot be a probe or lane hello, both of which are
	// short, so the magic would not be where it belongs.
	if int(request.Value) > SniffLimit-HeaderSize {
		return VerdictNo
	}
	end := HeaderSize + int(request.Value)
	if len(data) < end {
		return VerdictMore
	}
	clear := Crypt(data[HeaderSize:end], request.SID, mode, request.Seq, false)
	if len(clear) < len(magic) || !bytes.Equal(clear[:len(magic)], magic) {
		return VerdictNo
	}
	return VerdictYes
}

// frameMagic returns the plaintext prefix a mode's payload must start with,
// and whether that mode has one at all.
func frameMagic(mode byte) ([]byte, bool) {
	switch mode {
	case ModeProbe:
		// A probe is either the BHP1 profile or the BHP2 capability handshake;
		// both share the first three bytes, which is what is checked here.
		return []byte("BHP"), true
	case ModeLane:
		return []byte("BLN2"), true
	}
	return nil, false
}
