package hcr

import "encoding/binary"

// Verdict is the result of inspecting the first bytes of a connection.
type Verdict int

const (
	// VerdictNo means the bytes cannot begin an HCR request.
	VerdictNo Verdict = iota
	// VerdictMore means the bytes so far are consistent with HCR but more are
	// needed to decide. The caller should peek further and ask again.
	VerdictMore
	// VerdictYes means the bytes begin a valid HCR request header.
	VerdictYes
)

// SniffLimit is the largest number of bytes SniffFrame ever needs: the full
// fixed request header.
const SniffLimit = RequestHeaderSize

// IsHeader reports whether buf is a complete, valid 62-byte HCR request header.
// This is the strict check the coexistence design relies on: only a full header
// with the fixed protocol version and an in-range payload length counts.
func IsHeader(buf []byte) bool {
	if len(buf) < RequestHeaderSize {
		return false
	}
	code := buf[0]
	if code < 1 || code > 6 {
		return false
	}
	if buf[1] != ProtoVersion {
		return false
	}
	if binary.BigEndian.Uint32(buf[58:62]) > MaxPayloadLimit {
		return false
	}
	return true
}

// SniffFrame reports whether data begins an HCR request, so a port shared with
// BHTTP (and SSH, HTTP injection) can route the connection without consuming
// anything.
//
// HCR and BHTTP deliberately overlap on the first byte (opcodes 1..4 mean
// upload/download/… in both). The discriminator is HCR's fixed protocol version
// at byte [1] (always 0x01) and its 62-byte header layout, checked in full:
//
//   - byte 0 must be an HCR opcode (1..6); anything else (including BHTTP's
//     probe 0x00) is not HCR.
//   - byte 1 must be 0x01. A BHTTP frame's byte [1] is the first byte of its
//     random session UUID, so it is 0x01 only by chance — and that is the only
//     case where HCR waits for the full 62 bytes. A "clean" BHTTP frame is
//     rejected here at two bytes, with no stall, and falls through to BHTTP.
//   - the full 62-byte header must pass IsHeader. A BHTTP frame whose UUID
//     happens to start 0x01 almost never has a valid HCR payload length at
//     [58:62], so it is rejected and BHTTP still handles it.
//
// The caller must try HCR before BHTTP, exactly because a real HCR Connect
// (opcode 1) also looks like a BHTTP upload on the first byte.
func SniffFrame(data []byte) Verdict {
	if len(data) == 0 {
		return VerdictMore
	}
	if data[0] < 1 || data[0] > 6 {
		return VerdictNo
	}
	if len(data) < 2 {
		return VerdictMore
	}
	if data[1] != ProtoVersion {
		// Not HCR: a BHTTP frame or junk. Reject now so BHTTP gets its fast
		// 29-byte path with no wait for 62 bytes.
		return VerdictNo
	}
	if len(data) < RequestHeaderSize {
		return VerdictMore
	}
	if IsHeader(data[:RequestHeaderSize]) {
		return VerdictYes
	}
	return VerdictNo
}
