package main

// This file lets the tunnel transports share the ports the panel already owns:
// the HTTP+SSH proxy listeners (listen and extra_listen, normally 80 and 8080)
// and the TLS forwarders (normally 443).
//
// It works because the protocols on these ports open in mutually incompatible
// ways. A BHTTP frame starts with its mode number (0..5). A BTUN session starts
// with the fixed ASCII marker "DTUNNEL/1.1 CLIENT_HELLO". SSH starts with "SSH-"
// and an HTTP request or status line starts with a method or version letter.
// Each transport's own package owns the check for its wire format, so the rules
// live next to the protocol they describe.
//
// Nothing is ever consumed on a negative verdict: the bytes stay in the
// returned reader, and the caller continues with its normal handling as if this
// file did not exist.

import (
	"bufio"
	"encoding/binary"
	"net"
	"time"

	"github.com/dakarpy/ConectaSSH-PRO/internal/bhttp"
	"github.com/dakarpy/ConectaSSH-PRO/internal/btun"
	"github.com/dakarpy/ConectaSSH-PRO/internal/hcr"
)

// tunnelSniffTimeout bounds how long a shared listener waits for a client's
// first bytes. Every protocol here speaks immediately on connect, so a client
// that says nothing for this long is handed to the normal HTTP/SSH path rather
// than being held any longer.
const tunnelSniffTimeout = 3 * time.Second

// tunnelSharedReaderSize must hold the largest prefix any sniff can ask for.
const tunnelSharedReaderSize = bhttp.SniffLimit + 64

// tunnelShareEnabled reports whether any transport wants the shared ports, so
// the listeners can skip all of this when none do.
func tunnelShareEnabled() bool {
	return bhttpShareEnabled() || btunShareEnabled() || hcrShareEnabled()
}

// tunnelTakeSharedConn inspects the front of a connection that arrived on a
// port owned by another protocol and, when it belongs to a tunnel transport,
// serves it to completion.
//
// It returns the reader to keep using and whether the connection was consumed.
// When it returns false the caller continues with its normal handling, and the
// returned reader holds every byte that was inspected.
func tunnelTakeSharedConn(conn net.Conn, reader *bufio.Reader) (*bufio.Reader, bool) {
	if reader == nil {
		reader = bufio.NewReaderSize(conn, tunnelSharedReaderSize)
	}
	bhttpOn := bhttpShareEnabled()
	btunOn := btunShareEnabled()
	hcrOn := hcrShareEnabled()
	if !bhttpOn && !btunOn && !hcrOn {
		return reader, false
	}

	// The sniff needs its own deadline: the caller has not set one yet, and a
	// client that connects without sending must not wedge this goroutine.
	_ = conn.SetReadDeadline(time.Now().Add(tunnelSniffTimeout))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	// BTUN is checked first because its marker is a fixed string that either
	// matches from the first byte or does not. The two transports cannot both
	// claim a connection: a BHTTP frame opens with a byte below 6 and the BTUN
	// marker opens with 'D'.
	if btunOn && tunnelSniff(reader, btunSniffStep) {
		return reader, btunServeShared(conn, reader)
	}
	if hcrOn && tunnelSniff(reader, hcrSniffStep) {
		return reader, hcrServeShared(conn, reader)
	}
	if bhttpOn && tunnelSniff(reader, bhttpSniffStep) {
		return reader, bhttpServeShared(conn, reader)
	}
	return reader, false
}

// sniffStep inspects the bytes peeked so far. It returns the protocol's verdict
// and, when undecided, how many bytes to peek before asking again.
type sniffStep func(peeked []byte) (verdict int, want int)

// The verdicts a sniffStep may return, shared by both transports.
const (
	sniffNo = iota
	sniffMore
	sniffYes
)

// tunnelSniff runs one protocol's check, peeking progressively so a protocol
// that is rejected on its first byte costs exactly one byte of lookahead.
func tunnelSniff(reader *bufio.Reader, step sniffStep) bool {
	want := 1
	for {
		peeked, err := reader.Peek(want)
		verdict, next := sniffNo, want
		if len(peeked) > 0 {
			verdict, next = step(peeked)
		}
		switch {
		case verdict == sniffYes:
			return true
		case verdict == sniffNo:
			return false
		case err != nil:
			// Not enough bytes arrived to decide, so this is not the protocol
			// as far as this listener is concerned.
			return false
		case next <= len(peeked):
			// A step that cannot make progress would loop forever.
			return false
		}
		want = next
	}
}

// btunSniffStep matches the fixed BTUN client hello.
func btunSniffStep(peeked []byte) (int, int) {
	switch btun.SniffClientHello(peeked) {
	case btun.VerdictYes:
		return sniffYes, 0
	case btun.VerdictMore:
		return sniffMore, btun.SniffLimit
	}
	return sniffNo, 0
}

// bhttpSniffStep matches a BHTTP frame: the header first, then the payload the
// header declares, which is where the magic strings that settle it live.
func bhttpSniffStep(peeked []byte) (int, int) {
	switch bhttp.SniffFrame(peeked) {
	case bhttp.VerdictYes:
		return sniffYes, 0
	case bhttp.VerdictMore:
		if len(peeked) < bhttp.HeaderSize {
			return sniffMore, bhttp.HeaderSize
		}
		want := bhttp.HeaderSize + int(binary.BigEndian.Uint32(peeked[25:29]))
		if want > bhttp.SniffLimit {
			want = bhttp.SniffLimit
		}
		return sniffMore, want
	}
	return sniffNo, 0
}

// hcrSniffStep matches an HCR request: its opcode, then its fixed version byte,
// then the full 62-byte header. A BHTTP frame whose session byte is not 0x01 is
// rejected at two bytes, so it never waits for 62 bytes.
func hcrSniffStep(peeked []byte) (int, int) {
	switch hcr.SniffFrame(peeked) {
	case hcr.VerdictYes:
		return sniffYes, 0
	case hcr.VerdictMore:
		if len(peeked) < 2 {
			return sniffMore, 2
		}
		return sniffMore, hcr.RequestHeaderSize
	}
	return sniffNo, 0
}

// hcrServeShared hands an identified connection to the running HCR server.
func hcrServeShared(conn net.Conn, reader *bufio.Reader) bool {
	hcrMu.Lock()
	server := hcrServer
	ctx := hcrCtx
	hcrMu.Unlock()
	if server == nil || ctx == nil {
		return false
	}
	// The engine's own debug log records the session; no extra line here.
	server.ServeConn(ctx, &bufferedConn{Conn: conn, r: reader})
	return true
}

// bhttpServeShared hands an identified connection to the running BHTTP server.
func bhttpServeShared(conn net.Conn, reader *bufio.Reader) bool {
	bhttpMu.Lock()
	server := bhttpServer
	bhttpMu.Unlock()
	if server == nil {
		return false
	}
	if bhttpLogConnections() {
		bhttpLog.Printf("shared port: %s -> %s handed to BHTTP", conn.RemoteAddr(), conn.LocalAddr())
	}
	// The inspected bytes live in the reader, so the server has to read through
	// it rather than from the socket.
	server.ServeConn(&bufferedConn{Conn: conn, r: reader})
	return true
}

// btunServeShared hands an identified connection to the running BTUN server.
func btunServeShared(conn net.Conn, reader *bufio.Reader) bool {
	btunMu.Lock()
	server := btunServer
	btunMu.Unlock()
	if server == nil {
		return false
	}
	if btunLogConnections() {
		btunLog.Printf("shared port: %s -> %s handed to BTUN", conn.RemoteAddr(), conn.LocalAddr())
	}
	server.ServeConn(&bufferedConn{Conn: conn, r: reader})
	return true
}

func bhttpLogConnections() bool {
	globalCfgMu.RLock()
	defer globalCfgMu.RUnlock()
	return globalCfg != nil && globalCfg.BHTTP != nil && globalCfg.BHTTP.LogConnections
}

func btunLogConnections() bool {
	globalCfgMu.RLock()
	defer globalCfgMu.RUnlock()
	return globalCfg != nil && globalCfg.BTUN != nil && globalCfg.BTUN.LogConnections
}
