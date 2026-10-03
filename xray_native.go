package main

// Pure-Go, in-process Xray emulator.
//
// This is the Xray equivalent of the in-process SSH server in main.go: instead
// of shelling out to an external `xray run -c config.json` subprocess, the
// supported protocols are spoken directly in Go and every accepted stream is
// tunnelled with the same copyWithRateLimit machinery the SSH side uses.
//
// Native emulator scope:
//   - Protocols : VLESS and VMess AEAD (TCP + UDP commands)
//   - VLESS Mux : Mux.Cool child TCP/UDP sessions, including XUDP metadata
//   - Transports: raw TCP, WebSocket (RFC 6455), XHTTP/SplitHTTP
//   - Security  : TLS, none
//
// REALITY, gRPC and HTTPUpgrade are still deferred; unsupported commands are
// rejected explicitly instead of silently falling back.
//
// Native mode has its own DB-backed config/runtime path. It does not spawn or
// query the external xray binary and does not require /opt/sshpanel/xray to be
// installed. The JSON shape remains Xray-compatible so the same panel wizard can
// generate native and external configs.

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// ---------- parsed config model ----------

// nativeXrayClient is one authorized user parsed from an inbound's clients array.
type nativeXrayClient struct {
	id    [16]byte // parsed UUID bytes, used as the fast lookup key
	uuid  string   // canonical string form (for logs)
	email string   // stats label

	// VMess-only material, precomputed at parse time (nil/zero for VLESS).
	cmdKey       [16]byte     // MD5(uuid || vmess magic)
	authIDCipher cipher.Block // AES-128 over KDF16(cmdKey, "AES Auth ID Encryption")
}

// nativeInbound is a single listener built from one JSON inbound entry.
type nativeInbound struct {
	tag        string
	protocol   string // "vless" | "vmess" | "ssh" (XHTTP->SSH tunnel)
	listen     string // bind host, default 0.0.0.0
	port       int
	transport  string // "tcp" | "ws" | "xhttp" | ...
	path       string // ws/xhttp request path (default "/")
	security   string // "tls" | "" (none)
	sharedPort bool   // ConectaSSH-PRO public SSH/HTTP and TLS listeners own the socket

	// XHTTP/SplitHTTP transport options. Only the fields that affect the wire
	// format are mirrored here; unsupported obfuscation/padding knobs are ignored
	// leniently so existing panel configs keep working.
	xhttpHost                string
	xhttpMode                string
	xhttpSessionPlacement    string
	xhttpSessionKey          string
	xhttpSeqPlacement        string
	xhttpSeqKey              string
	xhttpUplinkDataPlacement string
	xhttpUplinkDataKey       string
	xhttpMaxEachPostBytes    int64
	xhttpMaxBufferedPosts    int
	xhttpMaxHeaderBytes      int
	xhttpNoSSEHeader         bool
	xhttpSessions            map[string]*nativeXHTTPSession
	xhttpMu                  sync.Mutex

	tlsConfig *tls.Config // built when security == "tls"

	clientMu    sync.RWMutex
	clientsByID map[[16]byte]*nativeXrayClient

	// Per-connection bandwidth ceilings in bytes/sec (0 = unlimited). Sourced
	// from the panel's default limits, matching the SSH tunnel behaviour.
	upBytesPerSec   int
	downBytesPerSec int
}

// ---------- listener manager ----------

type nativeXrayServer struct {
	mu            sync.Mutex
	listeners     []net.Listener
	inboundsByTag map[string]*nativeInbound
	running       bool
	startTime     time.Time
	shared        atomic.Pointer[sharedXrayRouter]
}

var nativeXray = &nativeXrayServer{}

// nativeXHTTPListener groups all XHTTP inbounds that bind the same address.
// XHTTP is ordinary HTTP at the transport layer, so routing by the configured
// path lets VLESS/VMess and the ConectaSSH-PRO SSH tunnel safely share one TLS port.
// The most specific path wins: for example /ssh/ is checked before /.
type nativeXHTTPListener struct {
	addr       string
	inbounds   []*nativeInbound
	tlsConfig  *tls.Config
	security   string
	headerSize int
}

// nativeRunning reports whether the in-process Xray listeners are up.
func (s *nativeXrayServer) nativeRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// start parses the config file and opens a listener for every supported
// inbound. It is idempotent-ish: callers (XrayManager) guard against double
// start, but start() will refuse if already running.
func (s *nativeXrayServer) start(configFile string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return fmt.Errorf("native xray already running")
	}
	beginNativeTransportAccepting()
	started := false
	defer func() {
		if !started {
			stopNativeTransportAccepting()
			closeAllNativeTransportConnections()
		}
	}()
	if configFile == "" {
		return fmt.Errorf("native xray: no config file configured")
	}

	inbounds, err := parseNativeInbounds(configFile)
	if err != nil {
		return err
	}
	if len(inbounds) == 0 {
		return fmt.Errorf("native xray: no servable inbounds in %s", configFile)
	}
	if data, err := os.ReadFile(configFile); err != nil {
		return err
	} else if err := validateNativeInboundBindings(data); err != nil {
		return err
	}

	var opened []net.Listener
	active := make(map[string]*nativeInbound, len(inbounds))
	xhttpGroups := make(map[string][]*nativeInbound)
	var xhttpOrder []string
	for _, ib := range inbounds {
		if ib.sharedPort {
			active[ib.tag] = ib
			continue
		}
		if ib.isXHTTP() {
			addr := net.JoinHostPort(ib.listen, strconv.Itoa(ib.port))
			if _, exists := xhttpGroups[addr]; !exists {
				xhttpOrder = append(xhttpOrder, addr)
			}
			xhttpGroups[addr] = append(xhttpGroups[addr], ib)
			active[ib.tag] = ib
			continue
		}
		addr := net.JoinHostPort(ib.listen, strconv.Itoa(ib.port))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			// Roll back anything already opened so we don't leak listeners.
			for _, l := range opened {
				_ = l.Close()
			}
			return fmt.Errorf("native xray: listen %s (inbound %q): %w", addr, ib.tag, err)
		}

		opened = append(opened, ln)
		xrayGo(fmt.Sprintf("native xray accept loop %s", addr), func() { ib.acceptLoop(ln) })
		active[ib.tag] = ib
		xrayLogf("native xray: serving %s/%s on %s (inbound %q, security=%s, %d clients)",
			ib.protocol, ib.transport, addr, ib.tag, orNone(ib.security), ib.clientCount())
	}
	shared, err := newSharedXrayRouter(inbounds)
	if err != nil {
		for _, l := range opened {
			_ = l.Close()
		}
		return err
	}

	for _, addr := range xhttpOrder {
		group, err := newNativeXHTTPListener(addr, xhttpGroups[addr])
		if err != nil {
			for _, l := range opened {
				_ = l.Close()
			}
			return err
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			for _, l := range opened {
				_ = l.Close()
			}
			return fmt.Errorf("native xray: listen %s (shared XHTTP): %w", addr, err)
		}
		// Track accepted sockets so stop/reload can close them. VPN transports are
		// not subject to a global website-style connection ceiling.
		serveLn := trackNativeListener(ln)
		if group.security == "tls" {
			serveLn = tls.NewListener(serveLn, group.tlsConfig)
		}
		opened = append(opened, serveLn)
		xrayGo(fmt.Sprintf("native xray shared xhttp listener %s", addr), func() { group.serve(serveLn) })
		for _, ib := range group.inbounds {
			xrayLogf("native xray: serving %s/%s on %s%s (inbound %q, security=%s, %d clients)",
				ib.protocol, ib.transport, addr, ib.path, ib.tag, orNone(ib.security), ib.clientCount())
		}
	}

	if shared != nil {
		opened = append(opened, shared.listeners...)
		s.shared.Store(shared)
		for _, ib := range inbounds {
			if ib.sharedPort {
				xrayLogf("native xray: serving %s/%s on ConectaSSH-PRO public ports%s (inbound %q, %d clients)", ib.protocol, ib.transport, ib.path, ib.tag, ib.clientCount())
			}
		}
		if shared.xhttp != nil {
			xrayGo("native xray shared public XHTTP", func() { shared.xhttp.serve(trackNativeListener(shared.httpListener)) })
		}
	}
	s.listeners = opened
	s.inboundsByTag = active
	s.running = true
	s.startTime = time.Now()
	started = true
	return nil
}

func (s *nativeXrayServer) stop() {
	s.mu.Lock()
	if !s.running && len(s.listeners) == 0 {
		s.mu.Unlock()
		return
	}
	stopNativeTransportAccepting()
	listeners := append([]net.Listener(nil), s.listeners...)
	inbounds := make([]*nativeInbound, 0, len(s.inboundsByTag))
	for _, ib := range s.inboundsByTag {
		inbounds = append(inbounds, ib)
	}
	s.listeners = nil
	s.inboundsByTag = nil
	s.running = false
	s.shared.Store(nil)
	s.mu.Unlock()

	for _, l := range listeners {
		_ = l.Close()
	}
	closeAllNativeTransportConnections()
	for _, ib := range inbounds {
		ib.closeAllXHTTPSessions()
	}
	xrayLogf("native xray: stopped")
}

func (ib *nativeInbound) acceptLoop(ln net.Listener) {
	defer xrayRecover(fmt.Sprintf("native xray accept loop inbound=%q", ib.tag))
	for {
		c, err := ln.Accept()
		if err != nil {
			if isListenerClosed(err) {
				return
			}
			xrayLogf("native xray: accept error on %s: %v", ln.Addr(), err)
			continue
		}
		counted, ok := waitWrapTrackedNativeTransportConn(c)
		if !ok {
			time.Sleep(nativeOverloadBackoff)
			continue
		}
		c = counted
		xrayGo(fmt.Sprintf("native xray connection remote=%s", c.RemoteAddr()), func() { ib.serve(c) })
	}
}

// serve terminates TLS + transport, then dispatches on protocol.
func (ib *nativeInbound) serve(raw net.Conn) {
	defer xrayRecover(fmt.Sprintf("native xray serve inbound=%q remote=%s", ib.tag, raw.RemoteAddr()))
	defer raw.Close()

	if tc, ok := raw.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
		_ = tc.SetNoDelay(true)
	}

	// --- security layer ---
	var conn net.Conn = raw
	if ib.security == "tls" {
		tconn := tls.Server(raw, ib.tlsConfig)
		_ = tconn.SetDeadline(time.Now().Add(tlsHandshakeTimeout))
		if err := tconn.Handshake(); err != nil {
			logNativePreAuthRejection("native xray: tls handshake from %s failed: %v", raw.RemoteAddr(), err)
			return
		}
		_ = tconn.SetDeadline(time.Time{})
		conn = tconn
	}

	// --- transport layer ---
	var stream net.Conn = conn
	switch ib.transport {
	case "tcp", "raw", "":
		// stream is already the protocol stream
	case "ws", "websocket":
		_ = conn.SetDeadline(time.Now().Add(tlsHandshakeTimeout))
		ws, err := wsServerHandshake(conn, ib.path)
		if err != nil {
			logNativePreAuthRejection("native xray: ws handshake from %s failed: %v", raw.RemoteAddr(), err)
			return
		}
		_ = conn.SetDeadline(time.Time{})
		stream = ws
	case "xhttp", "splithttp":
		xrayLogf("native xray: inbound %q got raw connection for XHTTP; this transport is served by http.Server", ib.tag)
		return
	default:
		xrayLogf("native xray: inbound %q transport %q not supported yet; dropping conn from %s",
			ib.tag, ib.transport, raw.RemoteAddr())
		return
	}

	// --- protocol layer ---
	switch ib.protocol {
	case "vless":
		ib.handleVLESS(stream, raw.RemoteAddr())
	case "vmess":
		ib.handleVMess(stream, raw.RemoteAddr())
	default:
		xrayLogf("native xray: inbound %q protocol %q not supported yet; dropping conn from %s",
			ib.tag, ib.protocol, raw.RemoteAddr())
	}
}

// ---------- VLESS ----------
//
// VLESS request header (client -> server):
//   1  byte  version (0)
//   16 bytes UUID
//   1  byte  addon length M
//   M  bytes addons (flow etc.) — skipped
//   1  byte  command (1=TCP, 2=UDP, 3=Mux)
//   for TCP/UDP only:
//     2  bytes port (big endian)
//     1  byte  address type (1=IPv4, 2=domain, 3=IPv6)
//     ...      address
//   for Mux:
//     ...      Mux.Cool/XUDP frames immediately after the command byte
//   ...      payload
// Response (server -> client): 1 byte version echo, 1 byte addon length (0).

const (
	vlessCmdTCP = 1
	vlessCmdUDP = 2
	vlessCmdMux = 3

	atypIPv4   = 1
	atypDomain = 2
	atypIPv6   = 3
)

func (ib *nativeInbound) handleVLESS(stream net.Conn, remote net.Addr) {
	defer xrayRecover(fmt.Sprintf("native xray VLESS inbound=%q remote=%s", ib.tag, remote))
	xrayTracef("native xray: vless handshake start inbound=%q transport=%s remote=%s", ib.tag, ib.transport, remote)
	_ = stream.SetReadDeadline(time.Now().Add(30 * time.Second))

	head := make([]byte, 1+16+1) // version + uuid + addonLen
	if _, err := io.ReadFull(stream, head); err != nil {
		ib.logVLESSReadFailure("handshake", remote, "", err)
		return
	}
	version := head[0]
	var id [16]byte
	copy(id[:], head[1:17])

	client := ib.getNativeClient(id)
	if client == nil {
		logNativePreAuthRejection("native xray: inbound %q rejected unknown VLESS uuid from %s", ib.tag, remote)
		return
	}
	if reason := xrayMgr.nativeClientAccessDenied(client.uuid); reason != "" {
		xrayLogf("native xray: inbound %q rejected VLESS user %s: %s", ib.tag, client.email, reason)
		return
	}

	if addonLen := int(head[17]); addonLen > 0 {
		if _, err := io.CopyN(io.Discard, stream, int64(addonLen)); err != nil {
			xrayLogf("native xray: vless addon read failed inbound=%q user=%s: %v", ib.tag, client.email, err)
			return
		}
	}

	var cmd [1]byte
	if _, err := io.ReadFull(stream, cmd[:]); err != nil {
		ib.logVLESSReadFailure("command", remote, client.email, err)
		return
	}

	var host string
	var port uint16
	if cmd[0] == vlessCmdTCP || cmd[0] == vlessCmdUDP {
		var portBuf [2]byte
		if _, err := io.ReadFull(stream, portBuf[:]); err != nil {
			xrayLogf("native xray: vless port read failed inbound=%q user=%s: %v", ib.tag, client.email, err)
			return
		}
		port = binary.BigEndian.Uint16(portBuf[:])

		var err error
		host, err = readProxyAddress(stream)
		if err != nil {
			xrayLogf("native xray: inbound %q VLESS bad address from %s: %v", ib.tag, remote, err)
			return
		}
		if isNativeDNSSinkTarget(host) {
			_ = stream.SetReadDeadline(time.Time{})
			_ = stream.SetWriteDeadline(time.Now().Add(time.Second))
			_, _ = stream.Write([]byte{version, 0})
			xrayTracef("native xray: inbound %q fast-ignored DNS sink target cmd=%d user=%s host=%q port=%d remote=%s", ib.tag, cmd[0], client.email, host, port, remote)
			return
		}
		if invalidNativeDestination(host, port) {
			xrayTracef("native xray: inbound %q rejected invalid VLESS target cmd=%d user=%s host=%q port=%d remote=%s", ib.tag, cmd[0], client.email, host, port, remote)
			return
		}
	}
	_ = stream.SetReadDeadline(time.Time{})

	switch cmd[0] {
	case vlessCmdTCP, vlessCmdUDP, vlessCmdMux:
	default:
		xrayLogf("native xray: inbound %q VLESS command %d not supported yet", ib.tag, cmd[0])
		return
	}
	releaseConnection, quotaState, ok := xrayMgr.acquireNativeClientConnection(client.uuid, client.email, stream)
	if !ok {
		return
	}
	defer releaseConnection()

	// VLESS response header must be sent before relaying payload. CommandMux is
	// special: official Xray does not read a target from the VLESS header for it;
	// the following bytes are Mux.Cool/XUDP frames. Reading port/address here
	// deadlocks muxed UDP clients and shows up as QUIC/YouTube stalls.
	if _, err := stream.Write([]byte{version, 0}); err != nil {
		xrayLogf("native xray: vless response write failed inbound=%q user=%s: %v", ib.tag, client.email, err)
		return
	}

	switch cmd[0] {
	case vlessCmdTCP:
		backend, target, err := ib.nativeDialTCP(host, port)
		if err != nil {
			xrayLogf("native xray: inbound %q VLESS TCP dial %s failed: %v", ib.tag, target, err)
			return
		}
		ib.nativeSuccessLogf("native xray: vless/tcp user=%s src=%s -> %s (inbound %q)", client.email, backend.LocalAddr(), target, ib.tag)
		nativeTunnel(stream, backend, client.uuid, client.email, quotaState, ib.upLimiter(), ib.downLimiter())
	case vlessCmdUDP:
		backend, target, err := ib.nativeDialUDP(host, port)
		if err != nil {
			xrayLogf("native xray: inbound %q VLESS UDP dial %s failed: %v", ib.tag, target, err)
			return
		}
		ib.nativeSuccessLogf("native xray: vless/udp user=%s src=%s -> %s (inbound %q)", client.email, backend.LocalAddr(), target, ib.tag)
		nativeVLESSUDPTunnel(stream, backend, client.uuid, client.email, quotaState, ib.upLimiter(), ib.downLimiter())
	case vlessCmdMux:
		ib.nativeSuccessLogf("native xray: vless/mux user=%s remote=%s (inbound %q)", client.email, remote, ib.tag)
		ib.nativeVLESSMuxTunnel(stream, client.uuid, client.email, quotaState)
	}
}

func (ib *nativeInbound) logVLESSReadFailure(stage string, remote net.Addr, email string, err error) {
	if ib.isXHTTP() && isNativeDeadlineError(err) {
		if email == "" {
			xrayTracef("native xray: vless %s timed out inbound=%q transport=%s remote=%s: %v", stage, ib.tag, ib.transport, remote, err)
		} else {
			xrayTracef("native xray: vless %s timed out inbound=%q transport=%s user=%s remote=%s: %v", stage, ib.tag, ib.transport, email, remote, err)
		}
		return
	}
	if email == "" {
		logNativePreAuthRejection("native xray: vless %s failed inbound=%q transport=%s remote=%s: %v", stage, ib.tag, ib.transport, remote, err)
	} else {
		xrayLogf("native xray: vless %s failed inbound=%q transport=%s user=%s remote=%s: %v", stage, ib.tag, ib.transport, email, remote, err)
	}
}

func isNativeDeadlineError(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func invalidNativeDestination(host string, port uint16) bool {
	host = strings.TrimSpace(normalizeNativeTargetHost(host))
	if host == "" || port == 0 {
		return true
	}
	if ip := net.ParseIP(stripNativeIPZone(host)); ip != nil {
		return ip.IsUnspecified()
	}
	return false
}

func isNativeDNSSinkTarget(host string) bool {
	host = strings.TrimSpace(normalizeNativeTargetHost(host))
	if host == "" {
		return false
	}
	ip := net.ParseIP(stripNativeIPZone(host))
	return ip != nil && ip.IsUnspecified()
}

func (ib *nativeInbound) nativeSuccessLogf(format string, args ...interface{}) {
	if ib != nil && ib.isXHTTP() {
		xrayTracef(format, args...)
		return
	}
	xrayLogf(format, args...)
}

// readProxyAddress reads a VMess/VLESS-style address (type byte + address).
func readProxyAddress(r io.Reader) (string, error) {
	var t [1]byte
	if _, err := io.ReadFull(r, t[:]); err != nil {
		return "", err
	}
	switch t[0] {
	case atypIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return "", err
		}
		d := make([]byte, int(l[0]))
		if _, err := io.ReadFull(r, d); err != nil {
			return "", err
		}
		return string(d), nil
	case atypIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	default:
		return "", fmt.Errorf("unknown address type %d", t[0])
	}
}

func (ib *nativeInbound) nativeDialTCP(host string, port uint16) (net.Conn, string, error) {
	return ib.nativeDialTarget("tcp", host, port)
}

func (ib *nativeInbound) nativeDialUDP(host string, port uint16) (net.Conn, string, error) {
	return ib.nativeDialTarget("udp", host, port)
}

func nativeDialTCP(host string, port uint16) (net.Conn, string, error) {
	return nativeDialTarget("tcp", host, port)
}

func nativeDialUDP(host string, port uint16) (net.Conn, string, error) {
	return nativeDialTarget("udp", host, port)
}

func nativeDialTarget(network, host string, port uint16) (net.Conn, string, error) {
	return nativeDialTargetWithSource(network, host, port, "")
}

func (ib *nativeInbound) nativeDialTarget(network, host string, port uint16) (net.Conn, string, error) {
	return nativeDialTargetWithSource(network, host, port, ib.listen)
}

func nativeDialTargetWithSource(network, host string, port uint16, sourceHost string) (net.Conn, string, error) {
	targetHost := normalizeNativeTargetHost(host)
	target := net.JoinHostPort(targetHost, strconv.Itoa(int(port)))
	dialNetwork := nativeDialNetwork(network, targetHost)

	// IPv6 tunnel traffic must remain IPv6, but binding to the inbound/listen
	// address is not always valid on providers with routed /128s, policy routing,
	// or multiple IPv6 addresses. Try the source-bound dial first when it makes
	// sense, then fall back to the kernel's normal source selection before giving
	// up. This mirrors external Xray/freedom behavior more closely and prevents
	// client-side ERR_CONNECTION_CLOSED when the first IPv6 source choice fails.
	var attempts []net.Addr
	if local := nativeLocalAddrForDial(dialNetwork, targetHost, sourceHost); local != nil {
		attempts = append(attempts, local)
	}
	attempts = append(attempts, nil)

	var lastErr error
	for i, local := range attempts {
		ctx, cancel := context.WithTimeout(context.Background(), directTCPIPDialTimeout)
		d := &net.Dialer{Timeout: directTCPIPDialTimeout, KeepAlive: 30 * time.Second}
		if local != nil {
			d.LocalAddr = local
		}
		conn, err := d.DialContext(ctx, dialNetwork, target)
		cancel()
		if err == nil {
			if i > 0 && len(attempts) > 1 {
				xrayLogf("native xray: outbound dial recovered target=%s network=%s using auto source after bound source failed", target, dialNetwork)
			}
			return conn, target, nil
		}
		lastErr = err
		if local != nil {
			xrayLogf("native xray: outbound dial target=%s network=%s source=%s failed, retrying auto source: %v", target, dialNetwork, local.String(), err)
		}
	}
	return nil, target, lastErr
}

func nativeDialNetwork(base, host string) string {
	if base != "tcp" && base != "udp" {
		return base
	}
	ip := net.ParseIP(normalizeNativeTargetHost(host))
	if ip == nil {
		// Domain targets must remain dual-stack. Let Go's dialer use the server's
		// resolver and Happy Eyeballs instead of forcing IPv4. This matches the
		// expected behavior when the Android client has IPv6 route enabled.
		return base
	}
	if ip.To4() != nil {
		return base + "4"
	}
	return base + "6"
}

func nativeLocalAddrForDial(network, targetHost, sourceHost string) net.Addr {
	base := network
	if strings.HasSuffix(base, "4") || strings.HasSuffix(base, "6") {
		base = base[:len(base)-1]
	}
	if base != "tcp" && base != "udp" {
		return nil
	}
	targetIP := net.ParseIP(normalizeNativeTargetHost(targetHost))
	if targetIP == nil {
		return nil
	}
	sourceIP := net.ParseIP(normalizeNativeListenHost(sourceHost))
	if sourceIP == nil || sourceIP.IsUnspecified() {
		return nil
	}
	// The tunnel must preserve the target address family. When the client sends
	// an IPv6 destination, bind the outbound socket to the inbound/listen IPv6
	// address so Linux does not select a different or unrouted IPv6 source. This
	// fixes the case where the Android client has IPv6 enabled and sends AAAA
	// destinations through VLESS/VMess. Do not bind an IPv4 source for an IPv6
	// target, or the dial will fail before leaving the server.
	if targetIP.To4() == nil {
		if sourceIP.To4() != nil {
			return nil
		}
		if base == "tcp" {
			return &net.TCPAddr{IP: sourceIP}
		}
		return &net.UDPAddr{IP: sourceIP}
	}
	if sourceIP.To4() == nil {
		return nil
	}
	if base == "tcp" {
		return &net.TCPAddr{IP: sourceIP}
	}
	return &net.UDPAddr{IP: sourceIP}
}

func normalizeNativeTargetHost(raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return v
	}
	if h, _, err := net.SplitHostPort(v); err == nil {
		v = strings.TrimSpace(h)
	}
	for len(v) >= 2 && strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]") {
		v = strings.TrimSpace(v[1 : len(v)-1])
	}
	return v
}

// ---------- bidirectional tunnel + traffic metering ----------

// nativeTunnel pipes bytes between the decoded client stream and the dialed
// backend, applying per-direction rate limits and accounting traffic against
// the client's email so the panel's online detection keeps working. It mirrors
// handleDirectTCPIP in main.go.
func nativeTunnel(client io.ReadWriteCloser, backend net.Conn, uuid, email string, quotaState *xrayNativeQuotaState, up, down *rate.Limiter) {
	defer xrayRecover(fmt.Sprintf("native xray TCP tunnel user=%s", email))

	upMeter := newTrafficMeter(uuid, email, true, quotaState)
	downMeter := newTrafficMeter(uuid, email, false, quotaState)

	var wg sync.WaitGroup
	var closeOnce sync.Once
	ctx, cancel := context.WithCancel(context.Background())
	closeAll := func() {
		closeOnce.Do(func() {
			cancel()
			_ = backend.Close()
			_ = client.Close()
		})
	}

	wg.Add(1)
	xrayGo("native xray TCP uplink", func() { // client -> backend
		defer wg.Done()
		defer closeAll()
		_, _ = copyWithRateLimitContext(ctx, xrayQuotaMeteredWriter{w: backend, meter: upMeter, ctx: ctx}, client, up)
		if cw, ok := backend.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	})

	wg.Add(1)
	xrayGo("native xray TCP downlink", func() { // backend -> client
		defer wg.Done()
		defer closeAll()
		_, _ = copyWithRateLimitContext(ctx, xrayQuotaMeteredWriter{w: client, meter: downMeter, ctx: ctx}, backend, down)
	})

	wg.Wait()
	upMeter.flush()
	downMeter.flush()
	closeAll()
}

// trafficMeter accumulates bytes for one direction and flushes them to the
// stats manager in batches to avoid locking on every write.
type trafficMeter struct {
	uuid            string
	email           string
	uplink          bool
	n               int64
	quotaGeneration uint64
	state           *xrayNativeQuotaState
}

const trafficFlushThreshold = 1024 * 1024

func newTrafficMeter(uuid, email string, uplink bool, state *xrayNativeQuotaState) *trafficMeter {
	t := &trafficMeter{uuid: uuid, email: email, uplink: uplink, state: state}
	t.syncQuotaGeneration()
	return t
}

func (t *trafficMeter) add(n int) {
	t.syncQuotaGeneration()
	t.n += int64(n)
	if t.n >= trafficFlushThreshold {
		t.flush()
	}
}

func (t *trafficMeter) flush() {
	t.syncQuotaGeneration()
	if t.n == 0 || t.email == "" {
		return
	}
	if t.uplink {
		xrayMgr.recordNativeTraffic(t.uuid, t.email, t.n, 0, t.quotaGeneration, t.state)
	} else {
		xrayMgr.recordNativeTraffic(t.uuid, t.email, 0, t.n, t.quotaGeneration, t.state)
	}
	t.n = 0
}

func (t *trafficMeter) syncQuotaGeneration() {
	var generation uint64
	if t.state != nil {
		t.state.mu.Lock()
		generation = t.state.generation
		t.state.mu.Unlock()
	}
	if t.quotaGeneration == 0 {
		t.quotaGeneration = generation
		return
	}
	if generation != t.quotaGeneration {
		t.n = 0
		t.quotaGeneration = generation
	}
}

func (ib *nativeInbound) upLimiter() *rate.Limiter   { return newByteLimiter(ib.upBytesPerSec) }
func (ib *nativeInbound) downLimiter() *rate.Limiter { return newByteLimiter(ib.downBytesPerSec) }

func newByteLimiter(bytesPerSec int) *rate.Limiter {
	if bytesPerSec <= 0 {
		return nil
	}
	return rate.NewLimiter(rate.Limit(bytesPerSec), bytesPerSec)
}

// ---------- WebSocket transport (RFC 6455, server side) ----------

const wsMagicGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
const wsMaxFrame = 16 * 1024 * 1024

// wsServerHandshake performs the server side of the WebSocket upgrade over an
// already-established (optionally TLS) connection, then returns a net.Conn whose
// Read/Write speak binary WebSocket frames.
func wsServerHandshake(conn net.Conn, wantPath string) (*websocketConn, error) {
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		return nil, errors.New("missing websocket upgrade")
	}
	key := req.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return nil, errors.New("missing Sec-WebSocket-Key")
	}
	if i := strings.IndexByte(wantPath, '?'); i >= 0 {
		wantPath = wantPath[:i]
	}
	if wantPath != "" && wantPath != "/" && req.URL.Path != wantPath {
		return nil, fmt.Errorf("ws path mismatch: got %q want %q", req.URL.Path, wantPath)
	}

	var early []byte
	proto := req.Header.Get("Sec-WebSocket-Protocol")
	if proto != "" {
		if ed, derr := base64.RawURLEncoding.DecodeString(proto); derr == nil {
			early = ed
		}
	}

	sum := sha1.Sum([]byte(key + wsMagicGUID))
	accept := base64.StdEncoding.EncodeToString(sum[:])
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n"
	if proto != "" {
		resp += "Sec-WebSocket-Protocol: " + proto + "\r\n"
	}
	resp += "\r\n"
	if _, err := conn.Write([]byte(resp)); err != nil {
		return nil, err
	}
	return &websocketConn{Conn: conn, r: br, early: early}, nil
}

// websocketConn adapts a WebSocket data stream to a net.Conn. Client frames are
// masked; server frames are written unmasked as binary frames.
type websocketConn struct {
	net.Conn
	r       *bufio.Reader
	early   []byte
	readBuf []byte // decoded payload not yet consumed by Read
	wmu     sync.Mutex
}

func (c *websocketConn) Read(p []byte) (int, error) {
	if len(c.early) > 0 {
		n := copy(p, c.early)
		c.early = c.early[n:]
		return n, nil
	}
	for len(c.readBuf) == 0 {
		payload, opcode, err := c.readFrame()
		if err != nil {
			return 0, err
		}
		switch opcode {
		case 0x8: // close
			return 0, io.EOF
		case 0x9: // ping -> pong
			_ = c.writeFrame(0xA, payload)
			continue
		case 0xA: // pong -> ignore
			continue
		default: // 0x0 continuation, 0x1 text, 0x2 binary -> treat as data
			c.readBuf = payload
		}
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *websocketConn) readFrame() (payload []byte, opcode byte, err error) {
	var h [2]byte
	if _, err = io.ReadFull(c.r, h[:]); err != nil {
		return nil, 0, err
	}
	opcode = h[0] & 0x0f
	masked := h[1]&0x80 != 0
	length := int64(h[1] & 0x7f)
	switch length {
	case 126:
		var ext [2]byte
		if _, err = io.ReadFull(c.r, ext[:]); err != nil {
			return nil, 0, err
		}
		length = int64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err = io.ReadFull(c.r, ext[:]); err != nil {
			return nil, 0, err
		}
		length = int64(binary.BigEndian.Uint64(ext[:]))
	}
	if length < 0 || length > wsMaxFrame {
		return nil, 0, fmt.Errorf("ws frame too large: %d", length)
	}
	var mask [4]byte
	if masked {
		if _, err = io.ReadFull(c.r, mask[:]); err != nil {
			return nil, 0, err
		}
	}
	payload = make([]byte, length)
	if _, err = io.ReadFull(c.r, payload); err != nil {
		return nil, 0, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i&3]
		}
	}
	return payload, opcode, nil
}

func (c *websocketConn) Write(p []byte) (int, error) {
	if err := c.writeFrame(0x2, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *websocketConn) writeFrame(opcode byte, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	n := len(payload)
	var header []byte
	b0 := byte(0x80) | opcode // FIN + opcode
	switch {
	case n < 126:
		header = []byte{b0, byte(n)}
	case n <= 0xffff:
		header = []byte{b0, 126, byte(n >> 8), byte(n)}
	default:
		header = make([]byte, 10)
		header[0] = b0
		header[1] = 127
		binary.BigEndian.PutUint64(header[2:], uint64(n))
	}
	frame := make([]byte, len(header)+n)
	copy(frame, header)
	copy(frame[len(header):], payload)
	_, err := c.Conn.Write(frame)
	return err
}

// ---------- config parsing ----------

// nativeXrayConfigFile mirrors the subset of the Xray JSON config the native
// server understands.
type nativeXrayConfigFile struct {
	Inbounds []nativeInboundJSON `json:"inbounds"`
}

type nativeXHTTPSettingsJSON struct {
	Host                 string           `json:"host"`
	Path                 string           `json:"path"`
	Mode                 string           `json:"mode"`
	NoSSEHeader          bool             `json:"noSSEHeader"`
	SessionIDPlacement   string           `json:"sessionIDPlacement"`
	SessionIDKey         string           `json:"sessionIDKey"`
	SeqPlacement         string           `json:"seqPlacement"`
	SeqKey               string           `json:"seqKey"`
	UplinkDataPlacement  string           `json:"uplinkDataPlacement"`
	UplinkDataKey        string           `json:"uplinkDataKey"`
	ScMaxEachPostBytes   *nativeRangeJSON `json:"scMaxEachPostBytes"`
	ScMaxBufferedPosts   int              `json:"scMaxBufferedPosts"`
	ServerMaxHeaderBytes int              `json:"serverMaxHeaderBytes"`
}

type nativeRangeJSON struct {
	From int64 `json:"from"`
	To   int64 `json:"to"`
}

type nativeInboundJSON struct {
	Tag                  string          `json:"tag"`
	DragoncoreSharedPort bool            `json:"dragoncoreSharedPort,omitempty"`
	Protocol             string          `json:"protocol"`
	Listen               string          `json:"listen"`
	Port                 json.RawMessage `json:"port"`
	Settings             struct {
		Clients []struct {
			ID       string `json:"id"`
			Password string `json:"password"`
			Email    string `json:"email"`
		} `json:"clients"`
		Users []struct {
			ID       string `json:"id"`
			Password string `json:"password"`
			Email    string `json:"email"`
		} `json:"users"`
	} `json:"settings"`
	StreamSettings struct {
		Network     string `json:"network"`
		Security    string `json:"security"`
		TLSSettings struct {
			Certificates []struct {
				CertificateFile string `json:"certificateFile"`
				KeyFile         string `json:"keyFile"`
			} `json:"certificates"`
		} `json:"tlsSettings"`
		WSSettings struct {
			Path string `json:"path"`
		} `json:"wsSettings"`
		XHTTPSettings     nativeXHTTPSettingsJSON `json:"xhttpSettings"`
		SplitHTTPSettings nativeXHTTPSettingsJSON `json:"splithttpSettings"`
	} `json:"streamSettings"`
}

// validateNativeInboundBindings checks the listener topology before a visual or
// raw-JSON update replaces the running native config. It intentionally mirrors
// the startup rules so an invalid shared-port edit is rejected before the last
// working file is overwritten.
func validateNativeInboundBindings(data []byte) error {
	var cf nativeXrayConfigFile
	if err := json.Unmarshal(data, &cf); err != nil {
		return fmt.Errorf("native xray: parse config: %w", err)
	}
	type binding struct {
		tag      string
		xhttp    bool
		path     string
		security string
		certFile string
		keyFile  string
	}
	groups := make(map[string][]binding)
	sharedPaths := map[string]string{}
	for _, in := range cf.Inbounds {
		proto := strings.ToLower(strings.TrimSpace(in.Protocol))
		if proto != "ssh" && !xrayClientProtos[proto] {
			continue
		}
		port, ok := parseSinglePort(in.Port)
		if !ok {
			return fmt.Errorf("native xray: inbound %q has an unsupported port", in.Tag)
		}
		network := strings.ToLower(firstNonEmpty(in.StreamSettings.Network, "tcp"))
		isXHTTP := network == "xhttp" || network == "splithttp"
		if proto == "ssh" && !isXHTTP {
			return fmt.Errorf("native xray: inbound %q protocol ssh requires XHTTP", in.Tag)
		}
		item := binding{tag: in.Tag, xhttp: isXHTTP, security: strings.ToLower(strings.TrimSpace(in.StreamSettings.Security))}
		if item.security == "none" {
			item.security = ""
		}
		if isXHTTP {
			xh := mergeNativeXHTTPSettings(in.StreamSettings.XHTTPSettings, in.StreamSettings.SplitHTTPSettings)
			item.path = normalizeXHTTPPath(firstNonEmpty(xh.Path, "/xhttp"))
		}
		if in.DragoncoreSharedPort {
			if err := validateSharedXrayInbound(in); err != nil {
				return err
			}
			path := in.StreamSettings.WSSettings.Path
			if isXHTTP {
				path = mergeNativeXHTTPSettings(in.StreamSettings.XHTTPSettings, in.StreamSettings.SplitHTTPSettings).Path
			}
			path, _ = sharedXrayPath(path)
			for prior, tag := range sharedPaths {
				if path == prior || strings.HasPrefix(path, prior+"/") || strings.HasPrefix(prior, path+"/") {
					return fmt.Errorf("shared Xray paths %s (%s) and %s (%s) overlap", prior, tag, path, in.Tag)
				}
			}
			sharedPaths[path] = in.Tag
			continue
		}
		if len(in.StreamSettings.TLSSettings.Certificates) > 0 {
			item.certFile = strings.TrimSpace(in.StreamSettings.TLSSettings.Certificates[0].CertificateFile)
			item.keyFile = strings.TrimSpace(in.StreamSettings.TLSSettings.Certificates[0].KeyFile)
		}
		host := normalizeNativeListenHost(firstNonEmpty(in.Listen, "0.0.0.0"))
		addr := net.JoinHostPort(host, strconv.Itoa(port))
		groups[addr] = append(groups[addr], item)
	}
	for addr, items := range groups {
		if len(items) < 2 {
			continue
		}
		paths := make(map[string]string, len(items))
		first := items[0]
		for _, item := range items {
			if !item.xhttp {
				return fmt.Errorf("native xray: multiple inbounds on %s require XHTTP path routing", addr)
			}
			if previous, exists := paths[item.path]; exists {
				return fmt.Errorf("native xray: XHTTP inbounds %q and %q use the same path %s on %s", previous, item.tag, item.path, addr)
			}
			paths[item.path] = item.tag
			if item.security != first.security {
				return fmt.Errorf("native xray: XHTTP inbounds sharing %s must use the same TLS setting", addr)
			}
			if item.security == "tls" && (item.certFile != first.certFile || item.keyFile != first.keyFile) {
				return fmt.Errorf("native xray: XHTTP inbounds sharing %s must use the same TLS certificate", addr)
			}
		}
	}
	return nil
}

// parseNativeInbounds reads the Xray config file and returns one nativeInbound
// per servable client-bearing inbound. Unsupported inbounds (api dokodemo-door,
// freedom, etc.) are silently skipped.
func parseNativeInbounds(configFile string) ([]*nativeInbound, error) {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, err
	}
	var cf nativeXrayConfigFile
	if err := json.Unmarshal(data, &cf); err != nil {
		return nil, fmt.Errorf("native xray: parse %s: %w", configFile, err)
	}

	upBps, downBps := defaultNativeLimits()

	var out []*nativeInbound
	for _, in := range cf.Inbounds {
		proto := strings.ToLower(strings.TrimSpace(in.Protocol))
		// "ssh" is an internal ConectaSSH-PRO extension: an XHTTP inbound whose decoded byte
		// stream is handed to the SSH server (handleConn) instead of a proxy
		// protocol. It carries no proxy clients (auth is the SSH account), so it
		// intentionally bypasses the client-bearing protocol gate below.
		if proto != "ssh" && !xrayClientProtos[proto] {
			continue // only vless/vmess/trojan carry clients; skip api/freedom/etc.
		}
		port, ok := parseSinglePort(in.Port)
		if !ok {
			xrayLogf("native xray: inbound %q has unsupported port form; skipping", in.Tag)
			continue
		}

		ib := &nativeInbound{
			tag:             in.Tag,
			protocol:        proto,
			listen:          normalizeNativeListenHost(firstNonEmpty(in.Listen, "0.0.0.0")),
			port:            port,
			transport:       strings.ToLower(firstNonEmpty(in.StreamSettings.Network, "tcp")),
			security:        strings.ToLower(strings.TrimSpace(in.StreamSettings.Security)),
			sharedPort:      in.DragoncoreSharedPort,
			clientsByID:     make(map[[16]byte]*nativeXrayClient),
			upBytesPerSec:   upBps,
			downBytesPerSec: downBps,
		}
		if ib.security == "none" {
			ib.security = ""
		}

		switch ib.transport {
		case "ws", "websocket":
			ib.path = firstNonEmpty(in.StreamSettings.WSSettings.Path, "/")
		case "xhttp", "splithttp":
			xh := mergeNativeXHTTPSettings(in.StreamSettings.XHTTPSettings, in.StreamSettings.SplitHTTPSettings)
			ib.path = normalizeXHTTPPath(firstNonEmpty(xh.Path, "/xhttp"))
			ib.xhttpHost = strings.TrimSpace(xh.Host)
			ib.xhttpMode = strings.ToLower(strings.TrimSpace(xh.Mode))
			ib.xhttpSessionPlacement = strings.ToLower(strings.TrimSpace(xh.SessionIDPlacement))
			ib.xhttpSessionKey = strings.TrimSpace(xh.SessionIDKey)
			ib.xhttpSeqPlacement = strings.ToLower(strings.TrimSpace(xh.SeqPlacement))
			ib.xhttpSeqKey = strings.TrimSpace(xh.SeqKey)
			ib.xhttpUplinkDataPlacement = strings.ToLower(strings.TrimSpace(xh.UplinkDataPlacement))
			ib.xhttpUplinkDataKey = strings.TrimSpace(xh.UplinkDataKey)
			ib.xhttpNoSSEHeader = xh.NoSSEHeader
			ib.xhttpMaxHeaderBytes = xh.ServerMaxHeaderBytes
			ib.xhttpMaxEachPostBytes = 1_000_000
			if xh.ScMaxEachPostBytes != nil && xh.ScMaxEachPostBytes.To > 0 {
				ib.xhttpMaxEachPostBytes = xh.ScMaxEachPostBytes.To
			}
			ib.xhttpMaxBufferedPosts = xh.ScMaxBufferedPosts
			if ib.xhttpMaxBufferedPosts <= 0 {
				ib.xhttpMaxBufferedPosts = nativeXHTTPBufferedPostLimit()
			}
			ib.xhttpSessions = make(map[string]*nativeXHTTPSession)
		}

		// TLS certificate: prefer the inbound's own tlsSettings, else fall back
		// to the panel's top-level cert/key.
		if ib.security == "tls" {
			tc, err := buildInboundTLS(in)
			if err != nil {
				xrayLogf("native xray: inbound %q TLS disabled: %v; skipping", in.Tag, err)
				continue
			}
			ib.tlsConfig = tc
		}

		// XHTTP->SSH inbounds have no proxy clients: the SSH handshake performed by
		// handleConn is the authentication step. Skip proxy-client loading and the
		// clientCount()==0 gate below, but enforce that "ssh" is only valid on the
		// XHTTP transport (that is the only path that reaches dispatchXHTTPConn).
		if ib.protocol == "ssh" {
			if !ib.isXHTTP() {
				xrayLogf("native xray: inbound %q protocol \"ssh\" requires xhttp transport; skipping", in.Tag)
				continue
			}
			out = append(out, ib)
			continue
		}

		configClients := in.Settings.Clients
		if len(in.Settings.Users) > 0 {
			configClients = append(configClients, in.Settings.Users...)
		}
		for _, c := range configClients {
			raw := c.ID
			if raw == "" {
				raw = c.Password // some protocols reuse password as id
			}
			if err := ib.addNativeClient(proto, raw, c.Email); err != nil {
				xrayLogf("native xray: inbound %q skipping client %q: %v", in.Tag, raw, err)
			}
		}
		if statsStore != nil && in.Tag != "" {
			metas, err := statsStore.ListXrayClientsByInbound(context.Background(), in.Tag)
			if err != nil {
				xrayLogf("native xray: inbound %q database clients unavailable: %v", in.Tag, err)
			} else {
				for _, m := range metas {
					if err := ib.addNativeClient(proto, m.UUID, firstNonEmpty(m.Email, m.Name, m.UUID)); err != nil {
						xrayLogf("native xray: inbound %q skipping DB client %q: %v", in.Tag, m.UUID, err)
					}
				}
			}
		}

		if ib.clientCount() == 0 {
			xrayLogf("native xray: inbound %q has no valid clients; skipping", in.Tag)
			continue
		}
		out = append(out, ib)
	}
	return out, nil
}

func (ib *nativeInbound) makeNativeClient(proto, raw, email string) (*nativeXrayClient, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty uuid")
	}
	id, err := parseUUID(raw)
	if err != nil {
		return nil, err
	}
	if email == "" {
		email = raw
	}
	nc := &nativeXrayClient{id: id, uuid: raw, email: email}
	if proto == "vmess" {
		nc.cmdKey = vmessCmdKey(id)
		block, err := aes.NewCipher(vmessKDF16(nc.cmdKey[:], kdfLabelAuthIDEncryptionKey))
		if err != nil {
			return nil, fmt.Errorf("vmess cipher init: %w", err)
		}
		nc.authIDCipher = block
	}
	return nc, nil
}

func (ib *nativeInbound) addNativeClient(proto, raw, email string) error {
	nc, err := ib.makeNativeClient(proto, raw, email)
	if err != nil {
		return err
	}
	ib.clientMu.Lock()
	if ib.clientsByID == nil {
		ib.clientsByID = make(map[[16]byte]*nativeXrayClient)
	}
	ib.clientsByID[nc.id] = nc
	ib.clientMu.Unlock()
	return nil
}

func (ib *nativeInbound) getNativeClient(id [16]byte) *nativeXrayClient {
	ib.clientMu.RLock()
	defer ib.clientMu.RUnlock()
	return ib.clientsByID[id]
}

func (ib *nativeInbound) removeNativeClient(uuid string) bool {
	id, err := parseUUID(uuid)
	if err != nil {
		return false
	}
	ib.clientMu.Lock()
	_, existed := ib.clientsByID[id]
	delete(ib.clientsByID, id)
	ib.clientMu.Unlock()
	return existed
}

func (ib *nativeInbound) updateNativeClientEmail(uuid, email string) bool {
	id, err := parseUUID(uuid)
	if err != nil || strings.TrimSpace(email) == "" {
		return false
	}
	ib.clientMu.Lock()
	defer ib.clientMu.Unlock()
	old := ib.clientsByID[id]
	if old == nil {
		return false
	}
	cp := *old
	cp.email = email
	ib.clientsByID[id] = &cp
	return true
}

func (ib *nativeInbound) clientCount() int {
	ib.clientMu.RLock()
	defer ib.clientMu.RUnlock()
	return len(ib.clientsByID)
}

func (s *nativeXrayServer) addClient(inboundTag, uuid, email string) error {
	s.mu.Lock()
	ib := s.inboundsByTag[inboundTag]
	running := s.running
	s.mu.Unlock()
	if !running || ib == nil {
		return nil
	}
	return ib.addNativeClient(ib.protocol, uuid, email)
}

func (s *nativeXrayServer) removeClient(inboundTag, uuid string) error {
	s.mu.Lock()
	ib := s.inboundsByTag[inboundTag]
	running := s.running
	s.mu.Unlock()
	if !running || ib == nil {
		return nil
	}
	ib.removeNativeClient(uuid)
	return nil
}

func (s *nativeXrayServer) updateClientEmail(uuid, email string) error {
	s.mu.Lock()
	inbounds := make([]*nativeInbound, 0, len(s.inboundsByTag))
	for _, ib := range s.inboundsByTag {
		inbounds = append(inbounds, ib)
	}
	running := s.running
	s.mu.Unlock()
	if !running {
		return nil
	}
	for _, ib := range inbounds {
		ib.updateNativeClientEmail(uuid, email)
	}
	return nil
}

func buildInboundTLS(in nativeInboundJSON) (*tls.Config, error) {
	var certFile, keyFile string
	if certs := in.StreamSettings.TLSSettings.Certificates; len(certs) > 0 {
		certFile = certs[0].CertificateFile
		keyFile = certs[0].KeyFile
	}
	if certFile == "" || keyFile == "" {
		// Fall back to the panel's first TLS forwarder cert/key, which is the
		// main TLS material an operator already configured for TLS-over-SSH.
		if gc := getGlobalCfg(); gc != nil && len(gc.TLSForwarders) > 0 {
			if certFile == "" {
				certFile = gc.TLSForwarders[0].CertFile
			}
			if keyFile == "" {
				keyFile = gc.TLSForwarders[0].KeyFile
			}
		}
	}
	if certFile == "" || keyFile == "" {
		return nil, errors.New("no certificate/key configured")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}, nil
}

// defaultNativeLimits converts the panel's default Mbps limits to bytes/sec.
func defaultNativeLimits() (up, down int) {
	gc := getGlobalCfg()
	if gc == nil {
		return 0, 0
	}
	return gc.DefaultLimitMbpsUp * 125000, gc.DefaultLimitMbpsDown * 125000
}

// parseSinglePort accepts an Xray port field that is a plain integer (the only
// form the panel generates) and returns it. Ranges/strings are rejected.
func parseSinglePort(raw json.RawMessage) (int, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	var n int
	if err := json.Unmarshal(raw, &n); err == nil && n > 0 && n < 65536 {
		return n, true
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if p, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && p > 0 && p < 65536 {
			return p, true
		}
	}
	return 0, false
}

// parseUUID parses a canonical 36-char UUID string into 16 bytes.
func parseUUID(s string) ([16]byte, error) {
	var out [16]byte
	clean := strings.ReplaceAll(strings.TrimSpace(s), "-", "")
	if len(clean) != 32 {
		return out, fmt.Errorf("expected 32 hex chars, got %d", len(clean))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return out, err
	}
	copy(out[:], b)
	return out, nil
}

// normalizeNativeListenHost returns the host-only value expected by net.JoinHostPort.
// Xray's listen field is host-only, but panel/manual configs often store IPv6 in
// bracket form ("[2001:db8::1]") or accidentally store a full socket address
// ("[2001:db8::1]:443"). Passing a bracketed host to net.JoinHostPort creates
// invalid addresses like "[[2001:db8::1]]:443". Strip those forms here.
func normalizeNativeListenHost(raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "0.0.0.0"
	}
	if h, _, err := net.SplitHostPort(v); err == nil {
		v = strings.TrimSpace(h)
	}
	for len(v) >= 2 && strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]") {
		v = strings.TrimSpace(v[1 : len(v)-1])
	}
	if v == "" {
		return "0.0.0.0"
	}
	return v
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
