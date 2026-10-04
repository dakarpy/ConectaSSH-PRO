package main

// This file embeds the BHTTP (BHP1/BHP2) transport into the panel. BHTTP is the
// obfuscated TCP transport used by the DTunnel-family clients: a client opens a
// plain TCP socket, optionally sends an HTTP request as cover, then speaks the
// 29-byte-header BHTTP framing (probe, upload, download, batch, ACK and — in
// v2 — persistent lanes with resume and cumulative ACKs).
//
// The transport does NOT talk to the system's OpenSSH daemon. Exactly like the
// DNSTT integration, every BHTTP session is handed to this process's own SSH
// server through handleConn, so panel accounts, expiry, TOTP, per-user
// bandwidth limits, data quotas and connection counters all apply unchanged.
// There is no dependency on sshd, PAM or /etc/shadow anywhere in this path.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/dakarpy/ConectaSSH-PRO/internal/bhttp"
)

// BHTTPConfig defines the settings for the integrated BHTTP transport. A nil
// *BHTTPConfig in the main config disables it entirely.
type BHTTPConfig struct {
	// Listen lists the TCP addresses to bind. IPv6 addresses must use bracket
	// form, for example "[::]:8880". Empty uses the default 0.0.0.0:8880.
	// Ports 80/8080 normally belong to the HTTP+SSH proxy listeners, so BHTTP
	// defaults to a separate port instead of fighting them for the socket.
	Listen []string `json:"listen"`

	// SharedPorts also accepts BHTTP on the ports the panel already owns: the
	// HTTP+SSH proxy listeners (listen and extra_listen, normally 80 and 8080)
	// and every TLS forwarder (normally 443). Those listeners read the first
	// bytes of each connection and hand it here only when it is unmistakably a
	// BHTTP frame, so SSH and HTTP-injection clients on the same port are
	// unaffected.
	//
	// The one behaviour this changes for other clients: the proxy listener
	// normally answers with "HTTP/1.1 101" the moment a socket opens, and with
	// sharing on it waits for the client's first bytes instead (up to
	// bhttpSniffTimeout). Every known client sends immediately on connect, but
	// turn this off if a client of yours waits for that 101 before speaking.
	SharedPorts bool `json:"shared_ports,omitempty"`

	// SessionTimeout is how long a BHTTP session may sit with no traffic before
	// it is dropped and its SSH connection closed. Empty defaults to "2m".
	// BHTTP v2 clients reconnect lanes into an existing session, so this value
	// also bounds how long a resume stays possible.
	SessionTimeout string `json:"session_timeout,omitempty"`

	// MaxV2Lanes caps the combined number of BHTTP v2 lanes a single session
	// may keep attached. Zero uses the protocol default (128).
	MaxV2Lanes int `json:"max_v2_lanes,omitempty"`

	// MaxSessions caps concurrently tracked BHTTP sessions. Once reached, new
	// session IDs are refused while existing sessions keep working. Zero uses a
	// safe default; negative disables the cap.
	MaxSessions int `json:"max_sessions,omitempty"`

	// MaxConnections caps concurrently accepted client sockets across every
	// BHTTP listener. Sockets past the cap are closed before any protocol work.
	// Zero uses a safe default; negative disables the cap.
	MaxConnections int `json:"max_connections,omitempty"`

	// DisableConsoleLog keeps BHTTP log lines out of stderr. They are still
	// captured in memory and served by /api/bhttp/logs for the panel.
	DisableConsoleLog bool `json:"disable_console_log,omitempty"`

	// LogConnections enables one log line per accepted socket. Leave it off on
	// servers with thousands of users; connection logging can become the
	// bottleneck.
	LogConnections bool `json:"log_connections,omitempty"`

	// AutoRestartInterval controls a watchdog that periodically hard-restarts
	// only the BHTTP listeners and drops their sessions. Empty, "0s", "off" or
	// "disabled" turns it off. Minimum accepted value is 1m.
	AutoRestartInterval string `json:"auto_restart_interval,omitempty"`

	// AutoRestartGrace is the delay between closing the old listeners and
	// binding them again during an auto restart. Empty defaults to "2s".
	AutoRestartGrace string `json:"auto_restart_grace,omitempty"`
}

const (
	defaultBHTTPListen         = "0.0.0.0:8880"
	defaultBHTTPSessionTimeout = 2 * time.Minute
	defaultBHTTPMaxSessions    = 10000
	defaultBHTTPMaxConnections = 10000
	// bhttpTargetLabel is the "address" handed to the dialer. BHTTP never dials
	// a TCP target, so this is only what shows up in logs.
	bhttpTargetLabel = "bhttp"
)

var (
	bhttpMu        sync.Mutex
	bhttpServer    *bhttp.Server
	bhttpListeners []net.Listener
	bhttpAddrs     []string
	// bhttpSharedPorts mirrors BHTTPConfig.SharedPorts for the running
	// instance, so the proxy and TLS listeners can check it without reading the
	// whole config on every connection.
	bhttpSharedPorts bool

	bhttpAutoMu     sync.Mutex
	bhttpAutoCancel context.CancelFunc

	bhttpLog    = log.New(os.Stderr, "bhttp: ", log.LstdFlags|log.Lmicroseconds)
	bhttpLogBuf *ringLogBuffer
)

// ---------- Log buffer shared by the embedded transports ----------

// ringLogBuffer keeps the most recent log lines in memory so the admin panel
// can show them even when console logging is disabled.
type ringLogBuffer struct {
	mu       sync.Mutex
	lines    []string
	maxLines int
	partial  string
}

func newRingLogBuffer(maxLines int) *ringLogBuffer {
	if maxLines <= 0 {
		maxLines = 100
	}
	return &ringLogBuffer{lines: make([]string, 0, maxLines), maxLines: maxLines}
}

func (b *ringLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	text := b.partial + string(p)
	b.partial = ""
	for {
		index := strings.IndexByte(text, '\n')
		if index < 0 {
			b.partial = text
			break
		}
		line := strings.TrimRight(text[:index], "\r")
		text = text[index+1:]
		if line == "" {
			continue
		}
		if len(b.lines) >= b.maxLines {
			copy(b.lines, b.lines[1:])
			b.lines = b.lines[:len(b.lines)-1]
		}
		b.lines = append(b.lines, line)
	}
	return len(p), nil
}

func (b *ringLogBuffer) GetLines() []string {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, len(b.lines))
	copy(out, b.lines)
	return out
}

func getBHTTPLogLines() []string { return bhttpLogBuf.GetLines() }

// ---------- Handing a tunnelled stream to the built-in SSH server ----------

// transportAddr is a stable net.Addr placeholder for in-process tunnel streams,
// mirroring how the DNSTT integration labels its streams.
type transportAddr string

func (a transportAddr) Network() string { return string(a) }
func (a transportAddr) String() string  { return string(a) }

// dialInternalSSH returns a net.Conn whose other end is being served by this
// process's own SSH server. Nothing leaves the process: no loopback socket, no
// system sshd, no PAM. label only affects log output.
//
// The pair is buffered in both directions (see tunnel_pipe.go), so neither
// side has to be reading for the other to make progress. That keeps the SSH
// server's handshake, which writes and reads in the same goroutine, from
// depending on the transport happening to be draining at that moment.
func dialInternalSSH(label string) (net.Conn, error) {
	sshConf := getSSHConfig()
	if sshConf == nil {
		return nil, fmt.Errorf("%s: internal SSH server is not ready", label)
	}
	clientSide, serverSide := newTunnelConnPair(label, tunnelPipeBuffer)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("%s: recovered panic in SSH handler: %v", label, r)
			}
		}()
		defer serverSide.Close()
		handleConn(serverSide, sshConf)
	}()
	return clientSide, nil
}

// ---------- Lifecycle ----------

// stopBHTTP closes the BHTTP listeners, drops every session and stops the
// optional auto-restart watchdog. It is a no-op if BHTTP is not running.
func stopBHTTP() {
	stopBHTTPAutoRestart()
	stopBHTTPInstance()
}

// stopBHTTPInstance closes only the listeners and sessions. The auto-restart
// watchdog uses this so it can cycle BHTTP without disabling itself.
func stopBHTTPInstance() {
	bhttpMu.Lock()
	listeners := bhttpListeners
	server := bhttpServer
	bhttpListeners = nil
	bhttpAddrs = nil
	bhttpServer = nil
	bhttpSharedPorts = false
	bhttpMu.Unlock()

	for _, listener := range listeners {
		if listener != nil {
			_ = listener.Close()
		}
	}
	if server != nil {
		server.Close()
	}
}

func stopBHTTPAutoRestart() {
	bhttpAutoMu.Lock()
	defer bhttpAutoMu.Unlock()
	if bhttpAutoCancel != nil {
		bhttpAutoCancel()
		bhttpAutoCancel = nil
	}
}

func bhttpRunning() bool {
	bhttpMu.Lock()
	defer bhttpMu.Unlock()
	// The server can legitimately run with no listener of its own when it only
	// serves connections handed over from the shared proxy and TLS ports.
	return bhttpServer != nil
}

// bhttpListenList describes where BHTTP is reachable, for the panel.
func bhttpListenList() string {
	bhttpMu.Lock()
	addrs := append([]string(nil), bhttpAddrs...)
	shared := bhttpSharedPorts
	bhttpMu.Unlock()
	if shared {
		addrs = append(addrs, "shared proxy/TLS ports")
	}
	return strings.Join(addrs, ", ")
}

// bhttpShareEnabled reports whether a running BHTTP server wants the shared
// proxy and TLS ports.
func bhttpShareEnabled() bool {
	bhttpMu.Lock()
	defer bhttpMu.Unlock()
	return bhttpServer != nil && bhttpSharedPorts
}

func bhttpEnabledInCurrentConfig() bool {
	globalCfgMu.RLock()
	defer globalCfgMu.RUnlock()
	return globalCfg != nil && globalCfg.BHTTP != nil
}

// startBHTTP starts the integrated BHTTP transport if cfg is non-nil. Startup
// errors are returned so the admin panel can report them, but they never crash
// the panel.
func startBHTTP(cfg *BHTTPConfig) error {
	if cfg == nil {
		return nil
	}
	stopBHTTPAutoRestart()
	if err := startBHTTPInstance(cfg); err != nil {
		return err
	}
	startBHTTPAutoRestart(cfg)
	return nil
}

func startBHTTPInstance(cfg *BHTTPConfig) error {
	if cfg == nil {
		return nil
	}
	if bhttpLogBuf == nil {
		bhttpLogBuf = newRingLogBuffer(200)
	}
	if cfg.DisableConsoleLog {
		bhttpLog.SetOutput(bhttpLogBuf)
	} else {
		bhttpLog.SetOutput(io.MultiWriter(bhttpLogBuf, os.Stderr))
	}

	addrs := normalizeBHTTPListenList(cfg.Listen)
	cfg.Listen = addrs
	if len(addrs) == 0 && !cfg.SharedPorts {
		msg := errors.New("bhttp: needs either a listen address or shared_ports")
		bhttpLog.Print(msg.Error())
		return msg
	}

	sessionTimeout := bhttpSessionTimeout(cfg)
	maxSessions := cfg.MaxSessions
	if maxSessions == 0 {
		maxSessions = defaultBHTTPMaxSessions
	} else if maxSessions < 0 {
		maxSessions = 0 // unlimited
	}
	maxConnections := cfg.MaxConnections
	if maxConnections == 0 {
		maxConnections = defaultBHTTPMaxConnections
	} else if maxConnections < 0 {
		maxConnections = 0 // unlimited
	}

	server := bhttp.NewServer(bhttp.Config{
		TargetAddress:  bhttpTargetLabel,
		SessionTimeout: sessionTimeout,
		MaxV2Lanes:     cfg.MaxV2Lanes,
		MaxSessions:    maxSessions,
		MaxConnections: maxConnections,
		LogConnections: cfg.LogConnections,
		Logger:         bhttpLog,
		DialTarget:     dialInternalSSH,
	})

	// Release the previous instance first: rebinding the same address while the
	// old socket is still open would fail with "address already in use".
	stopBHTTPInstance()

	// Bind synchronously so the panel immediately knows whether BHTTP really
	// started or failed on a busy port.
	listeners := make([]net.Listener, 0, len(addrs))
	bound := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			for _, opened := range listeners {
				_ = opened.Close()
			}
			server.Close()
			msg := fmt.Errorf("bhttp: listen failed on %s: %w", addr, err)
			bhttpLog.Print(msg.Error())
			return msg
		}
		listeners = append(listeners, listener)
		bound = append(bound, addr)
	}

	bhttpMu.Lock()
	bhttpServer = server
	bhttpListeners = listeners
	bhttpAddrs = bound
	bhttpSharedPorts = cfg.SharedPorts
	bhttpMu.Unlock()

	bhttpLog.Printf("starting: listen=%q shared_ports=%v session_timeout=%s max_v2_lanes=%d max_sessions=%d max_connections=%d log_connections=%v -> built-in SSH server",
		bound, cfg.SharedPorts, sessionTimeout, cfg.MaxV2Lanes, maxSessions, maxConnections, cfg.LogConnections)

	for _, listener := range listeners {
		go func(current net.Listener) {
			defer func() {
				if r := recover(); r != nil {
					bhttpLog.Printf("recovered panic in accept loop: %v", r)
				}
			}()
			if err := server.Serve(current); err != nil && !isListenerClosed(err) {
				bhttpLog.Printf("listener %s stopped: %v", current.Addr(), err)
			}
		}(listener)
	}
	return nil
}

func startBHTTPAutoRestart(cfg *BHTTPConfig) {
	interval := bhttpAutoRestartInterval(cfg)
	if interval <= 0 {
		return
	}
	grace := bhttpAutoRestartGrace(cfg)
	cfgCopy := *cfg
	cfgCopy.Listen = append([]string(nil), cfg.Listen...)
	ctx, cancel := context.WithCancel(context.Background())

	bhttpAutoMu.Lock()
	if bhttpAutoCancel != nil {
		bhttpAutoCancel()
	}
	bhttpAutoCancel = cancel
	bhttpAutoMu.Unlock()

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		bhttpLog.Printf("auto restart enabled: interval=%s grace=%s mode=hard", interval, grace)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				bhttpLog.Print("auto restart: stopping listeners and sessions")
				stopBHTTPInstance()
				if !sleepOrContextDone(ctx, grace) {
					return
				}
				for attempt := 1; ; attempt++ {
					if err := startBHTTPInstance(&cfgCopy); err != nil {
						bhttpLog.Printf("auto restart: start attempt %d failed: %v", attempt, err)
						if !sleepOrContextDone(ctx, 10*time.Second) {
							return
						}
						continue
					}
					bhttpLog.Print("auto restart: listeners rebound")
					break
				}
			}
		}
	}()
}

func bhttpSessionTimeout(cfg *BHTTPConfig) time.Duration {
	if cfg == nil {
		return defaultBHTTPSessionTimeout
	}
	raw := strings.TrimSpace(cfg.SessionTimeout)
	if raw == "" {
		return defaultBHTTPSessionTimeout
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		bhttpLog.Printf("invalid session_timeout %q; using default %s", raw, defaultBHTTPSessionTimeout)
		return defaultBHTTPSessionTimeout
	}
	return d
}

func bhttpAutoRestartInterval(cfg *BHTTPConfig) time.Duration {
	if cfg == nil {
		return 0
	}
	raw := strings.TrimSpace(cfg.AutoRestartInterval)
	if raw == "" || raw == "0" || raw == "0s" || strings.EqualFold(raw, "off") || strings.EqualFold(raw, "disabled") {
		return 0
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		bhttpLog.Printf("auto restart disabled: invalid interval %q: %v", raw, err)
		return 0
	}
	if d < time.Minute {
		bhttpLog.Printf("auto restart disabled: interval %q is below minimum 1m", raw)
		return 0
	}
	return d
}

func bhttpAutoRestartGrace(cfg *BHTTPConfig) time.Duration {
	if cfg == nil || strings.TrimSpace(cfg.AutoRestartGrace) == "" {
		return 2 * time.Second
	}
	d, err := time.ParseDuration(strings.TrimSpace(cfg.AutoRestartGrace))
	if err != nil || d < 0 {
		bhttpLog.Printf("auto restart: invalid grace %q, using 2s", cfg.AutoRestartGrace)
		return 2 * time.Second
	}
	if d > time.Minute {
		return time.Minute
	}
	return d
}

// normalizeBHTTPListenList trims, de-duplicates and preserves the order of the
// configured listen addresses.
func normalizeBHTTPListenList(addrs []string) []string {
	seen := make(map[string]bool, len(addrs))
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		addr = strings.TrimSpace(addr)
		if addr == "" || seen[addr] {
			continue
		}
		seen[addr] = true
		out = append(out, addr)
	}
	return out
}

// ---------- Stats ----------

// BHTTPStatsSnapshot is what /api/bhttp returns.
type BHTTPStatsSnapshot struct {
	Enabled bool   `json:"enabled"`
	Running bool   `json:"running"`
	Listen  string `json:"listen,omitempty"`
	bhttp.StatsSnapshot
}

// GetBHTTPStatsSnapshot returns the current BHTTP counters. It is safe for
// concurrent use and always returns a copy.
func GetBHTTPStatsSnapshot() BHTTPStatsSnapshot {
	snapshot := BHTTPStatsSnapshot{
		Enabled: bhttpEnabledInCurrentConfig(),
		Running: bhttpRunning(),
		Listen:  bhttpListenList(),
	}
	bhttpMu.Lock()
	server := bhttpServer
	bhttpMu.Unlock()
	if server != nil {
		snapshot.StatsSnapshot = server.Stats()
	}
	return snapshot
}
