package main

// This file embeds the HCR (HTTP/Custom Relay) transport into the panel. HCR is
// a request/response tunnel: the client sends 62-byte-header frames (connect,
// data, poll, ack, close, ping) and the server relays the stream to a target.
//
// Exactly like BHTTP, every HCR session is handed to this process's own SSH
// server through dialInternalSSH, so panel accounts, expiry, TOTP, per-user
// bandwidth limits, data quotas and connection counters all apply. There is no
// dependency on the system sshd, PAM or /etc/shadow.
//
// HCR is built to coexist with BHTTP on the same ports: see tunnel_share.go for
// how a shared listener tells an HCR frame (62-byte header, version byte 0x01)
// apart from a BHTTP frame (29-byte header) and from SSH/HTTP.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/dakarpy/ConectaSSH-PRO/internal/hcr"
)

// HCRConfig defines the settings for the integrated HCR transport. A nil
// *HCRConfig in the main config disables it entirely.
type HCRConfig struct {
	// Listen lists the TCP addresses to bind. IPv6 addresses must use bracket
	// form, e.g. "[::]:8181". Empty with SharedPorts off uses the default.
	Listen []string `json:"listen"`

	// SharedPorts also accepts HCR on the ports the panel already owns (the
	// HTTP+SSH proxy listeners and every TLS forwarder), alongside BHTTP, SSH
	// and HTTP-injection clients. See tunnel_share.go.
	SharedPorts bool `json:"shared_ports,omitempty"`

	// MaxConnections caps concurrently accepted client sockets. Zero uses a
	// safe default; negative disables the cap.
	MaxConnections int `json:"max_connections,omitempty"`

	// MaxSessions caps concurrently tracked HCR sessions. Zero uses a safe
	// default; negative disables the cap.
	MaxSessions int `json:"max_sessions,omitempty"`

	// MaxSourceSessions caps sessions per client IP. Zero disables the per-IP
	// cap.
	MaxSourceSessions int `json:"max_source_sessions,omitempty"`

	// DownloadPollTimeout bounds a long-poll with no data. Empty defaults to
	// "10s".
	DownloadPollTimeout string `json:"download_poll_timeout,omitempty"`

	// MaxDownloadFrame is the largest record read from the target per frame, in
	// bytes. Zero or out-of-range uses 16384.
	MaxDownloadFrame int `json:"max_download_frame,omitempty"`

	// IdleSessionTimeout drops a session that sees no traffic for this long.
	// Empty defaults to "5m".
	IdleSessionTimeout string `json:"idle_session_timeout,omitempty"`

	// SessionStatsInterval logs compact session counters periodically.
	SessionStatsInterval string `json:"session_stats_interval,omitempty"`

	// DisableConsoleLog keeps HCR log lines out of stderr. They are still
	// captured in memory and served by /api/hcr/logs for the panel.
	DisableConsoleLog bool `json:"disable_console_log,omitempty"`

	// LogConnections raises the engine to debug logging (per-frame events).
	// Leave off on busy servers.
	LogConnections bool `json:"log_connections,omitempty"`

	// AutoRestartInterval controls a watchdog that periodically hard-restarts
	// only the HCR listeners and drops their sessions. Empty, "0s", "off" or
	// "disabled" turns it off. Minimum accepted value is 1m.
	AutoRestartInterval string `json:"auto_restart_interval,omitempty"`

	// AutoRestartGrace is the delay between closing the old listeners and
	// binding them again during an auto restart. Empty defaults to "2s".
	AutoRestartGrace string `json:"auto_restart_grace,omitempty"`
}

const (
	defaultHCRListen         = "0.0.0.0:8181"
	defaultHCRMaxConnections = 2048
	defaultHCRMaxSessions    = 128
	// hcrTargetLabel is only what shows up in logs; HCR never dials a real TCP
	// target, it hands each session to the built-in SSH server.
	hcrTargetLabel = "hcr"
)

var (
	hcrMu          sync.Mutex
	hcrServer      *hcr.Server
	hcrListeners   []net.Listener
	hcrAddrs       []string
	hcrSharedPorts bool
	hcrCtx         context.Context
	hcrCancel      context.CancelFunc

	hcrAutoMu     sync.Mutex
	hcrAutoCancel context.CancelFunc

	hcrLogBuf *ringLogBuffer
)

func getHCRLogLines() []string { return hcrLogBuf.GetLines() }

// hcrLogger builds an slog logger that writes into the in-memory ring buffer
// (always) and to stderr (unless the console log is disabled), at debug level
// when connection logging is on.
func hcrLogger(cfg *HCRConfig) *slog.Logger {
	level := slog.LevelInfo
	if cfg.LogConnections {
		level = slog.LevelDebug
	}
	var writer io.Writer = hcrLogBuf
	if !cfg.DisableConsoleLog {
		writer = io.MultiWriter(hcrLogBuf, os.Stderr)
	}
	return slog.New(slog.NewTextHandler(writer, &slog.HandlerOptions{Level: level}))
}

// ---------- Lifecycle ----------

func stopHCR() {
	stopHCRAutoRestart()
	stopHCRInstance()
}

func stopHCRInstance() {
	hcrMu.Lock()
	listeners := hcrListeners
	server := hcrServer
	cancel := hcrCancel
	hcrListeners = nil
	hcrAddrs = nil
	hcrServer = nil
	hcrSharedPorts = false
	hcrCtx = nil
	hcrCancel = nil
	hcrMu.Unlock()

	if cancel != nil {
		cancel()
	}
	for _, listener := range listeners {
		if listener != nil {
			_ = listener.Close()
		}
	}
	if server != nil {
		server.Close()
		server.Wait()
	}
}

func stopHCRAutoRestart() {
	hcrAutoMu.Lock()
	defer hcrAutoMu.Unlock()
	if hcrAutoCancel != nil {
		hcrAutoCancel()
		hcrAutoCancel = nil
	}
}

func hcrRunning() bool {
	hcrMu.Lock()
	defer hcrMu.Unlock()
	return hcrServer != nil
}

// hcrShareEnabled reports whether a running HCR server wants the shared proxy
// and TLS ports.
func hcrShareEnabled() bool {
	hcrMu.Lock()
	defer hcrMu.Unlock()
	return hcrServer != nil && hcrSharedPorts
}

func hcrListenList() string {
	hcrMu.Lock()
	addrs := append([]string(nil), hcrAddrs...)
	shared := hcrSharedPorts
	hcrMu.Unlock()
	if shared {
		addrs = append(addrs, "shared proxy/TLS ports")
	}
	return strings.Join(addrs, ", ")
}

func hcrEnabledInCurrentConfig() bool {
	globalCfgMu.RLock()
	defer globalCfgMu.RUnlock()
	return globalCfg != nil && globalCfg.HCR != nil
}

// startHCR starts the integrated HCR transport if cfg is non-nil.
func startHCR(cfg *HCRConfig) error {
	if cfg == nil {
		return nil
	}
	stopHCRAutoRestart()
	if err := startHCRInstance(cfg); err != nil {
		return err
	}
	startHCRAutoRestart(cfg)
	return nil
}

func startHCRInstance(cfg *HCRConfig) error {
	if cfg == nil {
		return nil
	}
	if hcrLogBuf == nil {
		hcrLogBuf = newRingLogBuffer(200)
	}
	logger := hcrLogger(cfg)

	addrs := normalizeHCRListenList(cfg.Listen)
	if len(addrs) == 0 && !cfg.SharedPorts {
		msg := errors.New("hcr: needs either a listen address or shared_ports")
		logger.Error(msg.Error())
		return msg
	}
	cfg.Listen = addrs

	maxConnections := cfg.MaxConnections
	if maxConnections == 0 {
		maxConnections = defaultHCRMaxConnections
	} else if maxConnections < 0 {
		maxConnections = 0
	}
	maxSessions := cfg.MaxSessions
	if maxSessions == 0 {
		maxSessions = defaultHCRMaxSessions
	} else if maxSessions < 0 {
		maxSessions = 0
	}

	server := hcr.NewServer(&hcr.Config{
		TargetAddr:           hcrTargetLabel,
		DialTarget:           func() (net.Conn, error) { return dialInternalSSH(hcrTargetLabel) },
		Logger:               logger,
		MaxConnections:       maxConnections,
		MaxSessions:          maxSessions,
		MaxSourceSessions:    cfg.MaxSourceSessions,
		DownloadPollTimeout:  hcrDurationOrDefault(cfg.DownloadPollTimeout, 8*time.Second, "download_poll_timeout", logger),
		MaxDownloadFrame:     cfg.MaxDownloadFrame,
		IdleSessionTimeout:   hcrDurationOrDefault(cfg.IdleSessionTimeout, 2*time.Minute, "idle_session_timeout", logger),
		SessionStatsInterval: hcrDurationOrDefault(cfg.SessionStatsInterval, 10*time.Second, "session_stats_interval", logger),
	})

	// Release the previous instance before rebinding the same addresses.
	stopHCRInstance()

	listeners := make([]net.Listener, 0, len(addrs))
	bound := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			for _, opened := range listeners {
				_ = opened.Close()
			}
			server.Close()
			msg := fmt.Errorf("hcr: listen failed on %s: %w", addr, err)
			logger.Error(msg.Error())
			return msg
		}
		listeners = append(listeners, listener)
		bound = append(bound, addr)
	}

	ctx, cancel := context.WithCancel(context.Background())
	hcrMu.Lock()
	hcrServer = server
	hcrListeners = listeners
	hcrAddrs = bound
	hcrSharedPorts = cfg.SharedPorts
	hcrCtx = ctx
	hcrCancel = cancel
	hcrMu.Unlock()

	logger.Info("starting",
		"listen", bound, "shared_ports", cfg.SharedPorts,
		"max_connections", maxConnections, "max_sessions", maxSessions,
		"log_connections", cfg.LogConnections)

	for _, listener := range listeners {
		go func(current net.Listener) {
			defer func() {
				if r := recover(); r != nil {
					logger.Error("recovered panic in accept loop", "err", r)
				}
			}()
			if err := server.Serve(ctx, current); err != nil && !isListenerClosed(err) {
				logger.Warn("listener stopped", "addr", current.Addr().String(), "err", err)
			}
		}(listener)
	}
	return nil
}

func startHCRAutoRestart(cfg *HCRConfig) {
	interval := hcrAutoRestartInterval(cfg)
	if interval <= 0 {
		return
	}
	grace := hcrAutoRestartGrace(cfg)
	cfgCopy := *cfg
	cfgCopy.Listen = append([]string(nil), cfg.Listen...)
	ctx, cancel := context.WithCancel(context.Background())

	hcrAutoMu.Lock()
	if hcrAutoCancel != nil {
		hcrAutoCancel()
	}
	hcrAutoCancel = cancel
	hcrAutoMu.Unlock()

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				stopHCRInstance()
				if !sleepOrContextDone(ctx, grace) {
					return
				}
				for attempt := 1; ; attempt++ {
					if err := startHCRInstance(&cfgCopy); err != nil {
						if !sleepOrContextDone(ctx, 10*time.Second) {
							return
						}
						continue
					}
					break
				}
			}
		}
	}()
}

func hcrAutoRestartInterval(cfg *HCRConfig) time.Duration {
	if cfg == nil {
		return 0
	}
	raw := strings.TrimSpace(cfg.AutoRestartInterval)
	if raw == "" || raw == "0" || raw == "0s" || strings.EqualFold(raw, "off") || strings.EqualFold(raw, "disabled") {
		return 0
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d < time.Minute {
		return 0
	}
	return d
}

func hcrAutoRestartGrace(cfg *HCRConfig) time.Duration {
	if cfg == nil || strings.TrimSpace(cfg.AutoRestartGrace) == "" {
		return 2 * time.Second
	}
	d, err := time.ParseDuration(strings.TrimSpace(cfg.AutoRestartGrace))
	if err != nil || d < 0 {
		return 2 * time.Second
	}
	if d > time.Minute {
		return time.Minute
	}
	return d
}

func hcrDurationOrDefault(raw string, fallback time.Duration, field string, logger *slog.Logger) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		logger.Warn("invalid duration; using default", "field", field, "value", raw, "default", fallback)
		return fallback
	}
	return d
}

func normalizeHCRListenList(addrs []string) []string {
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

// hcrConfiguredListen describes the addresses a config asks for, for status
// reports when the server failed to bind them.
func hcrConfiguredListen(cfg *HCRConfig) string {
	if cfg == nil {
		return ""
	}
	return strings.Join(normalizeHCRListenList(cfg.Listen), ", ")
}

// ---------- Stats ----------

// HCRStatsSnapshot is what /api/hcr returns.
type HCRStatsSnapshot struct {
	Enabled bool   `json:"enabled"`
	Running bool   `json:"running"`
	Listen  string `json:"listen,omitempty"`
	hcr.StatsSnapshot
}

// GetHCRStatsSnapshot returns the current HCR counters. Safe for concurrent use.
func GetHCRStatsSnapshot() HCRStatsSnapshot {
	snapshot := HCRStatsSnapshot{
		Enabled: hcrEnabledInCurrentConfig(),
		Running: hcrRunning(),
		Listen:  hcrListenList(),
	}
	hcrMu.Lock()
	server := hcrServer
	hcrMu.Unlock()
	if server != nil {
		snapshot.StatsSnapshot = server.Stats()
	}
	return snapshot
}
