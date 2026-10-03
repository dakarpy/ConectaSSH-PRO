package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// XrayConfig holds Xray process management settings embedded in the main Config.
type XrayConfig struct {
	Enabled          bool   `json:"enabled"`
	BinPath          string `json:"bin_path"`                     // external mode only, e.g. /opt/sshpanel/xray
	ConfigFile       string `json:"config_file"`                  // external runtime config, e.g. /opt/sshpanel/xray_config.json
	NativeConfigFile string `json:"native_config_file,omitempty"` // native emulator config, independent from external xray

	// Mode selects the runtime implementation. Supported values:
	//   native   = run the in-process emulator implemented in this binary
	//   external = spawn the external /opt/sshpanel/xray binary
	// Empty/unknown is normalized to native so older configs do not silently
	// keep using the external binary after this build is installed.
	Mode string `json:"mode,omitempty"`

	// Native is kept for backward compatibility with older configs/UI payloads.
	// New writes should set both Mode and Native. Runtime decisions use UseNative().
	Native bool `json:"native,omitempty"`

	// Optional Xray API endpoint used for online client counters. If empty,
	// the panel auto-detects a local inbound tagged "api" from the Xray config.
	APIServer string `json:"api_server,omitempty"` // e.g. 127.0.0.1:10085
	// A client is considered online when its Xray stats traffic changed recently.
	OnlineWindowSeconds int `json:"online_window_seconds,omitempty"` // default 90
	StatsPollSeconds    int `json:"stats_poll_seconds,omitempty"`    // default 15

	// NativeIPStrategy controls native outbound address selection. The native
	// runtime defaults to auto dual-stack behavior so IPv6 destinations from
	// clients are preserved when the server has IPv6 connectivity. force_ipv4 is
	// only kept as an explicit legacy override.
	NativeIPStrategy string `json:"native_ip_strategy,omitempty"` // auto | force_ipv4

	// NativeTuning exposes native-emulator scale/performance knobs in the admin panel.
	// These replace the old XRAY_NATIVE_* systemd environment overrides.
	NativeTuning *XrayNativeTuning `json:"native_tuning,omitempty"`
}

const (
	xrayModeNative              = "native"
	xrayModeExternal            = "external"
	defaultXrayBinPath          = "/opt/sshpanel/xray"
	defaultXrayConfigFile       = "/opt/sshpanel/xray_config.json"
	defaultXrayNativeConfigFile = "/opt/sshpanel/xray_native_config.json"
	xrayNativeIPStrategyAuto    = "auto"
	xrayNativeIPStrategyForce4  = "force_ipv4"
)

func (c *XrayConfig) NormalizeDefaults() {
	if c == nil {
		return
	}
	mode := strings.ToLower(strings.TrimSpace(c.Mode))
	switch mode {
	case xrayModeExternal:
		c.Mode = xrayModeExternal
		c.Native = false
	case xrayModeNative:
		c.Mode = xrayModeNative
		c.Native = true
	default:
		// Old configs did not have mode/native and used the external binary by
		// accident. For the emulator build, make internal/native the safe default.
		c.Mode = xrayModeNative
		c.Native = true
	}
	if strings.TrimSpace(c.ConfigFile) == "" {
		c.ConfigFile = defaultXrayConfigFile
	}
	if strings.TrimSpace(c.NativeConfigFile) == "" {
		c.NativeConfigFile = defaultXrayNativeConfigFile
	}
	if strings.TrimSpace(c.BinPath) == "" {
		c.BinPath = defaultXrayBinPath
	}
	switch strings.ToLower(strings.TrimSpace(c.NativeIPStrategy)) {
	case "ipv4", "useipv4", "use_ipv4", xrayNativeIPStrategyForce4:
		c.NativeIPStrategy = xrayNativeIPStrategyForce4
	default:
		c.NativeIPStrategy = xrayNativeIPStrategyAuto
	}
	tuning := normalizeNativeXrayTuning(c.NativeTuning)
	c.NativeTuning = &tuning
	applyNativeXrayTuning(c.NativeTuning)
}

func (c *XrayConfig) NativeForceIPv4() bool {
	if c == nil {
		return false
	}
	mode := strings.ToLower(strings.TrimSpace(c.NativeIPStrategy))
	return mode == xrayNativeIPStrategyForce4 || mode == "ipv4" || mode == "useipv4" || mode == "use_ipv4"
}

func (c *XrayConfig) ModeName() string {
	if c == nil {
		return "disabled"
	}
	mode := strings.ToLower(strings.TrimSpace(c.Mode))
	if mode == xrayModeExternal {
		return xrayModeExternal
	}
	if mode == xrayModeNative || c.Native {
		return xrayModeNative
	}
	return xrayModeNative
}

func (c *XrayConfig) UseNative() bool {
	return c != nil && c.ModeName() != xrayModeExternal
}

func (c *XrayConfig) ActiveConfigFile() string {
	if c == nil {
		return ""
	}
	if c.UseNative() {
		if strings.TrimSpace(c.NativeConfigFile) != "" {
			return strings.TrimSpace(c.NativeConfigFile)
		}
		return defaultXrayNativeConfigFile
	}
	if strings.TrimSpace(c.ConfigFile) != "" {
		return strings.TrimSpace(c.ConfigFile)
	}
	return defaultXrayConfigFile
}

func (c *XrayConfig) ExternalConfigFile() string {
	if c == nil {
		return ""
	}
	if strings.TrimSpace(c.ConfigFile) != "" {
		return strings.TrimSpace(c.ConfigFile)
	}
	return defaultXrayConfigFile
}

// xrayLogRing is a fixed-capacity circular buffer for captured log lines.
type xrayLogRing struct {
	mu    sync.Mutex
	lines []string
	pos   int
}

const (
	xrayLogCap              = 5000
	xrayForcedLogLevel      = "debug"
	xrayForcedAccessLogPath = "/dev/stdout"
	xrayForcedErrorLogPath  = "/dev/stderr"
)

func (r *xrayLogRing) add(line string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.lines) < xrayLogCap {
		r.lines = append(r.lines, line)
	} else {
		r.lines[r.pos] = line
		r.pos = (r.pos + 1) % xrayLogCap
	}
}

func (r *xrayLogRing) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.lines) == 0 {
		return nil
	}
	out := make([]string, len(r.lines))
	if len(r.lines) < xrayLogCap {
		copy(out, r.lines)
	} else {
		n := copy(out, r.lines[r.pos:])
		copy(out[n:], r.lines[:r.pos])
	}
	return out
}

var xrayLogBuf = &xrayLogRing{}

// xrayWriter captures writes from the xray subprocess into the log ring buffer
// and forwards them to stderr so they appear in the process log.
type xrayWriter struct{}

func (w xrayWriter) Write(p []byte) (int, error) {
	text := strings.TrimRight(string(p), "\n")
	for _, line := range strings.Split(text, "\n") {
		if line != "" {
			xrayLogBuf.add(line)
		}
	}
	return os.Stderr.Write(p)
}

// xrayLogf writes native/runtime Xray debug messages directly to stderr and
// to the in-memory Xray log ring. It intentionally bypasses the global
// standard logger because the panel can run in quiet mode and call
// log.SetOutput(io.Discard). Xray debug logs must remain visible while
// troubleshooting transport issues.
func xrayLogf(format string, args ...interface{}) {
	msg := strings.TrimRight(fmt.Sprintf(format, args...), "\n")
	if strings.TrimSpace(msg) == "" {
		return
	}
	ts := time.Now().Format("2006/01/02 15:04:05")
	for _, line := range strings.Split(msg, "\n") {
		if line == "" {
			continue
		}
		full := ts + " " + line
		xrayLogBuf.add(full)
		_, _ = fmt.Fprintln(os.Stderr, full)
	}
}

// xrayTracef is for very hot transport-level traces such as every XHTTP packet.
// Leaving those on under many QUIC users can bottleneck on journald/stderr and
// make the tunnel appear slow. Enable only when packet-level tracing is needed:
// Enable packet-level tracing from Admin Panel -> Xray Native Scale -> Trace packets.
func xrayTracef(format string, args ...interface{}) {
	if !nativeTracePacketsEnabled() {
		return
	}
	xrayLogf(format, args...)
}

// XrayManager manages the lifecycle of the external xray subprocess.
type XrayManager struct {
	mu        sync.Mutex
	cmd       *exec.Cmd
	doneCh    chan struct{}
	cfg       *XrayConfig
	startTime time.Time
	lastErr   string

	statsMu            sync.RWMutex
	statsByEmail       map[string]xrayRuntimeStat
	lastStatsErr       string
	lastStatsPoll      time.Time
	pollStarted        bool
	rateSamplerStarted bool

	nativeDBMu              sync.Mutex
	nativeTrafficPersistMu  sync.Mutex
	nativeTrafficPending    map[string]xrayPendingTraffic
	nativeActivePending     map[string]xrayPendingActive
	nativeStatsFlushStarted bool

	nativeQuotaMu     sync.RWMutex
	nativeQuotaByUUID map[string]*xrayNativeQuotaState
}

type xrayTrafficCounters struct {
	Uplink   int64
	Downlink int64
}

type xrayRuntimeStat struct {
	Email             string
	Uplink            int64
	Downlink          int64
	LastActive        time.Time
	ActiveConnections int
}

type xrayPendingTraffic struct {
	Email    string
	Uplink   int64
	Downlink int64
	State    *xrayNativeQuotaState
}

type xrayPendingActive struct {
	Email     string
	Delta     int
	Connected bool
	State     *xrayNativeQuotaState
}

var xrayMgr = &XrayManager{}

// initXrayManager stores the config and auto-starts Xray if Enabled is true.
func initXrayManager(cfg *XrayConfig) {
	if cfg == nil {
		return
	}
	xrayMgr.mu.Lock()
	xrayMgr.cfg = cfg
	if err := xrayMgr.bootstrapConfigStoreLocked(); err != nil {
		xrayLogf("xray: database config bootstrap failed: %v", err)
	}
	xrayMgr.mu.Unlock()

	// Reconcile already-expired rows before the runtime loads DB-backed clients.
	// The periodic checker intentionally sleeps between passes, so doing one pass
	// here closes the startup window in which an expired UUID could reconnect.
	expireXrayClientsOnce(statsStore)
	xrayMgr.reloadNativeQuotaPolicies()

	// In native mode the in-process emulator records traffic directly, so the
	// external `xray api statsquery` poller is not started (it would overwrite
	// the native counters with errors from a non-existent CLI endpoint).
	xrayMgr.startNativeStatsFlusher()
	xrayMgr.startRateSampler()
	if !cfg.UseNative() {
		xrayMgr.startStatsPoller()
	}

	if cfg.Enabled {
		if err := xrayMgr.Start(); err != nil {
			xrayLogf("xray: auto-start failed: %v", err)
		}
	}
}

// isRunning returns true if the subprocess is currently alive.
// Must be called with m.mu held.
func (m *XrayManager) isRunning() bool {
	if m.doneCh == nil {
		return false
	}
	select {
	case <-m.doneCh:
		return false
	default:
		return true
	}
}

// Start launches the xray subprocess. Returns an error if already running or misconfigured.
func (m *XrayManager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cfg == nil {
		return fmt.Errorf("xray not configured")
	}
	m.cfg.NormalizeDefaults()
	if err := m.syncConfigFileFromStoreLocked(); err != nil {
		m.lastErr = err.Error()
		return err
	}
	configFile := m.activeConfigFileLocked()
	if _, err := m.readConfigLocked(); err != nil && !os.IsNotExist(err) {
		m.lastErr = err.Error()
		return err
	}

	// Native mode: run the in-process emulator instead of the subprocess.
	if m.cfg.UseNative() {
		if nativeXray.nativeRunning() {
			return fmt.Errorf("native xray already running")
		}
		if err := nativeXray.start(configFile); err != nil {
			m.lastErr = err.Error()
			return err
		}
		m.startTime = time.Now()
		m.lastErr = ""
		return nil
	}

	if m.isRunning() {
		return fmt.Errorf("xray already running (pid %d)", m.cmd.Process.Pid)
	}
	if _, err := os.Stat(m.cfg.BinPath); err != nil {
		return fmt.Errorf("xray binary not found at %s", m.cfg.BinPath)
	}
	if changed, err := m.ensureStatsAPIConfigLocked(); err != nil {
		return fmt.Errorf("xray stats api check failed: %w", err)
	} else if changed {
		xrayLogf("xray: repaired Stats API support and forced debug logs in config before start")
	}

	args := []string{"run"}
	if configFile != "" {
		args = append(args, "-c", configFile)
	}

	cmd := exec.Command(m.cfg.BinPath, args...)
	cmd.Stdout = xrayWriter{}
	cmd.Stderr = xrayWriter{}

	if err := cmd.Start(); err != nil {
		m.lastErr = err.Error()
		return fmt.Errorf("xray start: %w", err)
	}

	doneCh := make(chan struct{})
	m.cmd = cmd
	m.doneCh = doneCh
	m.startTime = time.Now()
	m.lastErr = ""

	go func() {
		err := cmd.Wait()
		close(doneCh)
		m.mu.Lock()
		if err != nil {
			m.lastErr = err.Error()
		}
		m.mu.Unlock()
		xrayLogf("xray: process exited: %v", err)
	}()

	xrayLogf("xray: started (pid %d)", cmd.Process.Pid)
	return nil
}

// Stop sends SIGTERM and waits up to 5 s before forcing SIGKILL.
func (m *XrayManager) Stop() error {
	// Stop both implementations defensively. Mode can change at runtime; relying
	// only on the new cfg.Native value can leak the old external subprocess when
	// switching external -> native, or leave native listeners bound when switching
	// native -> external.
	nativeXray.stop()
	m.flushNativeStatsToDB()

	m.mu.Lock()
	if !m.isRunning() {
		m.mu.Unlock()
		return nil
	}
	doneCh := m.doneCh
	cmd := m.cmd
	m.mu.Unlock()

	_ = cmd.Process.Signal(syscall.SIGTERM)

	select {
	case <-doneCh:
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		select {
		case <-doneCh:
		case <-time.After(2 * time.Second):
		}
	}
	xrayLogf("xray: stopped")
	return nil
}

// Restart stops then starts the xray subprocess.
func (m *XrayManager) Restart() error {
	if err := m.Stop(); err != nil {
		return err
	}
	return m.Start()
}

// recordNativeConnect marks a native client stream as online immediately. This
// is more accurate than external Xray's Stats API polling because it knows when
// the decoded VMess/VLESS stream is authenticated and opened.
func (m *XrayManager) recordNativeConnect(uuid, email string, state *xrayNativeQuotaState) {
	uuid = strings.TrimSpace(uuid)
	email = strings.TrimSpace(email)
	if email == "" {
		email = uuid
	}
	if uuid == "" && email == "" {
		return
	}
	now := time.Now()
	m.statsMu.Lock()
	if m.statsByEmail == nil {
		m.statsByEmail = make(map[string]xrayRuntimeStat)
	}
	key := firstNonEmpty(uuid, email)
	st := m.statsByEmail[key]
	st.Email = email
	st.LastActive = now
	st.ActiveConnections++
	m.statsByEmail[key] = st
	m.statsMu.Unlock()

	m.queueNativeActiveDelta(uuid, email, 1, true, state)
}

func (m *XrayManager) recordNativeDisconnect(uuid, email string, state *xrayNativeQuotaState) {
	uuid = strings.TrimSpace(uuid)
	email = strings.TrimSpace(email)
	if email == "" {
		email = uuid
	}
	if uuid == "" && email == "" {
		return
	}
	m.statsMu.Lock()
	if m.statsByEmail != nil {
		key := firstNonEmpty(uuid, email)
		st := m.statsByEmail[key]
		if st.ActiveConnections > 0 {
			st.ActiveConnections--
		}
		m.statsByEmail[key] = st
	}
	m.statsMu.Unlock()

	m.queueNativeActiveDelta(uuid, email, -1, false, state)
}

func (m *XrayManager) queueNativeActiveDelta(uuid, email string, delta int, connected bool, state *xrayNativeQuotaState) {
	if statsStore == nil || uuid == "" || delta == 0 || state == nil {
		return
	}
	// Keep the policy identity stable until the delta is queued. A UUID can be
	// deleted and later recreated; an old connection must never decrement or add
	// traffic to the replacement account merely because the string key matches.
	m.nativeQuotaMu.RLock()
	if m.nativeQuotaByUUID[uuid] != state {
		m.nativeQuotaMu.RUnlock()
		return
	}
	m.nativeDBMu.Lock()
	if m.nativeActivePending == nil {
		m.nativeActivePending = make(map[string]xrayPendingActive)
	}
	p := m.nativeActivePending[uuid]
	if p.State != nil && p.State != state {
		p = xrayPendingActive{}
	}
	if p.Email == "" {
		p.Email = email
	}
	p.Delta += delta
	p.Connected = p.Connected || connected
	p.State = state
	m.nativeActivePending[uuid] = p
	m.nativeDBMu.Unlock()
	m.nativeQuotaMu.RUnlock()
}

// recordNativeTraffic accumulates in-process byte counters for a client and
// queues DB persistence. Used by the native emulator instead of external
// `xray api statsquery` polling.
func (m *XrayManager) recordNativeTraffic(uuid, email string, up, down int64, generation uint64, state *xrayNativeQuotaState) {
	uuid = strings.TrimSpace(uuid)
	email = strings.TrimSpace(email)
	if email == "" {
		email = uuid
	}
	if email == "" || (up == 0 && down == 0) {
		return
	}
	if state != nil {
		// Keep generation validation and queuing in the same critical section as
		// resetNativeTrafficAccounting. Otherwise an old meter can validate just
		// before a reset and enqueue its bytes immediately after the DB was zeroed.
		state.mu.Lock()
		defer state.mu.Unlock()
		if generation != state.generation {
			return
		}
	}

	// Only DB-backed clients have a native policy state. Config-only clients are
	// still shown in runtime stats, but queuing UPDATEs for rows that do not exist
	// can make the retry map grow during a database outage.
	if statsStore != nil && uuid != "" && state != nil {
		m.nativeQuotaMu.RLock()
		if m.nativeQuotaByUUID[uuid] != state {
			m.nativeQuotaMu.RUnlock()
			return
		}
		m.nativeDBMu.Lock()
		if m.nativeTrafficPending == nil {
			m.nativeTrafficPending = make(map[string]xrayPendingTraffic)
		}
		p := m.nativeTrafficPending[uuid]
		if p.State != nil && p.State != state {
			p = xrayPendingTraffic{}
		}
		p.Email = email
		p.Uplink += up
		p.Downlink += down
		p.State = state
		m.nativeTrafficPending[uuid] = p
		m.nativeDBMu.Unlock()
		m.nativeQuotaMu.RUnlock()
	}

	now := time.Now()
	m.statsMu.Lock()
	if m.statsByEmail == nil {
		m.statsByEmail = make(map[string]xrayRuntimeStat)
	}
	key := firstNonEmpty(uuid, email)
	st := m.statsByEmail[key]
	st.Email = email
	st.Uplink += up
	st.Downlink += down
	st.LastActive = now
	m.statsByEmail[key] = st
	m.statsMu.Unlock()

}

func (m *XrayManager) startNativeStatsFlusher() {
	m.nativeDBMu.Lock()
	if m.nativeStatsFlushStarted {
		m.nativeDBMu.Unlock()
		return
	}
	m.nativeStatsFlushStarted = true
	m.nativeDBMu.Unlock()

	xrayGo("native xray stats flusher", func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			m.flushNativeStatsToDB()
			m.pruneStaleRuntimeStats()
		}
	})
}

// pruneStaleRuntimeStats drops runtime stat entries for clients that have no
// active connections and have been idle well past the online window. Without
// this, statsByEmail keeps one entry per email/UUID that has ever connected and
// never shrinks. The retention comfortably exceeds the online-detection grace
// window so CountOnlineUsers is unaffected; persistent traffic totals live in
// the DB, so dropping the in-memory counter for a long-offline client is safe.
func (m *XrayManager) pruneStaleRuntimeStats() {
	retention := 2 * m.onlineWindow()
	if retention < 5*time.Minute {
		retention = 5 * time.Minute
	}
	cutoff := time.Now().Add(-retention)
	m.statsMu.Lock()
	for email, st := range m.statsByEmail {
		if st.ActiveConnections <= 0 && (st.LastActive.IsZero() || st.LastActive.Before(cutoff)) {
			delete(m.statsByEmail, email)
		}
	}
	m.statsMu.Unlock()
}

func (m *XrayManager) flushNativeStatsToDB() {
	if statsStore == nil {
		return
	}
	m.nativeTrafficPersistMu.Lock()
	defer m.nativeTrafficPersistMu.Unlock()
	persistent := m.nativePersistentStates()
	m.nativeDBMu.Lock()
	for uuid, pending := range m.nativeTrafficPending {
		if persistent[uuid] != pending.State {
			delete(m.nativeTrafficPending, uuid)
		}
	}
	for uuid, pending := range m.nativeActivePending {
		if persistent[uuid] != pending.State {
			delete(m.nativeActivePending, uuid)
		}
	}
	pendingTraffic := m.nativeTrafficPending
	pendingActive := m.nativeActivePending
	m.nativeTrafficPending = nil
	m.nativeActivePending = nil
	m.nativeDBMu.Unlock()
	if len(pendingTraffic) == 0 && len(pendingActive) == 0 {
		return
	}

	var trafficErr error
	if len(pendingTraffic) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		trafficErr = statsStore.AddXrayClientTrafficBatch(ctx, pendingTraffic)
		cancel()
	}
	var activeErr error
	if len(pendingActive) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		activeErr = statsStore.AddXrayClientActiveBatch(ctx, pendingActive)
		cancel()
	}

	if trafficErr != nil {
		xrayLogf("xray native stats: db traffic flush failed: %v", trafficErr)
	}
	if activeErr != nil {
		xrayLogf("xray native stats: db active flush failed: %v", activeErr)
	}
	if trafficErr != nil || activeErr != nil {
		// Put only failed batches back so a successful write is never duplicated.
		persistent = m.nativePersistentStates()
		m.nativeDBMu.Lock()
		if trafficErr != nil && m.nativeTrafficPending == nil {
			m.nativeTrafficPending = make(map[string]xrayPendingTraffic)
		}
		if trafficErr != nil {
			for uuid, d := range pendingTraffic {
				if persistent[uuid] != d.State {
					continue
				}
				p := m.nativeTrafficPending[uuid]
				if p.State != nil && p.State != d.State {
					p = xrayPendingTraffic{}
				}
				if p.Email == "" {
					p.Email = d.Email
				}
				p.Uplink += d.Uplink
				p.Downlink += d.Downlink
				p.State = d.State
				m.nativeTrafficPending[uuid] = p
			}
		}
		if activeErr != nil && m.nativeActivePending == nil {
			m.nativeActivePending = make(map[string]xrayPendingActive)
		}
		if activeErr != nil {
			for uuid, d := range pendingActive {
				if persistent[uuid] != d.State {
					continue
				}
				p := m.nativeActivePending[uuid]
				if p.State != nil && p.State != d.State {
					p = xrayPendingActive{}
				}
				if p.Email == "" {
					p.Email = d.Email
				}
				p.Delta += d.Delta
				p.Connected = p.Connected || d.Connected
				p.State = d.State
				m.nativeActivePending[uuid] = p
			}
		}
		m.nativeDBMu.Unlock()
	}
}

func (m *XrayManager) nativePersistentStates() map[string]*xrayNativeQuotaState {
	m.nativeQuotaMu.RLock()
	out := make(map[string]*xrayNativeQuotaState, len(m.nativeQuotaByUUID))
	for uuid, state := range m.nativeQuotaByUUID {
		out[uuid] = state
	}
	m.nativeQuotaMu.RUnlock()
	return out
}

// XrayStatusDTO is returned by /api/xray/status.
type XrayStatusDTO struct {
	Enabled         bool       `json:"enabled"`
	Running         bool       `json:"running"`
	Mode            string     `json:"mode"`
	Native          bool       `json:"native"`
	PID             int        `json:"pid,omitempty"`
	Uptime          string     `json:"uptime,omitempty"`
	Error           string     `json:"error,omitempty"`
	OnlineUsers     int        `json:"online_users"`
	StatsError      string     `json:"stats_error,omitempty"`
	StatsConfigured bool       `json:"stats_configured"`
	StatsMissing    []string   `json:"stats_missing,omitempty"`
	APIServer       string     `json:"api_server,omitempty"`
	LastStatsPoll   *time.Time `json:"last_stats_poll,omitempty"`
	OnlineWindowSec int        `json:"online_window_seconds"`
}

// Status returns a snapshot of the current xray process state.
func (m *XrayManager) Status() XrayStatusDTO {
	m.mu.Lock()
	native := m.cfg != nil && m.cfg.UseNative()
	m.mu.Unlock()

	// Native mode: report the in-process emulator's state. Traffic counters are
	// recorded live so there is no CLI poll and no Stats API config to check.
	if native {
		m.mu.Lock()
		s := XrayStatusDTO{Enabled: m.cfg.Enabled, Mode: m.cfg.ModeName(), Native: m.cfg.UseNative()}
		if nativeXray.nativeRunning() {
			s.Running = true
			s.Uptime = time.Since(m.startTime).Round(time.Second).String()
		}
		if m.lastErr != "" {
			s.Error = m.lastErr
		}
		m.mu.Unlock()
		s.OnlineUsers = m.CountOnlineUsers()
		s.OnlineWindowSec = int(m.onlineWindow().Seconds())
		s.StatsConfigured = true // in-process metering is always available
		return s
	}

	m.refreshRuntimeStatsIfStale(3 * time.Second)
	m.mu.Lock()
	s := XrayStatusDTO{}
	if m.cfg != nil {
		s.Enabled = m.cfg.Enabled
		s.Mode = m.cfg.ModeName()
		s.Native = m.cfg.UseNative()
	}
	if m.isRunning() && m.cmd != nil && m.cmd.Process != nil {
		s.Running = true
		s.PID = m.cmd.Process.Pid
		s.Uptime = time.Since(m.startTime).Round(time.Second).String()
	}
	if m.lastErr != "" {
		s.Error = m.lastErr
	}
	m.mu.Unlock()

	s.OnlineUsers = m.CountOnlineUsers()
	s.OnlineWindowSec = int(m.onlineWindow().Seconds())
	m.statsMu.RLock()
	if m.lastStatsErr != "" {
		s.StatsError = m.lastStatsErr
	}
	if !m.lastStatsPoll.IsZero() {
		t := m.lastStatsPoll
		s.LastStatsPoll = &t
	}
	m.statsMu.RUnlock()
	if check, err := m.CheckStatsAPIConfig(); err == nil {
		s.StatsConfigured = check.Configured
		s.StatsMissing = check.Missing
		s.APIServer = check.APIServer
	} else if err != nil {
		s.StatsConfigured = false
		s.StatsMissing = []string{err.Error()}
	}
	return s
}

func (m *XrayManager) pollInterval() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	sec := 15
	if m.cfg != nil && m.cfg.StatsPollSeconds > 0 {
		sec = m.cfg.StatsPollSeconds
	}
	if sec < 5 {
		sec = 5
	}
	return time.Duration(sec) * time.Second
}

func (m *XrayManager) onlineWindow() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	sec := 90
	if m.cfg != nil && m.cfg.OnlineWindowSeconds > 0 {
		sec = m.cfg.OnlineWindowSeconds
	}
	if sec < 15 {
		sec = 15
	}
	return time.Duration(sec) * time.Second
}

func (m *XrayManager) startStatsPoller() {
	m.mu.Lock()
	if m.pollStarted {
		m.mu.Unlock()
		return
	}
	m.pollStarted = true
	m.mu.Unlock()

	go func() {
		// First sample establishes a baseline. Active Xray users appear online
		// after their traffic counters change on a later poll.
		for {
			m.refreshRuntimeStats()
			time.Sleep(m.pollInterval())
		}
	}()
}

// Live per-client speed, derived from the same cumulative counters the panel
// already reports as lifetime traffic.
var xrayBandwidth = newBandwidthSampler(6*time.Second, 45*time.Second)

const xrayNativeRateSampleInterval = 2 * time.Second

// startRateSampler keeps xrayBandwidth fresh in native mode, where the
// in-process runtime updates the counters continuously. In external mode the
// counters only move once per stats poll (15s by default), so refreshRuntimeStats
// feeds the sampler at its own cadence instead — sampling faster than the source
// updates would show alternating spikes and zeros. The mode is re-checked on
// every tick because a hot reload can switch it while running.
func (m *XrayManager) startRateSampler() {
	m.mu.Lock()
	if m.rateSamplerStarted {
		m.mu.Unlock()
		return
	}
	m.rateSamplerStarted = true
	m.mu.Unlock()

	go func() {
		ticker := time.NewTicker(xrayNativeRateSampleInterval)
		defer ticker.Stop()
		for range ticker.C {
			if !m.usesNativeSnapshot() {
				continue
			}
			m.sampleRuntimeRates(time.Now())
		}
	}()
}

func (m *XrayManager) usesNativeSnapshot() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg != nil && m.cfg.UseNative()
}

func (m *XrayManager) sampleRuntimeRates(now time.Time) {
	type counterSnapshot struct {
		key      string
		uplink   int64
		downlink int64
	}
	m.statsMu.RLock()
	snapshots := make([]counterSnapshot, 0, len(m.statsByEmail))
	for key, st := range m.statsByEmail {
		snapshots = append(snapshots, counterSnapshot{key: key, uplink: st.Uplink, downlink: st.Downlink})
	}
	m.statsMu.RUnlock()

	active := make(map[string]struct{}, len(snapshots))
	for _, snapshot := range snapshots {
		xrayBandwidth.Observe(snapshot.key, snapshot.uplink, snapshot.downlink, now)
		active[snapshot.key] = struct{}{}
	}
	xrayBandwidth.Retain(active)
}

// RuntimeRateForKeys resolves a client's live speed. Clients are tracked under
// their UUID in native mode and under their stats-API email in external mode,
// so callers pass every identifier the client may be stored under.
func (m *XrayManager) RuntimeRateForKeys(keys ...string) (bandwidthRate, bool) {
	return xrayBandwidth.RateForKeys(keys...)
}

func (m *XrayManager) isRunningSnapshot() bool {
	m.mu.Lock()
	native := m.cfg != nil && m.cfg.UseNative()
	m.mu.Unlock()
	if native {
		return nativeXray.nativeRunning()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.isRunning()
}

func (m *XrayManager) apiCommandConfig() (binPath, apiServer string, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cfg == nil || m.cfg.BinPath == "" || m.cfg.ExternalConfigFile() == "" {
		return "", "", false
	}
	binPath = m.cfg.BinPath
	apiServer = strings.TrimSpace(m.cfg.APIServer)
	if apiServer == "" {
		apiServer = m.discoverAPIServerLocked()
	}
	return binPath, apiServer, apiServer != ""
}

func (m *XrayManager) discoverAPIServerLocked() string {
	if m.cfg == nil || m.cfg.ExternalConfigFile() == "" {
		return ""
	}
	data, err := os.ReadFile(m.cfg.ExternalConfigFile())
	if err != nil {
		return ""
	}
	var cfg struct {
		Inbounds []struct {
			Tag      string          `json:"tag"`
			Listen   string          `json:"listen"`
			Protocol string          `json:"protocol"`
			Port     json.RawMessage `json:"port"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return ""
	}
	for _, ib := range cfg.Inbounds {
		if ib.Tag != "api" || !strings.EqualFold(ib.Protocol, "dokodemo-door") {
			continue
		}
		host := strings.TrimSpace(ib.Listen)
		if host == "" || host == "0.0.0.0" || host == "::" {
			host = "127.0.0.1"
		}
		port := strings.Trim(string(ib.Port), `"`)
		if port == "" || port == "null" {
			continue
		}
		return host + ":" + port
	}
	return ""
}

func (m *XrayManager) refreshRuntimeStats() {
	if !m.isRunningSnapshot() {
		return
	}
	traffic, err := m.queryUserTraffic()
	now := time.Now()
	m.statsMu.Lock()
	defer m.statsMu.Unlock()
	m.lastStatsPoll = now
	if err != nil {
		m.lastStatsErr = err.Error()
		return
	}
	m.lastStatsErr = ""
	if m.statsByEmail == nil {
		m.statsByEmail = make(map[string]xrayRuntimeStat, len(traffic))
	}
	// External mode: the counters only move once per poll, so this is also the
	// natural cadence for the live speed sampler.
	active := make(map[string]struct{}, len(traffic))
	for email, counters := range traffic {
		active[email] = struct{}{}
		xrayBandwidth.Observe(email, counters.Uplink, counters.Downlink, now)
		prev := m.statsByEmail[email]
		st := xrayRuntimeStat{Email: email, Uplink: counters.Uplink, Downlink: counters.Downlink, LastActive: prev.LastActive, ActiveConnections: prev.ActiveConnections}
		changed := counters.Uplink != prev.Uplink || counters.Downlink != prev.Downlink
		// First successful poll with non-zero traffic means the client has been
		// active since Xray started. Later polls refresh LastActive only when bytes
		// move, which avoids counting old idle clients forever.
		if changed && (prev.Email != "" || counters.Uplink+counters.Downlink > 0) {
			st.LastActive = now
		}
		m.statsByEmail[email] = st
	}
	// Keep old stat entries, but do not delete them immediately: Xray may omit
	// zero counters for users that have not moved traffic yet. Speed samples are
	// dropped for absent users because a missing baseline only costs one poll.
	xrayBandwidth.Retain(active)
}

func (m *XrayManager) refreshRuntimeStatsIfStale(maxAge time.Duration) {
	if !m.isRunningSnapshot() {
		return
	}
	m.statsMu.RLock()
	last := m.lastStatsPoll
	m.statsMu.RUnlock()
	if last.IsZero() || time.Since(last) >= maxAge {
		m.refreshRuntimeStats()
	}
}

func (m *XrayManager) queryUserTraffic() (map[string]xrayTrafficCounters, error) {
	binPath, apiServer, ok := m.apiCommandConfig()
	if !ok {
		return nil, fmt.Errorf("Xray API stats not configured; add an api inbound or set xray.api_server")
	}
	attempts := [][]string{
		{"api", "statsquery", "--server=" + apiServer, "-pattern", "user>>>", "-reset=false"},
		{"api", "statsquery", "--server", apiServer, "-pattern", "user>>>", "-reset=false"},
		{"api", "statsquery", "--server=" + apiServer, "-pattern", "user>>>"},
		{"api", "statsquery", "--server", apiServer, "-pattern", "user>>>"},
	}
	var lastErr error
	for _, args := range attempts {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cmd := exec.CommandContext(ctx, binPath, args...)
		out, err := cmd.CombinedOutput()
		cancel()
		if err == nil {
			return parseXrayStatsOutput(out), nil
		}
		lastErr = fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil, fmt.Errorf("Xray stats query failed: %v", lastErr)
}

func parseXrayStatsOutput(out []byte) map[string]xrayTrafficCounters {
	result := map[string]xrayTrafficCounters{}
	type rawStat struct {
		Name  string          `json:"name"`
		Value json.RawMessage `json:"value"`
	}
	var js struct {
		Stat  []rawStat `json:"stat"`
		Stats []rawStat `json:"stats"`
	}
	if json.Unmarshal(out, &js) == nil {
		for _, st := range js.Stat {
			addXrayCounter(result, st.Name, parseXrayStatValue(st.Value))
		}
		for _, st := range js.Stats {
			addXrayCounter(result, st.Name, parseXrayStatValue(st.Value))
		}
	}
	if len(result) > 0 {
		return result
	}

	// Text/protobuf form: name: "user>>>..." value: 123
	reText := regexp.MustCompile(`(?s)name:\s*"([^"]+)"\s+value:\s*([0-9]+)`)
	for _, m := range reText.FindAllSubmatch(out, -1) {
		v, _ := strconv.ParseInt(string(m[2]), 10, 64)
		addXrayCounter(result, string(m[1]), v)
	}
	if len(result) > 0 {
		return result
	}

	// Some Xray/protobuf JSON builds encode int64 values as strings.
	reJSON := regexp.MustCompile(`"name"\s*:\s*"([^"]+)"[^}]*"value"\s*:\s*"?([0-9]+)"?`)
	for _, m := range reJSON.FindAllSubmatch(out, -1) {
		v, _ := strconv.ParseInt(string(m[2]), 10, 64)
		addXrayCounter(result, string(m[1]), v)
	}
	return result
}

func parseXrayStatValue(raw json.RawMessage) int64 {
	if len(raw) == 0 {
		return 0
	}
	var n int64
	if err := json.Unmarshal(raw, &n); err == nil {
		return n
	}
	var f float64
	if err := json.Unmarshal(raw, &f); err == nil {
		return int64(f)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		v, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		return v
	}
	return 0
}

func addXrayCounter(result map[string]xrayTrafficCounters, name string, value int64) {
	// Xray user traffic stats are normally named:
	//   user>>>EMAIL>>>traffic>>>uplink
	//   user>>>EMAIL>>>traffic>>>downlink
	// Older code expected a fifth segment and therefore ignored valid Xray
	// Stats API responses, which made every client look offline.
	parts := strings.Split(name, ">>>")
	if len(parts) < 4 || parts[0] != "user" || parts[2] != "traffic" {
		return
	}
	email := strings.TrimSpace(parts[1])
	direction := strings.ToLower(strings.TrimSpace(parts[3]))
	if email == "" {
		return
	}
	c := result[email]
	switch direction {
	case "uplink":
		c.Uplink = value
	case "downlink":
		c.Downlink = value
	default:
		return
	}
	result[email] = c
}

func (m *XrayManager) RuntimeStatsForEmail(email string) (xrayRuntimeStat, bool) {
	return m.RuntimeStatsForKeys(email)
}

func (m *XrayManager) RuntimeStatsForKeys(keys ...string) (xrayRuntimeStat, bool) {
	m.statsMu.RLock()
	defer m.statsMu.RUnlock()
	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if st, ok := m.statsByEmail[key]; ok && st.Email != "" {
			return st, true
		}
	}
	return xrayRuntimeStat{}, false
}

func (m *XrayManager) CountOnlineUsers() int {
	window := m.onlineWindow()
	now := time.Now()
	m.statsMu.RLock()
	defer m.statsMu.RUnlock()
	n := 0
	for _, st := range m.statsByEmail {
		if st.ActiveConnections > 0 || (!st.LastActive.IsZero() && now.Sub(st.LastActive) <= window) {
			n++
		}
	}
	return n
}

func (m *XrayManager) activeConfigFileLocked() string {
	if m.cfg == nil {
		return ""
	}
	return m.cfg.ActiveConfigFile()
}

func (m *XrayManager) configStoreKeyLocked() string {
	if m.cfg == nil {
		return "default"
	}
	mode := m.cfg.ModeName()
	path := strings.TrimSpace(m.activeConfigFileLocked())
	if path == "" {
		path = "default"
	}
	return mode + ":" + path
}

func normalizeJSONIndent(data []byte) ([]byte, error) {
	var raw interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	return json.MarshalIndent(raw, "", "  ")
}

func forceXrayDebugLogBytes(data []byte) ([]byte, bool, error) {
	if !json.Valid(data) {
		return nil, false, fmt.Errorf("invalid JSON")
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, false, fmt.Errorf("parse xray config: %w", err)
	}
	if raw == nil {
		return nil, false, fmt.Errorf("xray config must be a JSON object")
	}
	changed := ensureXrayForcedDebugLogConfig(raw)
	if !changed {
		return data, false, nil
	}
	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return nil, false, err
	}
	return out, true, nil
}

func ensureXrayForcedDebugLogConfig(raw map[string]interface{}) bool {
	changed := false
	logObj := asObject(raw["log"])
	if logObj == nil {
		logObj = map[string]interface{}{}
		raw["log"] = logObj
		changed = true
	}
	if v, _ := logObj["access"].(string); v != xrayForcedAccessLogPath {
		logObj["access"] = xrayForcedAccessLogPath
		changed = true
	}
	if v, _ := logObj["error"].(string); v != xrayForcedErrorLogPath {
		logObj["error"] = xrayForcedErrorLogPath
		changed = true
	}
	if v, _ := logObj["loglevel"].(string); !strings.EqualFold(v, xrayForcedLogLevel) {
		logObj["loglevel"] = xrayForcedLogLevel
		changed = true
	}
	if v, _ := logObj["dnsLog"].(bool); !v {
		logObj["dnsLog"] = true
		changed = true
	}
	return changed
}

func (m *XrayManager) readConfigLocked() ([]byte, error) {
	configFile := m.activeConfigFileLocked()
	if m.cfg == nil || configFile == "" {
		return nil, fmt.Errorf("xray config file not configured")
	}
	if statsStore != nil {
		if data, ok, err := statsStore.GetXrayConfig(context.Background(), m.configStoreKeyLocked()); err != nil {
			xrayLogf("xray: database config read failed, falling back to file: %v", err)
		} else if ok {
			if forced, changed, err := forceXrayDebugLogBytes(data); err != nil {
				return nil, err
			} else if changed {
				data = forced
				_ = statsStore.UpsertXrayConfig(context.Background(), m.configStoreKeyLocked(), forced)
				xrayLogf("xray: forced debug log output in database config")
			}
			pretty, err := normalizeJSONIndent(data)
			if err != nil {
				return nil, err
			}
			_ = writeFileAtomic(configFile, pretty, 0o600)
			return pretty, nil
		}
	}
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, err
	}
	if forced, changed, err := forceXrayDebugLogBytes(data); err != nil {
		return nil, err
	} else if changed {
		data = forced
		_ = writeFileAtomic(configFile, forced, 0o600)
		xrayLogf("xray: forced debug log output in file config")
	}
	return data, nil
}

func (m *XrayManager) writeConfigLocked(data []byte) error {
	configFile := m.activeConfigFileLocked()
	if m.cfg == nil || configFile == "" {
		return fmt.Errorf("xray config file not configured")
	}
	if forced, changed, err := forceXrayDebugLogBytes(data); err != nil {
		return err
	} else if changed {
		data = forced
		xrayLogf("xray: forced debug log output while saving config")
	}
	pretty, err := normalizeJSONIndent(data)
	if err != nil {
		return err
	}
	if statsStore != nil {
		if err := statsStore.UpsertXrayConfig(context.Background(), m.configStoreKeyLocked(), pretty); err != nil {
			return fmt.Errorf("save Xray config to database: %w", err)
		}
	}
	if err := writeFileAtomic(configFile, pretty, 0o600); err != nil {
		return err
	}
	m.importConfigClientsLocked(pretty, "saved xray config")
	return nil
}

func (m *XrayManager) importConfigClientsLocked(data []byte, source string) {
	if statsStore == nil || len(data) == 0 {
		return
	}
	n, err := statsStore.ImportXrayClientsFromConfig(context.Background(), data)
	if err != nil {
		xrayLogf("xray: import clients from %s failed: %v", source, err)
		return
	}
	if n > 0 {
		xrayLogf("xray: imported/synced %d client UUIDs from %s into database", n, source)
	}
}

func (m *XrayManager) importRuntimeConfigFileClientsLocked(source string) {
	configFile := m.activeConfigFileLocked()
	if m.cfg == nil || strings.TrimSpace(configFile) == "" || statsStore == nil {
		return
	}
	data, err := os.ReadFile(configFile)
	if err != nil {
		if !os.IsNotExist(err) {
			xrayLogf("xray: read %s for client import failed: %v", configFile, err)
		}
		return
	}
	pretty, err := normalizeJSONIndent(data)
	if err != nil {
		xrayLogf("xray: cannot import clients from %s: invalid JSON: %v", configFile, err)
		return
	}
	m.importConfigClientsLocked(pretty, source)
}

func (m *XrayManager) restartIfExternalRunning() {
	m.mu.Lock()
	external := m.cfg != nil && !m.cfg.UseNative()
	running := external && m.isRunning()
	m.mu.Unlock()
	if !running {
		return
	}
	if err := m.Restart(); err != nil {
		xrayLogf("xray: external restart after client/config change failed: %v", err)
	}
}

func (m *XrayManager) useNativeMode() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg != nil && m.cfg.UseNative()
}

func (m *XrayManager) bootstrapConfigStoreLocked() error {
	configFile := m.activeConfigFileLocked()
	if m.cfg == nil || configFile == "" || statsStore == nil {
		return nil
	}
	ctx := context.Background()
	key := m.configStoreKeyLocked()

	if data, ok, err := statsStore.GetXrayConfig(ctx, key); err != nil {
		return err
	} else if ok {
		if forced, changed, err := forceXrayDebugLogBytes(data); err != nil {
			return err
		} else if changed {
			data = forced
			if err := statsStore.UpsertXrayConfig(ctx, key, forced); err != nil {
				return err
			}
			xrayLogf("xray: forced debug log output during config bootstrap")
		}
		pretty, err := normalizeJSONIndent(data)
		if err != nil {
			return err
		}
		m.importConfigClientsLocked(pretty, "database xray config")
		return writeFileAtomic(configFile, pretty, 0o600)
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		if os.IsNotExist(err) && m.cfg.UseNative() {
			// One-time migration only: if this node already has an old external
			// config and no native config exists yet, clone it into the native path.
			// After this point native mode reads/writes only its own DB row/file.
			if migrated, migErr := m.seedNativeConfigFromExternalLocked(configFile); migErr != nil {
				return migErr
			} else if len(migrated) > 0 {
				if forced, changed, err := forceXrayDebugLogBytes(migrated); err != nil {
					return err
				} else if changed {
					migrated = forced
					xrayLogf("xray: forced debug log output during native config migration")
				}
				pretty, err := normalizeJSONIndent(migrated)
				if err != nil {
					return err
				}
				m.importConfigClientsLocked(pretty, "one-time external-to-native migration")
				if err := statsStore.UpsertXrayConfig(ctx, key, pretty); err != nil {
					return err
				}
				return writeFileAtomic(configFile, pretty, 0o600)
			}
		}
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if forced, changed, err := forceXrayDebugLogBytes(data); err != nil {
		return err
	} else if changed {
		data = forced
		xrayLogf("xray: forced debug log output while importing runtime config")
	}
	pretty, err := normalizeJSONIndent(data)
	if err != nil {
		return err
	}
	m.importConfigClientsLocked(pretty, "runtime xray config")
	return statsStore.UpsertXrayConfig(ctx, key, pretty)
}

func (m *XrayManager) seedNativeConfigFromExternalLocked(nativeConfigFile string) ([]byte, error) {
	if m.cfg == nil || !m.cfg.UseNative() {
		return nil, nil
	}
	ext := strings.TrimSpace(m.cfg.ExternalConfigFile())
	if ext == "" || ext == nativeConfigFile {
		return nil, nil
	}
	data, err := os.ReadFile(ext)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if _, err := normalizeJSONIndent(data); err != nil {
		return nil, err
	}
	xrayLogf("xray native: cloned %s to independent native config %s once", ext, nativeConfigFile)
	return data, nil
}

func (m *XrayManager) syncConfigFileFromStoreLocked() error {
	configFile := m.activeConfigFileLocked()
	if m.cfg == nil || configFile == "" || statsStore == nil {
		return nil
	}
	data, ok, err := statsStore.GetXrayConfig(context.Background(), m.configStoreKeyLocked())
	if err != nil || !ok {
		return err
	}
	if forced, changed, err := forceXrayDebugLogBytes(data); err != nil {
		return err
	} else if changed {
		data = forced
		if err := statsStore.UpsertXrayConfig(context.Background(), m.configStoreKeyLocked(), forced); err != nil {
			return err
		}
		xrayLogf("xray: forced debug log output while syncing config")
	}
	pretty, err := normalizeJSONIndent(data)
	if err != nil {
		return err
	}
	m.importConfigClientsLocked(pretty, "database xray config")
	return writeFileAtomic(configFile, pretty, 0o600)
}

// GetConfig reads the current Xray JSON config. With PostgreSQL enabled, the
// database row is canonical and the file is only a synchronized runtime copy.
func (m *XrayManager) GetConfig() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.readConfigLocked()
}

// SetConfig validates and writes a new Xray JSON config to DB and to the runtime file.
func (m *XrayManager) SetConfig(data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	patched, changed, err := patchXrayStatsAPIBytes(data)
	if err != nil {
		return err
	}
	if changed {
		xrayLogf("xray: added/repaired Stats API support and forced debug logs while saving config")
	}
	if m.cfg != nil && m.cfg.UseNative() {
		if err := validateNativeInboundBindings(patched); err != nil {
			return err
		}
	}
	return m.writeConfigLocked(patched)
}

type xrayStatsConfigCheck struct {
	Configured bool
	Missing    []string
	APIServer  string
}

func (m *XrayManager) CheckStatsAPIConfig() (xrayStatsConfigCheck, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.checkStatsAPIConfigLocked()
}

func (m *XrayManager) checkStatsAPIConfigLocked() (xrayStatsConfigCheck, error) {
	data, err := m.readConfigLocked()
	if err != nil {
		return xrayStatsConfigCheck{}, err
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return xrayStatsConfigCheck{}, fmt.Errorf("parse xray config: %w", err)
	}
	if raw == nil {
		return xrayStatsConfigCheck{}, fmt.Errorf("xray config must be a JSON object")
	}
	check := checkXrayStatsAPIConfig(raw)
	if check.APIServer == "" {
		check.APIServer = m.discoverAPIServerFromRaw(raw)
	}
	return check, nil
}

func (m *XrayManager) EnsureStatsAPIConfig() (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ensureStatsAPIConfigLocked()
}

func (m *XrayManager) ensureStatsAPIConfigLocked() (bool, error) {
	data, err := m.readConfigLocked()
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	patched, changed, err := patchXrayStatsAPIBytes(data)
	if err != nil {
		return false, err
	}
	if !changed {
		return false, nil
	}
	return true, m.writeConfigLocked(patched)
}

func patchXrayStatsAPIBytes(data []byte) ([]byte, bool, error) {
	if !json.Valid(data) {
		return nil, false, fmt.Errorf("invalid JSON")
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, false, fmt.Errorf("parse xray config: %w", err)
	}
	if raw == nil {
		return nil, false, fmt.Errorf("xray config must be a JSON object")
	}
	changed, _ := ensureXrayStatsAPIConfig(raw)
	if ensureXrayForcedDebugLogConfig(raw) {
		changed = true
	}
	if !changed {
		return data, false, nil
	}
	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return nil, false, err
	}
	return out, true, nil
}

func ensureXrayStatsAPIConfig(raw map[string]interface{}) (bool, xrayStatsConfigCheck) {
	changed := false

	api := asObject(raw["api"])
	if api == nil {
		api = map[string]interface{}{}
		raw["api"] = api
		changed = true
	}
	if tag, _ := api["tag"].(string); tag != "api" {
		api["tag"] = "api"
		changed = true
	}
	services, ok := api["services"].([]interface{})
	if !ok {
		services = []interface{}{}
	}
	for _, svc := range []string{"HandlerService", "LoggerService", "StatsService"} {
		if !sliceHasString(services, svc) {
			services = append(services, svc)
			changed = true
		}
	}
	api["services"] = services

	if asObject(raw["stats"]) == nil {
		raw["stats"] = map[string]interface{}{}
		changed = true
	}

	policy := asObject(raw["policy"])
	if policy == nil {
		policy = map[string]interface{}{}
		raw["policy"] = policy
		changed = true
	}
	levels := asObject(policy["levels"])
	if levels == nil {
		levels = map[string]interface{}{}
		policy["levels"] = levels
		changed = true
	}
	level0 := asObject(levels["0"])
	if level0 == nil {
		level0 = map[string]interface{}{}
		levels["0"] = level0
		changed = true
	}
	for _, key := range []string{"statsUserUplink", "statsUserDownlink"} {
		if v, _ := level0[key].(bool); !v {
			level0[key] = true
			changed = true
		}
	}
	system := asObject(policy["system"])
	if system == nil {
		system = map[string]interface{}{}
		policy["system"] = system
		changed = true
	}
	for _, key := range []string{"statsInboundUplink", "statsInboundDownlink"} {
		if v, _ := system[key].(bool); !v {
			system[key] = true
			changed = true
		}
	}

	inbounds, _ := raw["inbounds"].([]interface{})
	apiInbound := findObjectByTag(inbounds, "api")
	if apiInbound == nil {
		apiInbound = map[string]interface{}{
			"tag":      "api",
			"listen":   "127.0.0.1",
			"port":     float64(10085),
			"protocol": "dokodemo-door",
			"settings": map[string]interface{}{"address": "127.0.0.1"},
		}
		inbounds = append([]interface{}{apiInbound}, inbounds...)
		raw["inbounds"] = inbounds
		changed = true
	} else {
		if proto, _ := apiInbound["protocol"].(string); !strings.EqualFold(proto, "dokodemo-door") {
			apiInbound["protocol"] = "dokodemo-door"
			changed = true
		}
		if strings.TrimSpace(fmt.Sprint(apiInbound["listen"])) == "" {
			apiInbound["listen"] = "127.0.0.1"
			changed = true
		}
		if _, ok := apiInbound["port"]; !ok || strings.TrimSpace(fmt.Sprint(apiInbound["port"])) == "" || strings.TrimSpace(fmt.Sprint(apiInbound["port"])) == "<nil>" {
			apiInbound["port"] = float64(10085)
			changed = true
		}
		settings := asObject(apiInbound["settings"])
		if settings == nil {
			settings = map[string]interface{}{}
			apiInbound["settings"] = settings
			changed = true
		}
		if strings.TrimSpace(fmt.Sprint(settings["address"])) == "" || strings.TrimSpace(fmt.Sprint(settings["address"])) == "<nil>" {
			settings["address"] = "127.0.0.1"
			changed = true
		}
	}

	outbounds, _ := raw["outbounds"].([]interface{})
	if findObjectByTag(outbounds, "api") == nil {
		outbounds = append(outbounds, map[string]interface{}{"tag": "api", "protocol": "freedom", "settings": map[string]interface{}{}})
		raw["outbounds"] = outbounds
		changed = true
	}

	routing := asObject(raw["routing"])
	if routing == nil {
		routing = map[string]interface{}{}
		raw["routing"] = routing
		changed = true
	}
	rules, _ := routing["rules"].([]interface{})
	if !hasAPIRoutingRule(rules) {
		rules = append([]interface{}{map[string]interface{}{"type": "field", "inboundTag": []interface{}{"api"}, "outboundTag": "api"}}, rules...)
		routing["rules"] = rules
		changed = true
	}

	if ensureXrayClientEmails(raw) {
		changed = true
	}

	return changed, checkXrayStatsAPIConfig(raw)
}

func checkXrayStatsAPIConfig(raw map[string]interface{}) xrayStatsConfigCheck {
	missing := []string{}
	api := asObject(raw["api"])
	if api == nil {
		missing = append(missing, "api.services")
	} else {
		services, _ := api["services"].([]interface{})
		if !sliceHasString(services, "StatsService") {
			missing = append(missing, "api.services StatsService")
		}
	}
	if asObject(raw["stats"]) == nil {
		missing = append(missing, "stats")
	}
	policy := asObject(raw["policy"])
	levels := asObject(nil)
	level0 := asObject(nil)
	if policy != nil {
		levels = asObject(policy["levels"])
		if levels != nil {
			level0 = asObject(levels["0"])
		}
	}
	if level0 == nil {
		missing = append(missing, "policy.levels.0")
	} else {
		if v, _ := level0["statsUserUplink"].(bool); !v {
			missing = append(missing, "policy.levels.0.statsUserUplink")
		}
		if v, _ := level0["statsUserDownlink"].(bool); !v {
			missing = append(missing, "policy.levels.0.statsUserDownlink")
		}
	}

	inbounds, _ := raw["inbounds"].([]interface{})
	apiInbound := findObjectByTag(inbounds, "api")
	if apiInbound == nil {
		missing = append(missing, "api inbound")
	}
	outbounds, _ := raw["outbounds"].([]interface{})
	if findObjectByTag(outbounds, "api") == nil {
		missing = append(missing, "api outbound")
	}
	if n := countXrayClientEmailIssues(raw); n > 0 {
		missing = append(missing, fmt.Sprintf("%d client stats labels", n))
	}
	routing := asObject(raw["routing"])
	if routing == nil {
		missing = append(missing, "routing api rule")
	} else {
		rules, _ := routing["rules"].([]interface{})
		if !hasAPIRoutingRule(rules) {
			missing = append(missing, "routing api rule")
		}
	}
	return xrayStatsConfigCheck{Configured: len(missing) == 0, Missing: missing, APIServer: discoverAPIServerFromRaw(raw)}
}

func (m *XrayManager) discoverAPIServerFromRaw(raw map[string]interface{}) string {
	return discoverAPIServerFromRaw(raw)
}

func discoverAPIServerFromRaw(raw map[string]interface{}) string {
	inbounds, _ := raw["inbounds"].([]interface{})
	for _, item := range inbounds {
		ib, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		tag, _ := ib["tag"].(string)
		proto, _ := ib["protocol"].(string)
		if tag != "api" || !strings.EqualFold(proto, "dokodemo-door") {
			continue
		}
		host, _ := ib["listen"].(string)
		host = strings.TrimSpace(host)
		if host == "" || host == "0.0.0.0" || host == "::" {
			host = "127.0.0.1"
		}
		port := strings.TrimSpace(fmt.Sprint(ib["port"]))
		port = strings.Trim(port, `"`)
		if port == "" || port == "<nil>" || port == "null" {
			continue
		}
		return host + ":" + port
	}
	return ""
}

func countXrayClientEmailIssues(raw map[string]interface{}) int {
	inbounds, _ := raw["inbounds"].([]interface{})
	seen := map[string]int{}
	issues := 0
	for _, ib := range inbounds {
		ibMap, ok := ib.(map[string]interface{})
		if !ok {
			continue
		}
		proto, _ := ibMap["protocol"].(string)
		if !xrayClientProtos[strings.ToLower(proto)] {
			continue
		}
		settings, _ := ibMap["settings"].(map[string]interface{})
		if settings == nil {
			continue
		}
		clients, _ := settings["clients"].([]interface{})
		for _, item := range clients {
			cm, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			email := safeXrayStatsEmail(firstNonEmptyString(cm["email"]))
			if email == "" || seen[email] > 0 {
				issues++
			}
			if email != "" {
				seen[email]++
			}
		}
	}
	return issues
}

func ensureXrayClientEmails(raw map[string]interface{}) bool {
	changed := false
	inbounds, _ := raw["inbounds"].([]interface{})
	seen := map[string]int{}
	for _, ib := range inbounds {
		ibMap, ok := ib.(map[string]interface{})
		if !ok {
			continue
		}
		proto, _ := ibMap["protocol"].(string)
		if !xrayClientProtos[strings.ToLower(proto)] {
			continue
		}
		settings, _ := ibMap["settings"].(map[string]interface{})
		if settings == nil {
			continue
		}
		clients, _ := settings["clients"].([]interface{})
		for idx, item := range clients {
			cm, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			email := safeXrayStatsEmail(firstNonEmptyString(cm["email"]))
			if email == "" || seen[email] > 0 {
				base := firstNonEmptyString(cm["name"], cm["email"], cm["id"], cm["password"])
				if base == "" {
					base = fmt.Sprintf("client-%d", idx+1)
				}
				email = uniqueXrayEmail(base, seen)
				cm["email"] = email
				changed = true
			}
			if _, ok := cm["level"]; !ok {
				cm["level"] = float64(0)
				changed = true
			}
			seen[email]++
		}
	}
	return changed
}

func firstNonEmptyString(values ...interface{}) string {
	for _, v := range values {
		s := strings.TrimSpace(fmt.Sprint(v))
		if s != "" && s != "<nil>" {
			return s
		}
	}
	return ""
}

func uniqueXrayEmail(base string, seen map[string]int) string {
	email := safeXrayStatsEmail(base)
	if email == "" {
		email = "xray-client"
	}
	if len(email) > 40 {
		email = email[:40]
		email = strings.Trim(email, "-_.")
		if email == "" {
			email = "xray-client"
		}
	}
	candidate := email
	for i := 2; seen[candidate] > 0; i++ {
		candidate = fmt.Sprintf("%s-%d", email, i)
	}
	return candidate
}

func safeXrayStatsEmail(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "<nil>" {
		return ""
	}
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '@' || r == '.' || r == '_' || r == '-'
		if ok {
			b.WriteRune(r)
			lastDash = false
		} else if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-_.")
}

func asObject(v interface{}) map[string]interface{} {
	m, _ := v.(map[string]interface{})
	return m
}

func findObjectByTag(items []interface{}, tag string) map[string]interface{} {
	for _, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if t, _ := m["tag"].(string); t == tag {
			return m
		}
	}
	return nil
}

func sliceHasString(items []interface{}, want string) bool {
	for _, item := range items {
		if s, ok := item.(string); ok && strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

func hasAPIRoutingRule(rules []interface{}) bool {
	for _, item := range rules {
		rule, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		outbound, _ := rule["outboundTag"].(string)
		if outbound != "api" {
			continue
		}
		tags, ok := rule["inboundTag"].([]interface{})
		if !ok {
			if tag, _ := rule["inboundTag"].(string); tag == "api" {
				return true
			}
			continue
		}
		if sliceHasString(tags, "api") {
			return true
		}
	}
	return false
}

// ---- Admin HTTP handlers ----

func handleXrayStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if proxyManagedServerFromRequest(w, r, statsStore, "/api/xray/status", nil, "") {
		return
	}
	// Be practical for old/manual configs: if the panel detects missing Stats API
	// pieces or missing per-client stat labels, repair once automatically. This
	// avoids a dashboard that says "OK" but continues to show zero Xray online
	// users until a technical admin manually edits JSON.
	if !xrayMgr.useNativeMode() {
		if check, err := xrayMgr.CheckStatsAPIConfig(); err == nil && !check.Configured {
			wasRunning := xrayMgr.isRunningSnapshot()
			if changed, err := xrayMgr.EnsureStatsAPIConfig(); err == nil && changed && wasRunning {
				if err := xrayMgr.Restart(); err != nil {
					xrayLogf("xray: auto stats repair restart failed: %v", err)
				}
			}
		}
	}
	status := xrayMgr.Status()
	if sess := sessionFromCtx(r.Context()); sess != nil && sess.Role == RoleReseller && statsStore != nil {
		metas, err := statsStore.ListXrayClientsByOwner(r.Context(), sess.Username)
		if err == nil {
			status.OnlineUsers = 0
			window := xrayMgr.onlineWindow()
			now := time.Now()
			for _, m := range metas {
				online := m.ActiveConnections > 0 || (m.LastActive != nil && now.Sub(*m.LastActive) <= window)
				if st, ok := xrayMgr.RuntimeStatsForKeys(m.Email, m.UUID, m.Name); ok {
					online = online || st.ActiveConnections > 0 || (!st.LastActive.IsZero() && now.Sub(st.LastActive) <= window)
				}
				if online {
					status.OnlineUsers++
				}
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}

func handleXrayStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if proxyManagedServerFromRequest(w, r, statsStore, "/api/xray/start", nil, "") {
		return
	}
	if err := xrayMgr.Start(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func handleXrayStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if proxyManagedServerFromRequest(w, r, statsStore, "/api/xray/stop", nil, "") {
		return
	}
	if err := xrayMgr.Stop(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func handleXrayRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if proxyManagedServerFromRequest(w, r, statsStore, "/api/xray/restart", nil, "") {
		return
	}
	if err := xrayMgr.Restart(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func handleXrayConfig(w http.ResponseWriter, r *http.Request) {
	if requestedServerID(r) != "" && requestedServerID(r) != "local" && requestedServerID(r) != "0" {
		body := []byte(nil)
		if r.Method == http.MethodPost {
			var err error
			body, err = io.ReadAll(io.LimitReader(r.Body, 512*1024))
			if err != nil {
				http.Error(w, "failed to read body", http.StatusBadRequest)
				return
			}
		}
		if proxyManagedServerFromRequest(w, r, statsStore, "/api/xray/config", body, "") {
			return
		}
	}
	switch r.Method {
	case http.MethodGet:
		data, err := xrayMgr.GetConfig()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)

	case http.MethodPost:
		body, err := io.ReadAll(io.LimitReader(r.Body, 512*1024))
		if err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}
		if err := xrayMgr.SetConfig(body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func handleXrayRepairStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if proxyManagedServerFromRequest(w, r, statsStore, "/api/xray/stats/repair", nil, "") {
		return
	}
	wasRunning := xrayMgr.isRunningSnapshot()
	changed, err := xrayMgr.EnsureStatsAPIConfig()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	restarted := false
	if wasRunning {
		if err := xrayMgr.Restart(); err != nil {
			http.Error(w, "config repaired but restart failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		restarted = true
	}
	check, _ := xrayMgr.CheckStatsAPIConfig()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"changed":          changed,
		"restarted":        restarted,
		"stats_configured": check.Configured,
		"stats_missing":    check.Missing,
		"api_server":       check.APIServer,
	})
}

func handleXrayLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if proxyManagedServerFromRequest(w, r, statsStore, "/api/xray/logs", nil, "") {
		return
	}
	lines := xrayLogBuf.snapshot()
	if lines == nil {
		lines = []string{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"lines": lines})
}

// ---- Inbound / client management ----

// XrayClientInfo is a single client entry inside an Xray inbound.
type XrayClientInfo struct {
	UUID     string `json:"id"`
	Password string `json:"password,omitempty"`
	Email    string `json:"email"`
	Level    int    `json:"level,omitempty"`
	// Runtime counters from the Xray stats API. Online means this user's
	// traffic counters changed inside the configured online window.
	Online            bool       `json:"online"`
	LastActive        *time.Time `json:"last_active,omitempty"`
	UplinkBytes       int64      `json:"uplink_bytes,omitempty"`
	DownlinkBytes     int64      `json:"downlink_bytes,omitempty"`
	TotalBytes        int64      `json:"total_bytes,omitempty"`
	ActiveConnections int        `json:"active_connections,omitempty"`
	// Live speed in bytes per second for the whole client, summed across every
	// connection it has open.
	UpBytesPerSec   float64 `json:"up_bytes_per_sec"`
	DownBytesPerSec float64 `json:"down_bytes_per_sec"`
	// Metadata from PostgreSQL (enriched by handleXrayInbounds)
	Name              string     `json:"name,omitempty"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty"`
	ExpirationDays    int        `json:"expiration_days"`
	MaxConns          int        `json:"max_conns"`
	DataQuotaBytes    int64      `json:"data_quota_bytes"`
	QuotaAction       string     `json:"quota_action"`
	QuotaThrottleMbps int        `json:"quota_throttle_mbps"`
	QuotaExceeded     bool       `json:"quota_exceeded,omitempty"`
	OwnerUsername     string     `json:"owner_username,omitempty"`
	Expired           bool       `json:"expired,omitempty"`
}

// XrayInboundInfo is returned by /api/xray/inbounds.
type XrayInboundInfo struct {
	Tag        string           `json:"tag"`
	Protocol   string           `json:"protocol"`
	Port       json.RawMessage  `json:"port,omitempty"`
	Listen     string           `json:"listen,omitempty"`
	Network    string           `json:"network,omitempty"`
	Path       string           `json:"path,omitempty"`
	SharedPort bool             `json:"shared_port,omitempty"`
	Clients    []XrayClientInfo `json:"clients"`
}

// protocols that carry a "clients" array in their settings
var xrayClientProtos = map[string]bool{
	"vless": true, "vmess": true, "trojan": true,
}

// ListInbounds parses the config and returns only inbounds that support client lists.
func (m *XrayManager) ListInbounds() ([]XrayInboundInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, err := m.readConfigLocked()
	if err != nil {
		return nil, err
	}
	var cfg struct {
		Inbounds []json.RawMessage `json:"inbounds"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse xray config: %w", err)
	}
	var result []XrayInboundInfo
	for _, raw := range cfg.Inbounds {
		var ib struct {
			Tag            string          `json:"tag"`
			Protocol       string          `json:"protocol"`
			Port           json.RawMessage `json:"port"`
			Listen         string          `json:"listen"`
			SharedPort     bool            `json:"dragoncoreSharedPort"`
			StreamSettings struct {
				Network    string `json:"network"`
				WSSettings struct {
					Path string `json:"path"`
				} `json:"wsSettings"`
				XHTTPSettings struct {
					Path string `json:"path"`
				} `json:"xhttpSettings"`
				SplitHTTPSettings struct {
					Path string `json:"path"`
				} `json:"splithttpSettings"`
			} `json:"streamSettings"`
			Settings struct {
				Clients []XrayClientInfo `json:"clients"`
			} `json:"settings"`
		}
		if err := json.Unmarshal(raw, &ib); err != nil {
			continue
		}
		if !xrayClientProtos[strings.ToLower(ib.Protocol)] {
			continue
		}
		clients := ib.Settings.Clients
		if clients == nil {
			clients = []XrayClientInfo{}
		}
		for i := range clients {
			if clients[i].UUID == "" && clients[i].Password != "" {
				clients[i].UUID = clients[i].Password
			}
		}
		result = append(result, XrayInboundInfo{
			Tag:        ib.Tag,
			Protocol:   strings.ToLower(ib.Protocol),
			Port:       ib.Port,
			Listen:     ib.Listen,
			Network:    ib.StreamSettings.Network,
			Path:       firstNonEmpty(ib.StreamSettings.WSSettings.Path, ib.StreamSettings.XHTTPSettings.Path, ib.StreamSettings.SplitHTTPSettings.Path),
			SharedPort: ib.SharedPort,
			Clients:    clients,
		})
	}
	if result == nil {
		result = []XrayInboundInfo{}
	}
	return result, nil
}

// modifyRawConfig reads the config as a generic map, calls fn to mutate it, then writes it back.
// Caller must hold m.mu.
func (m *XrayManager) modifyRawConfig(fn func(cfg map[string]interface{}) error) error {
	data, err := m.readConfigLocked()
	if err != nil {
		return err
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parse xray config: %w", err)
	}
	if raw == nil {
		return fmt.Errorf("xray config must be a JSON object")
	}
	if err := fn(raw); err != nil {
		return err
	}
	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}
	return m.writeConfigLocked(out)
}

// AddXrayClient adds a client to the named inbound and saves the config.
func (m *XrayManager) AddXrayClient(inboundTag, uuid, email string) error {
	return m.addXrayClient(inboundTag, uuid, email, false)
}

// EnsureXrayClient restores a previously suspended DB-backed client without
// failing if it is already present in the active config.
func (m *XrayManager) EnsureXrayClient(inboundTag, uuid, email string) error {
	return m.addXrayClient(inboundTag, uuid, email, true)
}

func (m *XrayManager) addXrayClient(inboundTag, uuid, email string, allowExisting bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	err := m.modifyRawConfig(func(raw map[string]interface{}) error {
		_, _ = ensureXrayStatsAPIConfig(raw)
		inbounds, _ := raw["inbounds"].([]interface{})
		for _, ib := range inbounds {
			ibMap, ok := ib.(map[string]interface{})
			if !ok {
				continue
			}
			if tag, _ := ibMap["tag"].(string); tag != inboundTag {
				continue
			}
			settings, _ := ibMap["settings"].(map[string]interface{})
			if settings == nil {
				settings = make(map[string]interface{})
				ibMap["settings"] = settings
			}
			clients, _ := settings["clients"].([]interface{})
			for _, c := range clients {
				if cm, ok := c.(map[string]interface{}); ok {
					id, _ := cm["id"].(string)
					if id == "" {
						id, _ = cm["password"].(string)
					}
					if id == uuid {
						if allowExisting {
							cm["email"] = email
							return nil
						}
						return fmt.Errorf("UUID %s already exists in inbound %s", uuid, inboundTag)
					}
				}
			}
			proto, _ := ibMap["protocol"].(string)
			client := map[string]interface{}{
				"id": uuid, "email": email, "level": 0,
			}
			if strings.EqualFold(proto, "vmess") {
				client["alterId"] = 0
			}
			settings["clients"] = append(clients, client)
			return nil
		}
		return fmt.Errorf("inbound %q not found", inboundTag)
	})
	if err == nil && m.cfg != nil && m.cfg.UseNative() {
		if hotErr := nativeXray.addClient(inboundTag, uuid, email); hotErr != nil {
			xrayLogf("native xray: hot-add client %s to %s failed: %v", uuid, inboundTag, hotErr)
		}
	}
	return err
}

// RemoveXrayClient removes a client by UUID from the named inbound and saves the config.
func (m *XrayManager) RemoveXrayClient(inboundTag, uuid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	err := m.modifyRawConfig(func(raw map[string]interface{}) error {
		inbounds, _ := raw["inbounds"].([]interface{})
		for _, ib := range inbounds {
			ibMap, ok := ib.(map[string]interface{})
			if !ok {
				continue
			}
			if tag, _ := ibMap["tag"].(string); tag != inboundTag {
				continue
			}
			settings, _ := ibMap["settings"].(map[string]interface{})
			if settings == nil {
				return fmt.Errorf("inbound %s has no settings", inboundTag)
			}
			clients, _ := settings["clients"].([]interface{})
			var kept []interface{}
			removed := false
			for _, c := range clients {
				if cm, ok := c.(map[string]interface{}); ok {
					id, _ := cm["id"].(string)
					if id == "" {
						id, _ = cm["password"].(string)
					}
					if id == uuid {
						removed = true
						continue
					}
				}
				kept = append(kept, c)
			}
			if !removed {
				// DB-backed native users may exist only in xray_clients. The inbound
				// exists, so let the caller delete the database row too.
				return nil
			}
			settings["clients"] = kept
			return nil
		}
		return fmt.Errorf("inbound %q not found", inboundTag)
	})
	if err == nil && m.cfg != nil && m.cfg.UseNative() {
		if hotErr := nativeXray.removeClient(inboundTag, uuid); hotErr != nil {
			xrayLogf("native xray: hot-remove client %s from %s failed: %v", uuid, inboundTag, hotErr)
		}
	}
	return err
}

// UpdateXrayClientEmail updates the client's email/stats label inside the Xray JSON config.
// UUID remains immutable; metadata such as display name/expiry stays in PostgreSQL.
func (m *XrayManager) UpdateXrayClientEmail(uuid, email string) error {
	if strings.TrimSpace(uuid) == "" || strings.TrimSpace(email) == "" {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	err := m.modifyRawConfig(func(raw map[string]interface{}) error {
		changed := false
		inbounds, _ := raw["inbounds"].([]interface{})
		for _, ib := range inbounds {
			ibMap, ok := ib.(map[string]interface{})
			if !ok {
				continue
			}
			settings, _ := ibMap["settings"].(map[string]interface{})
			clients, _ := settings["clients"].([]interface{})
			for _, c := range clients {
				cm, ok := c.(map[string]interface{})
				if !ok {
					continue
				}
				id, _ := cm["id"].(string)
				if id == "" {
					id, _ = cm["password"].(string)
				}
				if id == uuid {
					cm["email"] = email
					changed = true
				}
			}
		}
		if !changed {
			return nil
		}
		return nil
	})
	if err == nil && m.cfg != nil && m.cfg.UseNative() {
		if hotErr := nativeXray.updateClientEmail(uuid, email); hotErr != nil {
			xrayLogf("native xray: hot-update client %s email failed: %v", uuid, hotErr)
		}
	}
	return err
}

// ---- HTTP handlers for inbound/client management ----

func handleXrayInbounds(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	filterOwner := ""
	if sess := sessionFromCtx(r.Context()); sess != nil && sess.Role == RoleReseller {
		filterOwner = sess.Username
	}
	if proxyManagedServerFromRequest(w, r, statsStore, "/api/xray/inbounds", nil, filterOwner) {
		return
	}
	inbounds, err := xrayMgr.ListInbounds()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sess := sessionFromCtx(r.Context())
	isReseller := sess != nil && sess.Role == RoleReseller

	// Enrich clients with metadata from PostgreSQL when available. Resellers only
	// see their own Xray clients, but they still see all available inbounds so
	// they know where they can create new users.
	if statsStore != nil {
		metas, err := statsStore.ListAllXrayClients(r.Context())
		if err != nil {
			if isReseller {
				for i := range inbounds {
					inbounds[i].Clients = []XrayClientInfo{}
				}
			} else {
				for i := range inbounds {
					for j := range inbounds[i].Clients {
						applyXrayRuntimeStats(&inbounds[i].Clients[j])
					}
				}
			}
		} else {
			metaMap := make(map[string]*XrayClientMeta, len(metas))
			metasByInbound := make(map[string][]*XrayClientMeta)
			for _, m := range metas {
				metaMap[m.UUID] = m
				metasByInbound[m.InboundTag] = append(metasByInbound[m.InboundTag], m)
			}
			now := time.Now()
			for i := range inbounds {
				seen := make(map[string]bool)
				filtered := make([]XrayClientInfo, 0, len(inbounds[i].Clients)+len(metasByInbound[inbounds[i].Tag]))
				appendMetaClient := func(m *XrayClientMeta) {
					if m == nil || m.UUID == "" || seen[m.UUID] {
						return
					}
					c := XrayClientInfo{
						UUID:              m.UUID,
						Email:             m.Email,
						Name:              m.Name,
						ExpiresAt:         m.ExpiresAt,
						MaxConns:          m.MaxConns,
						DataQuotaBytes:    m.DataQuotaBytes,
						QuotaAction:       normalizeQuotaAction(m.QuotaAction),
						QuotaThrottleMbps: quotaThrottleMbpsOrDefault(m.QuotaThrottleMbps),
						QuotaExceeded:     m.DataQuotaBytes > 0 && m.TotalUplinkBytes+m.TotalDownlinkBytes >= m.DataQuotaBytes,
						OwnerUsername:     m.OwnerUsername,
						UplinkBytes:       m.TotalUplinkBytes,
						DownlinkBytes:     m.TotalDownlinkBytes,
						TotalBytes:        m.TotalUplinkBytes + m.TotalDownlinkBytes,
						LastActive:        m.LastActive,
						ActiveConnections: m.ActiveConnections,
					}
					if c.Email == "" {
						c.Email = m.UUID
					}
					if c.ActiveConnections > 0 {
						c.Online = true
					} else if c.LastActive != nil && now.Sub(*c.LastActive) <= xrayMgr.onlineWindow() {
						c.Online = true
					}
					applyXrayRuntimeStats(&c)
					if m.ExpiresAt == nil {
						c.ExpirationDays = -1
					} else if m.ExpiresAt.Before(now) {
						c.Expired = true
						c.ExpirationDays = 0
					} else {
						c.ExpirationDays = int(m.ExpiresAt.Sub(now).Hours() / 24)
					}
					seen[m.UUID] = true
					filtered = append(filtered, c)
				}
				for j := range inbounds[i].Clients {
					c := inbounds[i].Clients[j]
					applyXrayRuntimeStats(&c)
					m, ok := metaMap[c.UUID]
					if isReseller && (!ok || m.OwnerUsername != sess.Username) {
						continue
					}
					if !ok {
						c.ExpirationDays = -1
						seen[c.UUID] = true
						filtered = append(filtered, c)
						continue
					}
					appendMetaClient(m)
				}
				for _, m := range metasByInbound[inbounds[i].Tag] {
					if isReseller && m.OwnerUsername != sess.Username {
						continue
					}
					appendMetaClient(m)
				}
				inbounds[i].Clients = filtered
			}
		}
	} else if isReseller {
		for i := range inbounds {
			inbounds[i].Clients = []XrayClientInfo{}
		}
	} else {
		for i := range inbounds {
			for j := range inbounds[i].Clients {
				applyXrayRuntimeStats(&inbounds[i].Clients[j])
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(inbounds)
}

func applyXrayRuntimeStats(c *XrayClientInfo) {
	if c == nil {
		return
	}
	if rate, ok := xrayMgr.RuntimeRateForKeys(c.Email, c.UUID, c.Name); ok {
		c.UpBytesPerSec = rate.UpBytesPerSec
		c.DownBytesPerSec = rate.DownBytesPerSec
	}
	st, ok := xrayMgr.RuntimeStatsForKeys(c.Email, c.UUID, c.Name)
	if !ok {
		return
	}
	window := xrayMgr.onlineWindow()
	now := time.Now()
	if st.Uplink > c.UplinkBytes {
		c.UplinkBytes = st.Uplink
	}
	if st.Downlink > c.DownlinkBytes {
		c.DownlinkBytes = st.Downlink
	}
	c.TotalBytes = c.UplinkBytes + c.DownlinkBytes
	c.QuotaExceeded = c.DataQuotaBytes > 0 && c.TotalBytes >= c.DataQuotaBytes
	if st.ActiveConnections > c.ActiveConnections {
		c.ActiveConnections = st.ActiveConnections
	}
	if !st.LastActive.IsZero() {
		t := st.LastActive
		c.LastActive = &t
	}
	c.Online = c.ActiveConnections > 0 || (c.LastActive != nil && now.Sub(*c.LastActive) <= window)
}

func handleXrayClientAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		InboundTag        string `json:"inbound_tag"`
		UUID              string `json:"uuid"`
		Email             string `json:"email"`
		Name              string `json:"name"`
		ExpiresAt         string `json:"expires_at"` // RFC3339 or YYYY-MM-DD or empty
		MaxConnections    int    `json:"max_connections"`
		DataQuotaBytes    int64  `json:"data_quota_bytes"`
		QuotaAction       string `json:"quota_action"`
		QuotaThrottleMbps int    `json:"quota_throttle_mbps"`
		OwnerUsername     string `json:"owner_username,omitempty"`
		ServerID          string `json:"server_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.InboundTag == "" || req.UUID == "" {
		http.Error(w, "inbound_tag and uuid required", http.StatusBadRequest)
		return
	}
	req.InboundTag = strings.TrimSpace(req.InboundTag)
	req.UUID = strings.TrimSpace(req.UUID)
	if _, err := parseUUID(req.UUID); err != nil {
		http.Error(w, "invalid uuid: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.MaxConnections < 0 || req.MaxConnections > 10000 {
		http.Error(w, "max_connections must be between 0 and 10000", http.StatusBadRequest)
		return
	}
	if err := validateQuotaConfig(req.DataQuotaBytes, req.QuotaAction, req.QuotaThrottleMbps); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if ms, remote, err := managedServerFromID(r.Context(), statsStore, req.ServerID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} else if remote {
		if !ms.EnableXray {
			http.Error(w, "Xray creation is disabled for this server", http.StatusForbidden)
			return
		}
		if sess := sessionFromCtx(r.Context()); sess != nil && sess.Role == RoleReseller {
			_, exists, ownerErr := remoteXrayClientOwner(r.Context(), ms, req.UUID)
			if ownerErr != nil {
				http.Error(w, "could not verify remote ownership", http.StatusBadGateway)
				return
			}
			if exists {
				http.Error(w, "UUID already exists", http.StatusConflict)
				return
			}
			owner, ok := adminUsers.get(sess.Username)
			used, quotaErr := countOwnedQuotaAcrossManagedServers(r.Context(), statsStore, sess.Username)
			if quotaErr != nil {
				http.Error(w, "could not verify reseller quota", http.StatusBadGateway)
				return
			}
			if ok && owner.MaxUsers > 0 && used >= owner.MaxUsers {
				http.Error(w, fmt.Sprintf("user limit reached (%d)", owner.MaxUsers), http.StatusForbidden)
				return
			}
			req.OwnerUsername = sess.Username
		}
		req.ServerID = ""
		body, _ := json.Marshal(req)
		status, data, ct, err := proxyManagedServer(r.Context(), ms, http.MethodPost, "/api/xray/clients/add", body, "application/json")
		if err != nil {
			http.Error(w, "remote server error: "+err.Error(), http.StatusBadGateway)
			return
		}
		writeProxyResponse(w, status, data, ct)
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" {
		req.Email = strings.TrimSpace(req.Name)
	}
	if req.Email == "" {
		req.Email = req.UUID
	}
	expiresAt, err := parseOptionalXrayExpiry(req.ExpiresAt)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	sess := sessionFromCtx(r.Context())
	ownerUsername := ""
	if sess != nil && sess.Role == RoleReseller {
		ownerUsername = sess.Username
		if statsStore == nil {
			http.Error(w, "storage not available", http.StatusInternalServerError)
			return
		}
		owner, ok := adminUsers.get(sess.Username)
		if !ok || !owner.IsActive || (owner.ExpiresAt != nil && time.Now().After(*owner.ExpiresAt)) {
			http.Error(w, "reseller account suspended or expired", http.StatusForbidden)
			return
		}
		used, quotaErr := countOwnedQuotaAcrossManagedServers(r.Context(), statsStore, sess.Username)
		if quotaErr != nil {
			http.Error(w, "could not verify reseller quota", http.StatusBadGateway)
			return
		}
		if owner.MaxUsers > 0 && used >= owner.MaxUsers {
			http.Error(w, fmt.Sprintf("user limit reached (%d)", owner.MaxUsers), http.StatusForbidden)
			return
		}
	} else if sess != nil && sess.Role == RoleSuperAdmin && strings.TrimSpace(req.OwnerUsername) != "" {
		ownerUsername = strings.TrimSpace(req.OwnerUsername)
	}

	if statsStore != nil {
		if _, err := statsStore.GetXrayClientMeta(r.Context(), req.UUID); err == nil {
			http.Error(w, "UUID already exists in database", http.StatusBadRequest)
			return
		} else if err != sql.ErrNoRows {
			http.Error(w, "database error: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	var savedMeta *XrayClientMeta
	if statsStore != nil {
		meta := XrayClientMeta{
			UUID:              req.UUID,
			Name:              req.Name,
			Email:             req.Email,
			InboundTag:        req.InboundTag,
			OwnerUsername:     ownerUsername,
			MaxConns:          req.MaxConnections,
			DataQuotaBytes:    req.DataQuotaBytes,
			QuotaAction:       normalizeQuotaAction(req.QuotaAction),
			QuotaThrottleMbps: quotaThrottleMbpsOrDefault(req.QuotaThrottleMbps),
		}
		meta.ExpiresAt = expiresAt
		if err := statsStore.UpsertXrayClientMeta(r.Context(), meta); err != nil {
			http.Error(w, "save client metadata failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		xrayMgr.setNativeQuotaPolicy(&meta)
		savedMeta = &meta
	}
	// Publish the credential only after its quota/owner/expiry policy exists, so
	// a fast native client can never enter an unmetered window during creation.
	if err := xrayMgr.AddXrayClient(req.InboundTag, req.UUID, req.Email); err != nil {
		if savedMeta != nil {
			_ = statsStore.DeleteXrayClientMeta(r.Context(), req.UUID)
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	xrayMgr.restartIfExternalRunning()
	w.WriteHeader(http.StatusCreated)
}

// handleXrayClientUpdate updates DB metadata and mirrors the email/stats label
// into the Xray JSON config when the client also exists there.
func handleXrayClientUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		UUID              string `json:"uuid"`
		Name              string `json:"name"`
		Email             string `json:"email"`
		ExpiresAt         string `json:"expires_at"`
		MaxConnections    int    `json:"max_connections"`
		DataQuotaBytes    int64  `json:"data_quota_bytes"`
		QuotaAction       string `json:"quota_action"`
		QuotaThrottleMbps int    `json:"quota_throttle_mbps"`
		ResetUsage        bool   `json:"reset_usage,omitempty"`
		ServerID          string `json:"server_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.UUID == "" {
		http.Error(w, "uuid required", http.StatusBadRequest)
		return
	}
	req.UUID = strings.TrimSpace(req.UUID)
	if _, err := parseUUID(req.UUID); err != nil {
		http.Error(w, "invalid uuid: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.MaxConnections < 0 || req.MaxConnections > 10000 {
		http.Error(w, "max_connections must be between 0 and 10000", http.StatusBadRequest)
		return
	}
	if err := validateQuotaConfig(req.DataQuotaBytes, req.QuotaAction, req.QuotaThrottleMbps); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if ms, remote, err := managedServerFromID(r.Context(), statsStore, req.ServerID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} else if remote {
		if sess := sessionFromCtx(r.Context()); sess != nil && sess.Role == RoleReseller && !remoteXrayClientOwned(r.Context(), ms, req.UUID, sess.Username) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		req.ServerID = ""
		body, _ := json.Marshal(req)
		status, data, ct, err := proxyManagedServer(r.Context(), ms, http.MethodPost, "/api/xray/clients/update", body, "application/json")
		if err != nil {
			http.Error(w, "remote server error: "+err.Error(), http.StatusBadGateway)
			return
		}
		writeProxyResponse(w, status, data, ct)
		return
	}
	if statsStore == nil {
		http.Error(w, "storage not available", http.StatusInternalServerError)
		return
	}

	existing, err := statsStore.GetXrayClientMeta(r.Context(), req.UUID)
	if err != nil {
		http.Error(w, "client metadata not found", http.StatusNotFound)
		return
	}
	sess := sessionFromCtx(r.Context())
	if sess != nil && sess.Role == RoleReseller && existing.OwnerUsername != sess.Username {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" {
		req.Email = firstNonEmpty(strings.TrimSpace(req.Name), existing.Email, req.UUID)
	}
	expiresAt, err := parseOptionalXrayExpiry(req.ExpiresAt)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	meta := XrayClientMeta{
		UUID:               req.UUID,
		Name:               req.Name,
		Email:              req.Email,
		InboundTag:         existing.InboundTag,
		OwnerUsername:      existing.OwnerUsername,
		MaxConns:           req.MaxConnections,
		DataQuotaBytes:     req.DataQuotaBytes,
		QuotaAction:        normalizeQuotaAction(req.QuotaAction),
		QuotaThrottleMbps:  quotaThrottleMbpsOrDefault(req.QuotaThrottleMbps),
		TotalUplinkBytes:   existing.TotalUplinkBytes,
		TotalDownlinkBytes: existing.TotalDownlinkBytes,
	}
	meta.ExpiresAt = expiresAt
	emailChanged := req.Email != existing.Email
	if emailChanged {
		if err := xrayMgr.UpdateXrayClientEmail(req.UUID, req.Email); err != nil {
			http.Error(w, "update config email failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if err := statsStore.UpsertXrayClientMeta(r.Context(), meta); err != nil {
		if emailChanged {
			_ = xrayMgr.UpdateXrayClientEmail(req.UUID, existing.Email)
		}
		http.Error(w, "update failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if req.ResetUsage {
		if err := xrayMgr.resetNativeTrafficAccounting(r.Context(), statsStore, req.UUID, existing.Email); err != nil {
			http.Error(w, "usage reset failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		meta.TotalUplinkBytes = 0
		meta.TotalDownlinkBytes = 0
	}
	xrayMgr.setNativeQuotaPolicy(&meta)
	if meta.ExpiresAt != nil && !meta.ExpiresAt.After(time.Now()) {
		xrayMgr.disconnectNativeClient(req.UUID)
	}
	if emailChanged {
		xrayMgr.restartIfExternalRunning()
	}
	w.WriteHeader(http.StatusOK)
}

func parseOptionalXrayExpiry(raw string) (*time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04", "2006-01-02"} {
		if t, err := time.Parse(layout, raw); err == nil {
			return &t, nil
		}
	}
	return nil, fmt.Errorf("invalid expires_at (RFC3339, YYYY-MM-DDThh:mm, or YYYY-MM-DD required)")
}

func handleXrayClientResetTraffic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		UUID     string `json:"uuid"`
		ServerID string `json:"server_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	req.UUID = strings.TrimSpace(req.UUID)
	if req.UUID == "" {
		http.Error(w, "uuid required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	if ms, remote, err := managedServerFromID(ctx, statsStore, req.ServerID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} else if remote {
		if sess := sessionFromCtx(ctx); sess != nil && sess.Role == RoleReseller && !remoteXrayClientOwned(ctx, ms, req.UUID, sess.Username) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		req.ServerID = ""
		body, _ := json.Marshal(req)
		status, data, ct, err := proxyManagedServer(ctx, ms, http.MethodPost, "/api/xray/clients/reset-traffic", body, "application/json")
		if err != nil {
			http.Error(w, "remote server error: "+err.Error(), http.StatusBadGateway)
			return
		}
		writeProxyResponse(w, status, data, ct)
		return
	}
	if statsStore == nil {
		http.Error(w, "storage not available", http.StatusInternalServerError)
		return
	}

	existing, err := statsStore.GetXrayClientMeta(ctx, req.UUID)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "client not found", http.StatusNotFound)
		} else {
			http.Error(w, "database error", http.StatusInternalServerError)
		}
		return
	}
	if sess := sessionFromCtx(ctx); sess != nil && sess.Role == RoleReseller && existing.OwnerUsername != sess.Username {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := xrayMgr.resetNativeTrafficAccounting(ctx, statsStore, req.UUID, existing.Email); err != nil {
		http.Error(w, "usage reset failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "uuid": req.UUID})
}

func handleXrayClientRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	inboundTag := r.URL.Query().Get("inbound_tag")
	uuid := r.URL.Query().Get("uuid")
	if inboundTag == "" || uuid == "" {
		http.Error(w, "inbound_tag and uuid required", http.StatusBadRequest)
		return
	}
	if ms, remote, err := managedServerFromID(r.Context(), statsStore, requestedServerID(r)); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} else if remote {
		if sess := sessionFromCtx(r.Context()); sess != nil && sess.Role == RoleReseller && !remoteXrayClientOwned(r.Context(), ms, uuid, sess.Username) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		remotePath := "/api/xray/clients/remove?inbound_tag=" + url.QueryEscape(inboundTag) + "&uuid=" + url.QueryEscape(uuid)
		status, data, ct, err := proxyManagedServer(r.Context(), ms, http.MethodDelete, remotePath, nil, "application/json")
		if err != nil {
			http.Error(w, "remote server error: "+err.Error(), http.StatusBadGateway)
			return
		}
		writeProxyResponse(w, status, data, ct)
		return
	}

	sess := sessionFromCtx(r.Context())
	if sess != nil && sess.Role == RoleReseller {
		if statsStore == nil {
			http.Error(w, "storage not available", http.StatusInternalServerError)
			return
		}
		meta, err := statsStore.GetXrayClientMeta(r.Context(), uuid)
		if err != nil || meta.OwnerUsername != sess.Username {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if meta.InboundTag != "" {
			inboundTag = meta.InboundTag
		}
	}

	if err := xrayMgr.RemoveXrayClient(inboundTag, uuid); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if statsStore != nil {
		_ = statsStore.DeleteXrayClientMeta(r.Context(), uuid)
	}
	xrayMgr.restartIfExternalRunning()
	w.WriteHeader(http.StatusNoContent)
}
