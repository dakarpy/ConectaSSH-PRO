package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// ---------- Global SSH config ----------

var (
	sshCfgMu      sync.RWMutex
	currentSSHCfg *ssh.ServerConfig
)

func setSSHConfig(c *ssh.ServerConfig) {
	sshCfgMu.Lock()
	currentSSHCfg = c
	sshCfgMu.Unlock()
}

func getSSHConfig() *ssh.ServerConfig {
	sshCfgMu.RLock()
	defer sshCfgMu.RUnlock()
	return currentSSHCfg
}

// ---------- Dynamic TCP listener pool ----------

// listenerPool manages a set of net.Listener instances by address.
// Calling Sync() opens new addresses and closes removed ones; unchanged
// addresses are left untouched so existing connections are not disrupted.
type listenerPool struct {
	mu      sync.Mutex
	entries map[string]net.Listener
	serve   func(net.Listener) // goroutine launched for each new listener
}

func newListenerPool(serve func(net.Listener)) *listenerPool {
	return &listenerPool{entries: make(map[string]net.Listener), serve: serve}
}

// Sync ensures exactly addrs are listening. Returns errors for addresses
// that could not be opened.
func (p *listenerPool) Sync(addrs []string) []error {
	p.mu.Lock()
	defer p.mu.Unlock()

	want := make(map[string]bool, len(addrs))
	for _, a := range addrs {
		if a != "" {
			want[a] = true
		}
	}

	for addr, ln := range p.entries {
		if !want[addr] {
			_ = ln.Close() // causes the serve goroutine to exit
			delete(p.entries, addr)
			log.Printf("hotreload: stopped %s", addr)
		}
	}

	var errs []error
	for addr := range want {
		if _, ok := p.entries[addr]; ok {
			continue
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			errs = append(errs, fmt.Errorf("listen %s: %w", addr, err))
			continue
		}
		p.entries[addr] = ln
		log.Printf("hotreload: listening on %s", addr)
		go p.serve(ln)
	}
	return errs
}

func (p *listenerPool) Has(addr string) bool {
	if p == nil || addr == "" {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.entries[addr]
	return ok
}

// StopAll closes every listener in the pool. Active SSH sessions are not owned
// by this pool; callers that want a hard restart should also close tracked SSH
// server connections through userMgr.DisconnectAll().
func (p *listenerPool) StopAll(reason string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for addr, ln := range p.entries {
		_ = ln.Close()
		delete(p.entries, addr)
		if reason != "" {
			log.Printf("hotreload: stopped %s (%s)", addr, reason)
		} else {
			log.Printf("hotreload: stopped %s", addr)
		}
	}
}

func (p *listenerPool) HasAll(addrs []string) bool {
	if p == nil {
		return false
	}
	for _, addr := range addrs {
		if addr == "" {
			continue
		}
		if !p.Has(addr) {
			return false
		}
	}
	return true
}

// ---------- Dynamic TLS listener pool ----------

type tlsListenerPool struct {
	mu      sync.Mutex
	entries map[string]net.Listener
}

func newTLSListenerPool() *tlsListenerPool {
	return &tlsListenerPool{entries: make(map[string]net.Listener)}
}

// Sync ensures exactly forwarders are listening (matched by listen address).
func (p *tlsListenerPool) Sync(forwarders []TLSForwarderConfig) []error {
	p.mu.Lock()
	defer p.mu.Unlock()

	want := make(map[string]TLSForwarderConfig, len(forwarders))
	for _, f := range forwarders {
		if f.Listen != "" {
			want[f.Listen] = f
		}
	}

	for addr, ln := range p.entries {
		if _, ok := want[addr]; !ok {
			_ = ln.Close()
			delete(p.entries, addr)
			log.Printf("hotreload: stopped TLS %s", addr)
		}
	}

	var errs []error
	for addr, fwd := range want {
		if _, ok := p.entries[addr]; ok {
			continue
		}
		cert, err := tls.LoadX509KeyPair(fwd.CertFile, fwd.KeyFile)
		if err != nil {
			errs = append(errs, fmt.Errorf("TLS cert/key %s: %w", addr, err))
			continue
		}
		ln, err := tls.Listen("tcp", addr, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"h2", "http/1.1"},
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("TLS listen %s: %w", addr, err))
			continue
		}
		p.entries[addr] = ln
		log.Printf("hotreload: TLS+SSH listening on %s", addr)
		go serveTLSSSH(ln)
	}
	return errs
}

func (p *tlsListenerPool) Has(addr string) bool {
	if p == nil || addr == "" {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.entries[addr]
	return ok
}

// Drop closes the listeners for the given addresses so a following Sync rebinds
// them. Used after a certificate is replaced on disk: tls.Listen captures the
// certificate when the listener is created, so the socket has to be recreated
// for new material to be served. Accepted connections are not owned by the pool
// and keep running.
func (p *tlsListenerPool) Drop(addrs []string, reason string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, addr := range addrs {
		entry, ok := p.entries[addr]
		if !ok {
			continue
		}
		_ = entry.Close()
		delete(p.entries, addr)
		if reason != "" {
			log.Printf("hotreload: dropped TLS %s (%s)", addr, reason)
		} else {
			log.Printf("hotreload: dropped TLS %s", addr)
		}
	}
}

func (p *tlsListenerPool) StopAll(reason string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for addr, ln := range p.entries {
		_ = ln.Close()
		delete(p.entries, addr)
		if reason != "" {
			log.Printf("hotreload: stopped TLS %s (%s)", addr, reason)
		} else {
			log.Printf("hotreload: stopped TLS %s", addr)
		}
	}
}

func (p *tlsListenerPool) HasAll(forwarders []TLSForwarderConfig) bool {
	if p == nil {
		return false
	}
	for _, f := range forwarders {
		if f.Listen == "" {
			continue
		}
		if !p.Has(f.Listen) {
			return false
		}
	}
	return true
}

// ---------- Global pool instances (initialised in main) ----------

var (
	publicPool *listenerPool    // HTTP+SSH: listen + extra_listen
	localPool  *listenerPool    // raw SSH: loopback-only local_ssh_listen
	tlsPool    *tlsListenerPool // TLS forwarders
)

// isListenerClosed reports whether err came from using a closed listener.
func isListenerClosed(err error) bool {
	return errors.Is(err, net.ErrClosed)
}

// ---------- Runtime settings ----------

var (
	defaultLimitsMu      sync.RWMutex
	runtimeLimitMbpsUp   int
	runtimeLimitMbpsDown int
)

func setDefaultLimits(up, down int) {
	defaultLimitsMu.Lock()
	runtimeLimitMbpsUp = up
	runtimeLimitMbpsDown = down
	defaultLimitsMu.Unlock()
}

func getDefaultLimits() (up, down int) {
	defaultLimitsMu.RLock()
	defer defaultLimitsMu.RUnlock()
	return runtimeLimitMbpsUp, runtimeLimitMbpsDown
}

// ---------- Full live reload ----------

// applyFullConfigReload applies every field in newCfg to the running server
// without a process restart. Port changes, DNSTT/UDPGW changes, Xray changes,
// and bandwidth defaults all take effect immediately.
// It returns a status report for the API and CLI.
type ServiceReloadStatus struct {
	Enabled bool   `json:"enabled"`
	Running bool   `json:"running"`
	Listen  string `json:"listen,omitempty"`
	Error   string `json:"error,omitempty"`
}

type ConfigReloadReport struct {
	Applied  bool                           `json:"applied"`
	Warnings []string                       `json:"warnings,omitempty"`
	Services map[string]ServiceReloadStatus `json:"services"`
}

func newReloadReport() ConfigReloadReport {
	return ConfigReloadReport{Applied: true, Services: map[string]ServiceReloadStatus{}}
}

func (r *ConfigReloadReport) warnf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	r.Warnings = append(r.Warnings, msg)
	log.Printf("config reload: %s", msg)
}

func joinAddrs(addrs []string) string {
	clean := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if a = strings.TrimSpace(a); a != "" {
			clean = append(clean, a)
		}
	}
	return strings.Join(clean, ", ")
}

func applyFullConfigReload(newCfg *Config) ConfigReloadReport {
	report := newReloadReport()
	stopProxyAutoRestart()
	// Banner
	bt := newCfg.Banner
	if bt == "" && newCfg.BannerFile != "" {
		if data, err := os.ReadFile(newCfg.BannerFile); err == nil {
			bt = string(data)
		}
	}
	setBannerEnabled(newCfg.BannerEnabled)
	setBannerText(bt)

	// Default per-connection bandwidth limits and SSH inactivity cleanup
	// (picked up by new connections).
	setDefaultLimits(newCfg.DefaultLimitMbpsUp, newCfg.DefaultLimitMbpsDown)
	setSSHIdleTimeoutFromConfig(newCfg.SSHIdleTimeout)
	setMaxTotalConnsFromConfig(newCfg.MaxTotalConnections)
	setPAMAuthEnabled(newCfg.PAMAuthEnabled)

	// Quiet logging / user count display
	if newCfg.Quiet {
		log.SetOutput(io.Discard)
	} else if !newCfg.UserCount {
		log.SetOutput(os.Stderr)
	}
	userCountEnabled = newCfg.UserCount

	// Internal raw SSH listener. Keep it separate from the public listener
	// pool so proxy auto-restarts never take the local integration endpoint
	// offline. normalizeRuntimePorts guarantees one loopback address here.
	localAddrs := []string{newCfg.LocalSSHListen}
	for _, e := range localPool.Sync(localAddrs) {
		report.warnf("internal SSH listener error: %v", e)
	}
	report.Services["local_ssh"] = ServiceReloadStatus{
		Enabled: true,
		Running: localPool.HasAll(localAddrs),
		Listen:  newCfg.LocalSSHListen,
	}
	if !report.Services["local_ssh"].Running {
		report.Services["local_ssh"] = ServiceReloadStatus{Enabled: true, Running: false, Listen: newCfg.LocalSSHListen, Error: "internal SSH listener could not be opened"}
	}

	// Public SSH listeners (main listen + extra_listen)
	publicAddrs := append([]string{newCfg.Listen}, newCfg.ExtraListen...)
	for _, e := range publicPool.Sync(publicAddrs) {
		report.warnf("SSH listener error: %v", e)
	}
	report.Services["ssh"] = ServiceReloadStatus{
		Enabled: true,
		Running: publicPool.HasAll(publicAddrs),
		Listen:  joinAddrs(publicAddrs),
	}
	if !report.Services["ssh"].Running {
		report.Services["ssh"] = ServiceReloadStatus{Enabled: true, Running: false, Listen: joinAddrs(publicAddrs), Error: "one or more SSH listeners could not be opened"}
	}

	// TLS forwarders
	for _, e := range tlsPool.Sync(newCfg.TLSForwarders) {
		report.warnf("TLS listener error: %v", e)
	}
	if len(newCfg.TLSForwarders) > 0 {
		report.Services["tls"] = ServiceReloadStatus{
			Enabled: true,
			Running: tlsPool.HasAll(newCfg.TLSForwarders),
			Listen:  tlsForwarderList(newCfg.TLSForwarders),
		}
		if !report.Services["tls"].Running {
			report.Services["tls"] = ServiceReloadStatus{Enabled: true, Running: false, Listen: tlsForwarderList(newCfg.TLSForwarders), Error: "one or more TLS forwarders could not be opened"}
		}
	} else {
		report.Services["tls"] = ServiceReloadStatus{Enabled: false, Running: false}
	}

	// DNSTT — stop current instance (no-op if not running) then start new one.
	stopDNSTT()
	if newCfg.DNSTT != nil {
		if err := startDNSTT(newCfg.DNSTT, getSSHConfig()); err != nil {
			report.warnf("DNSTT failed to start: %v", err)
			report.Services["dnstt"] = ServiceReloadStatus{Enabled: true, Running: false, Listen: newCfg.DNSTT.UDPListen, Error: err.Error()}
		} else {
			report.Services["dnstt"] = ServiceReloadStatus{Enabled: true, Running: true, Listen: newCfg.DNSTT.UDPListen}
		}
	} else {
		report.Services["dnstt"] = ServiceReloadStatus{Enabled: false, Running: false}
	}

	// UDPGW — same pattern.
	stopUDPGW()
	if newCfg.UDPGW != nil {
		if err := startUDPGW(newCfg.UDPGW); err != nil {
			report.warnf("UDPGW failed to start: %v", err)
			report.Services["udpgw"] = ServiceReloadStatus{Enabled: true, Running: false, Listen: newCfg.UDPGW.Listen, Error: err.Error()}
		} else {
			report.Services["udpgw"] = ServiceReloadStatus{Enabled: true, Running: udpgwRunning(), Listen: newCfg.UDPGW.Listen}
		}
	} else {
		report.Services["udpgw"] = ServiceReloadStatus{Enabled: false, Running: false}
	}

	// BHTTP — stop current instance (no-op if not running) then start new one.
	stopBHTTP()
	if newCfg.BHTTP != nil {
		if err := startBHTTP(newCfg.BHTTP); err != nil {
			report.warnf("BHTTP failed to start: %v", err)
			report.Services["bhttp"] = ServiceReloadStatus{Enabled: true, Running: false, Listen: joinAddrs(newCfg.BHTTP.Listen), Error: err.Error()}
		} else {
			report.Services["bhttp"] = ServiceReloadStatus{Enabled: true, Running: bhttpRunning(), Listen: bhttpListenList()}
		}
	} else {
		report.Services["bhttp"] = ServiceReloadStatus{Enabled: false, Running: false}
	}

	// BTUN — same pattern. A failure here is usually a missing /dev/net/tun or
	// an interface name already taken, both of which the panel surfaces.
	stopBTUN()
	if newCfg.BTUN != nil {
		if err := startBTUN(newCfg.BTUN); err != nil {
			report.warnf("BTUN failed to start: %v", err)
			report.Services["btun"] = ServiceReloadStatus{Enabled: true, Running: false, Listen: btunConfiguredListen(newCfg.BTUN), Error: err.Error()}
		} else {
			report.Services["btun"] = ServiceReloadStatus{Enabled: true, Running: btunRunning(), Listen: btunListenList()}
		}
	} else {
		report.Services["btun"] = ServiceReloadStatus{Enabled: false, Running: false}
	}

	// HCR — stop current instance (no-op if not running) then start new one.
	stopHCR()
	if newCfg.HCR != nil {
		if err := startHCR(newCfg.HCR); err != nil {
			report.warnf("HCR failed to start: %v", err)
			report.Services["hcr"] = ServiceReloadStatus{Enabled: true, Running: false, Listen: hcrConfiguredListen(newCfg.HCR), Error: err.Error()}
		} else {
			report.Services["hcr"] = ServiceReloadStatus{Enabled: true, Running: hcrRunning(), Listen: hcrListenList()}
		}
	} else {
		report.Services["hcr"] = ServiceReloadStatus{Enabled: false, Running: false}
	}

	// Xray — update stored config then restart/stop as needed.
	if newCfg.Xray != nil {
		newCfg.Xray.NormalizeDefaults()
		xrayMgr.mu.Lock()
		xrayMgr.cfg = newCfg.Xray
		xrayMgr.mu.Unlock()
		if !newCfg.Xray.UseNative() {
			xrayMgr.startStatsPoller()
		}
		if newCfg.Xray.Enabled {
			if err := xrayMgr.Restart(); err != nil {
				report.warnf("Xray failed to restart: %v", err)
			}
			time.Sleep(500 * time.Millisecond)
			st := xrayMgr.Status()
			report.Services["xray"] = ServiceReloadStatus{Enabled: true, Running: st.Running, Error: st.Error}
			if !st.Running && st.Error == "" {
				report.Services["xray"] = ServiceReloadStatus{Enabled: true, Running: false, Error: "xray exited immediately; check logs"}
			}
		} else {
			_ = xrayMgr.Stop()
			report.Services["xray"] = ServiceReloadStatus{Enabled: false, Running: false}
		}
	} else {
		_ = xrayMgr.Stop()
		report.Services["xray"] = ServiceReloadStatus{Enabled: false, Running: false}
	}

	setGlobalCfg(newCfg)
	startProxyAutoRestart(newCfg)
	return report
}

func tlsForwarderList(forwarders []TLSForwarderConfig) string {
	addrs := make([]string, 0, len(forwarders))
	for _, f := range forwarders {
		if strings.TrimSpace(f.Listen) != "" {
			addrs = append(addrs, strings.TrimSpace(f.Listen))
		}
	}
	return strings.Join(addrs, ", ")
}
