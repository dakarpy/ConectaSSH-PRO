package main

// This file embeds the BTUN protocol server into the panel. BTUN is the native
// DTunnel VPN transport: a client speaks a "DTUNNEL/1.1 CLIENT_HELLO" handshake
// over TCP or UDP, authenticates, is handed an IPv4 address from a private
// subnet, and then exchanges raw IPv4 packets with a TUN interface owned by
// this process.
//
// Unlike BHTTP or DNSTT, BTUN is not an SSH carrier — it moves IP packets, not
// an SSH stream. Authentication therefore cannot be delegated to handleConn, so
// it is delegated to the panel's own account database instead: the same
// username/password (or TOTP), the same expiry, reseller-owner, data-quota and
// max_connections rules that passwordCallback enforces for SSH. PAM,
// /etc/shadow and password files are deliberately unreachable from this path;
// a BTUN login is a panel login and nothing else.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/dakarpy/ConectaSSH-PRO/internal/btun"
)

// BTUNConfig defines the settings for the integrated BTUN server. A nil
// *BTUNConfig in the main config disables it entirely.
type BTUNConfig struct {
	// TCPListen is the TCP address for BTUN clients. Empty disables the TCP
	// transport. IPv6 addresses must use bracket form, e.g. "[::]:7300".
	TCPListen string `json:"tcp_listen"`

	// UDPListen is the UDP address for BTUN clients. Empty disables the UDP
	// transport. At least one of TCPListen/UDPListen must be set.
	UDPListen string `json:"udp_listen"`

	// SharedPorts also accepts BTUN on the ports the panel already owns: the
	// HTTP+SSH proxy listeners (listen and extra_listen, normally 80 and 8080)
	// and every TLS forwarder (normally 443). Those listeners read the first
	// bytes of each connection and hand it here only on the fixed
	// "DTUNNEL/1.1 CLIENT_HELLO" marker, so SSH and HTTP-injection clients on
	// the same port are unaffected.
	//
	// This covers the TCP transport only: the panel owns no shared UDP port, so
	// UDP clients still need UDPListen. A TCP client that prepends cover bytes
	// is matched when that cover is an HTTP request (the panel's own HTTP
	// cleanup consumes it first); other cover shapes need TCPListen, because a
	// shared port cannot buffer an unbounded prefix while SSH waits behind it.
	SharedPorts bool `json:"shared_ports,omitempty"`

	// TUNName is the TUN interface this server creates and owns. Default
	// "btun0". It must not collide with an interface another service owns.
	TUNName string `json:"tun_name,omitempty"`

	// Subnet is the private IPv4 range handed out to clients, in CIDR form.
	// Default "10.77.0.0/16". It must have room for at least four addresses.
	Subnet string `json:"subnet,omitempty"`

	// Gateway is the address configured on the TUN interface itself, in CIDR
	// form, and is the first usable address of Subnet by convention. Empty
	// derives it from Subnet (for 10.77.0.0/16 that is 10.77.0.1/16).
	Gateway string `json:"gateway,omitempty"`

	// MTU is set on the TUN interface. Default 1400, which leaves headroom for
	// the BTUN framing plus an outer TCP/UDP header on a 1500-byte path.
	MTU int `json:"mtu,omitempty"`

	// ManageRouting lets the panel configure the interface address, MTU,
	// net.ipv4.ip_forward and the NAT/forward rules for Subnet itself. Turn it
	// off only when an external script (or an existing btun-routing unit)
	// already owns those rules.
	ManageRouting bool `json:"manage_routing,omitempty"`

	// WANInterface is the uplink used for NAT. Empty auto-detects it from the
	// default IPv4 route, which is correct on a single-uplink VPS.
	WANInterface string `json:"wan_interface,omitempty"`

	// HandshakeTimeout bounds the hello + authentication exchange. Empty
	// defaults to "15s".
	HandshakeTimeout string `json:"handshake_timeout,omitempty"`

	// IdleTimeout drops a session that sends nothing for this long. Empty
	// defaults to "2m". Clients send keep-alives, so this only reaps dead peers.
	IdleTimeout string `json:"idle_timeout,omitempty"`

	// MaxPacketSize limits a single BTUN frame payload in bytes. Zero uses the
	// protocol default (64 KiB); the hard ceiling is 4 MiB.
	MaxPacketSize int `json:"max_packet_size,omitempty"`

	// MaxCoverBytes is how much junk a TCP client may send before its
	// CLIENT_HELLO, which is what lets BTUN hide behind an HTTP-looking
	// preamble. Zero uses the default (64 KiB).
	MaxCoverBytes int `json:"max_cover_bytes,omitempty"`

	// MaxSessions caps concurrent BTUN sessions across both transports. Zero
	// uses a safe default; negative disables the cap. Per-account limits still
	// come from each user's max_connections.
	MaxSessions int `json:"max_sessions,omitempty"`

	// DisableConsoleLog keeps BTUN log lines out of stderr. They are still
	// captured in memory and served by /api/btun/logs for the panel.
	DisableConsoleLog bool `json:"disable_console_log,omitempty"`

	// LogConnections enables one log line per session start/stop.
	LogConnections bool `json:"log_connections,omitempty"`

	// AutoRestartInterval controls a watchdog that periodically hard-restarts
	// only the BTUN listeners and TUN device. Empty, "0s", "off" or "disabled"
	// turns it off. Minimum accepted value is 1m.
	AutoRestartInterval string `json:"auto_restart_interval,omitempty"`

	// AutoRestartGrace is the delay between tearing the old instance down and
	// bringing a new one up during an auto restart. Empty defaults to "2s".
	AutoRestartGrace string `json:"auto_restart_grace,omitempty"`
}

const (
	defaultBTUNTCPListen        = "0.0.0.0:7301"
	defaultBTUNUDPListen        = "0.0.0.0:7302"
	defaultBTUNName             = "btun0"
	defaultBTUNSubnet           = "10.77.0.0/16"
	defaultBTUNMTU              = 1400
	defaultBTUNHandshakeTimeout = 15 * time.Second
	defaultBTUNIdleTimeout      = 2 * time.Minute
	defaultBTUNMaxSessions      = 10000
	btunMaxPacketCeiling        = 4 * 1024 * 1024
	btunRouteCommandTimeout     = 10 * time.Second
)

var (
	btunMu        sync.Mutex
	btunServer    *btun.Server
	btunDevice    btun.PacketDevice
	btunTCP       net.Listener
	btunUDP       net.PacketConn
	btunListenTCP string
	btunListenUDP string
	// btunSharedPorts mirrors BTUNConfig.SharedPorts for the running instance,
	// so the proxy and TLS listeners can check it without reading the whole
	// config on every connection.
	btunSharedPorts bool
	// btunRoutingApplied records the settings used to add routing rules, so the
	// exact same rules can be removed on shutdown even after the config changed.
	btunRoutingApplied *btunRoutingSpec

	btunAutoMu     sync.Mutex
	btunAutoCancel context.CancelFunc

	btunLog    = log.New(os.Stderr, "btun: ", log.LstdFlags|log.Lmicroseconds)
	btunLogBuf *ringLogBuffer

	// btunSessionsMu guards the per-account session registry used for
	// max_connections and for forced disconnects from the panel.
	btunSessionsMu sync.Mutex
	btunSessions   = make(map[string]map[*btunLedger]struct{})
)

func getBTUNLogLines() []string { return btunLogBuf.GetLines() }

// ---------- Panel-backed authentication ----------

// btunPanelAuthenticator verifies a BTUN credential against the panel's own
// account database. It is intentionally the only authenticator wired into the
// BTUN server: there is no PAM, /etc/shadow or password-file path here, and
// pam_auth_enabled does not apply to BTUN.
type btunPanelAuthenticator struct{}

func (btunPanelAuthenticator) Name() string { return "panel" }

func (btunPanelAuthenticator) Authenticate(username, password string) error {
	// Mirrors passwordCallback's panel-credential branch. Kept as a separate
	// implementation because passwordCallback is bound to ssh.ConnMetadata and
	// also owns the (unrelated) system-login path.
	u, ok := userMgr.Get(username)
	if !ok {
		return errors.New("invalid username or password")
	}
	now := time.Now()
	if u.ExpiresAt != nil && now.After(*u.ExpiresAt) {
		return errors.New("account expired")
	}
	if sshUserQuotaBlocked(u) {
		return errDataQuotaExceeded
	}
	if err := ownerIsActive(u.Cfg.OwnerUsername); err != nil {
		return errors.New("invalid username or password")
	}
	u.mu.Lock()
	cfg := u.Cfg
	u.mu.Unlock()
	if strings.TrimSpace(cfg.TOTPSecret) != "" {
		if matchTOTPPassword(u, password, now) {
			return nil
		}
		if cfg.AllowStaticPassword && cfg.Password == password {
			return nil
		}
		return errors.New("invalid username or password")
	}
	if cfg.Password != password {
		return errors.New("invalid username or password")
	}
	return nil
}

// ---------- Panel-backed accounting ----------

// btunPanelAccountant admits authenticated BTUN sessions and meters their
// traffic against the same per-user counters the SSH path uses, so a user's
// bandwidth limits, data quota and connection count cover both transports.
type btunPanelAccountant struct{}

func (btunPanelAccountant) Admit(username, remote string, closer io.Closer) (btun.Ledger, error) {
	u, ok := userMgr.Get(username)
	if !ok {
		return nil, errors.New("account not found")
	}
	u.mu.Lock()
	cfg := u.Cfg
	// max_connections is shared with SSH: BTUN sessions and SSH connections
	// count against the same allowance, so a user cannot double their limit by
	// mixing transports.
	active := len(u.conns) + u.btunConns
	if cfg.MaxConnections > 0 && active >= cfg.MaxConnections {
		u.mu.Unlock()
		return nil, fmt.Errorf("connection limit reached (%d)", cfg.MaxConnections)
	}
	u.btunConns++
	u.ActiveConns = len(u.conns) + u.btunConns
	u.mu.Unlock()

	limitUp, limitDown := cfg.LimitMbpsUp, cfg.LimitMbpsDown
	if limitUp == 0 || limitDown == 0 {
		defUp, defDown := getDefaultLimits()
		if limitUp == 0 {
			limitUp = defUp
		}
		if limitDown == 0 {
			limitDown = defDown
		}
	}
	ledger := &btunLedger{
		user:     u,
		username: username,
		remote:   remote,
		closer:   closer,
		up:       btunRateLimiter(limitUp),
		down:     btunRateLimiter(limitDown),
	}

	btunSessionsMu.Lock()
	if btunSessions[username] == nil {
		btunSessions[username] = make(map[*btunLedger]struct{})
	}
	btunSessions[username][ledger] = struct{}{}
	btunSessionsMu.Unlock()

	updateUserDisplay()
	return ledger, nil
}

// btunRateLimiter builds a per-session limiter for an Mbps value. The burst is
// never smaller than one maximum-size IP packet, otherwise WaitN would reject
// a legitimate packet outright instead of pacing it.
func btunRateLimiter(mbps int) *rate.Limiter {
	if mbps <= 0 {
		return nil
	}
	bps := mbpsToBytesPerSec(mbps)
	burst := int(bps)
	if burst < 64*1024 {
		burst = 64 * 1024
	}
	return rate.NewLimiter(rate.Limit(bps), burst)
}

// btunLedger meters one BTUN session against its panel account.
type btunLedger struct {
	user     *UserState
	username string
	remote   string
	closer   io.Closer
	up       *rate.Limiter
	down     *rate.Limiter
	once     sync.Once
}

func (l *btunLedger) Uplink(ctx context.Context, n int) error {
	return l.meter(ctx, true, l.up, n)
}

func (l *btunLedger) Downlink(ctx context.Context, n int) error {
	return l.meter(ctx, false, l.down, n)
}

// meter reserves quota for one IP packet, paces it, and commits the bytes.
// BTUN forwards whole packets, so a partial quota allowance cannot be honoured:
// the reservation is released and the session ends instead of sending a
// truncated packet.
func (l *btunLedger) meter(ctx context.Context, uplink bool, limiter *rate.Limiter, n int) error {
	if l.user == nil || n <= 0 {
		return nil
	}
	// Held for the same reason sshQuotaWriter holds it: a traffic reset must not
	// interleave with a reservation.
	l.user.trafficMu.RLock()
	defer l.user.trafficMu.RUnlock()

	allowed, quotaLimiter, stopAfter := reserveSSHUserBytes(l.user, n)
	if allowed <= 0 {
		return errDataQuotaExceeded
	}
	if allowed < n {
		finishSSHUserReservation(l.user, uplink, allowed, 0)
		return errDataQuotaExceeded
	}
	if limiter != nil {
		if err := limiter.WaitN(ctx, n); err != nil {
			finishSSHUserReservation(l.user, uplink, allowed, 0)
			return err
		}
	}
	if quotaLimiter != nil {
		if err := quotaLimiter.WaitN(ctx, allowed); err != nil {
			finishSSHUserReservation(l.user, uplink, allowed, 0)
			return err
		}
	}
	finishSSHUserReservation(l.user, uplink, allowed, allowed)
	if stopAfter {
		return errDataQuotaExceeded
	}
	return nil
}

func (l *btunLedger) Close() {
	l.once.Do(func() {
		btunSessionsMu.Lock()
		if set := btunSessions[l.username]; set != nil {
			delete(set, l)
			if len(set) == 0 {
				delete(btunSessions, l.username)
			}
		}
		btunSessionsMu.Unlock()

		if l.user != nil {
			l.user.mu.Lock()
			if l.user.btunConns > 0 {
				l.user.btunConns--
			}
			l.user.ActiveConns = len(l.user.conns) + l.user.btunConns
			l.user.mu.Unlock()
		}
		updateUserDisplay()
	})
}

// btunDisconnectUser closes every BTUN session belonging to username. It is
// called from UserManager.DisconnectUser so panel actions (delete, edit,
// expire) drop BTUN sessions the same way they drop SSH connections.
func btunDisconnectUser(username string) int {
	btunSessionsMu.Lock()
	ledgers := make([]*btunLedger, 0, len(btunSessions[username]))
	for ledger := range btunSessions[username] {
		ledgers = append(ledgers, ledger)
	}
	btunSessionsMu.Unlock()
	for _, ledger := range ledgers {
		if ledger.closer != nil {
			_ = ledger.closer.Close()
		}
	}
	return len(ledgers)
}

// btunDisconnectAll closes every tracked BTUN session.
func btunDisconnectAll() int {
	btunSessionsMu.Lock()
	ledgers := make([]*btunLedger, 0, len(btunSessions))
	for _, set := range btunSessions {
		for ledger := range set {
			ledgers = append(ledgers, ledger)
		}
	}
	btunSessionsMu.Unlock()
	for _, ledger := range ledgers {
		if ledger.closer != nil {
			_ = ledger.closer.Close()
		}
	}
	return len(ledgers)
}

// ---------- Lifecycle ----------

// stopBTUN tears down the BTUN listeners, TUN device, routing rules and the
// optional auto-restart watchdog. It is a no-op if BTUN is not running.
func stopBTUN() {
	stopBTUNAutoRestart()
	stopBTUNInstance()
}

// stopBTUNInstance closes only the running instance. The auto-restart watchdog
// uses this so it can cycle BTUN without disabling itself.
func stopBTUNInstance() {
	btunMu.Lock()
	server := btunServer
	device := btunDevice
	tcpListener := btunTCP
	udpConn := btunUDP
	routing := btunRoutingApplied
	btunServer = nil
	btunDevice = nil
	btunTCP = nil
	btunUDP = nil
	btunListenTCP = ""
	btunListenUDP = ""
	btunSharedPorts = false
	btunRoutingApplied = nil
	btunMu.Unlock()

	if tcpListener != nil {
		_ = tcpListener.Close()
	}
	if udpConn != nil {
		_ = udpConn.Close()
	}
	if server != nil {
		// Server.Close also closes the TUN device it was given.
		if err := server.Close(); err != nil {
			btunLog.Printf("shutdown: %v", err)
		}
		server.Wait()
	} else if device != nil {
		_ = device.Close()
	}
	if routing != nil {
		removeBTUNRouting(*routing)
	}
}

func stopBTUNAutoRestart() {
	btunAutoMu.Lock()
	defer btunAutoMu.Unlock()
	if btunAutoCancel != nil {
		btunAutoCancel()
		btunAutoCancel = nil
	}
}

func btunRunning() bool {
	btunMu.Lock()
	defer btunMu.Unlock()
	return btunServer != nil
}

// btunListenList reports the addresses currently bound, for the panel.
func btunListenList() string {
	btunMu.Lock()
	defer btunMu.Unlock()
	parts := make([]string, 0, 3)
	if btunListenTCP != "" {
		parts = append(parts, "tcp "+btunListenTCP)
	}
	if btunListenUDP != "" {
		parts = append(parts, "udp "+btunListenUDP)
	}
	if btunSharedPorts {
		parts = append(parts, "shared proxy/TLS ports")
	}
	return strings.Join(parts, ", ")
}

// btunShareEnabled reports whether a running BTUN server wants the shared proxy
// and TLS ports.
func btunShareEnabled() bool {
	btunMu.Lock()
	defer btunMu.Unlock()
	return btunServer != nil && btunSharedPorts
}

// btunConfiguredListen describes the addresses a config asks for, used in
// status reports when the server failed to bind them.
func btunConfiguredListen(cfg *BTUNConfig) string {
	if cfg == nil {
		return ""
	}
	parts := make([]string, 0, 3)
	if addr := strings.TrimSpace(cfg.TCPListen); addr != "" {
		parts = append(parts, "tcp "+addr)
	}
	if addr := strings.TrimSpace(cfg.UDPListen); addr != "" {
		parts = append(parts, "udp "+addr)
	}
	if cfg.SharedPorts {
		parts = append(parts, "shared proxy/TLS ports")
	}
	return strings.Join(parts, ", ")
}

func btunEnabledInCurrentConfig() bool {
	globalCfgMu.RLock()
	defer globalCfgMu.RUnlock()
	return globalCfg != nil && globalCfg.BTUN != nil
}

// startBTUN starts the integrated BTUN server if cfg is non-nil. Startup errors
// are returned so the admin panel can report them, but they never crash the
// panel.
func startBTUN(cfg *BTUNConfig) error {
	if cfg == nil {
		return nil
	}
	stopBTUNAutoRestart()
	if err := startBTUNInstance(cfg); err != nil {
		return err
	}
	startBTUNAutoRestart(cfg)
	return nil
}

func startBTUNInstance(cfg *BTUNConfig) error {
	if cfg == nil {
		return nil
	}
	if btunLogBuf == nil {
		btunLogBuf = newRingLogBuffer(200)
	}
	if cfg.DisableConsoleLog {
		btunLog.SetOutput(btunLogBuf)
	} else {
		btunLog.SetOutput(io.MultiWriter(btunLogBuf, os.Stderr))
	}

	normalizeBTUNConfig(cfg)
	if cfg.TCPListen == "" && cfg.UDPListen == "" && !cfg.SharedPorts {
		msg := errors.New("btun: needs tcp_listen, udp_listen or shared_ports")
		btunLog.Print(msg.Error())
		return msg
	}

	// Release the previous instance first: the TUN interface name and the
	// listen addresses cannot be held twice.
	stopBTUNInstance()

	device, err := btun.OpenTUN(cfg.TUNName)
	if err != nil {
		msg := fmt.Errorf("btun: open TUN %s: %w", cfg.TUNName, err)
		btunLog.Print(msg.Error())
		return msg
	}

	maxSessions := cfg.MaxSessions
	if maxSessions == 0 {
		maxSessions = defaultBTUNMaxSessions
	} else if maxSessions < 0 {
		maxSessions = 0 // unlimited
	}

	server, err := btun.NewServer(btun.Config{
		Subnet:           cfg.Subnet,
		Authenticator:    btunPanelAuthenticator{},
		Accountant:       btunPanelAccountant{},
		Logger:           btunLog,
		HandshakeTimeout: btunDurationOrDefault(cfg.HandshakeTimeout, defaultBTUNHandshakeTimeout, "handshake_timeout"),
		IdleTimeout:      btunDurationOrDefault(cfg.IdleTimeout, defaultBTUNIdleTimeout, "idle_timeout"),
		MaxPacketSize:    cfg.MaxPacketSize,
		MaxCoverBytes:    cfg.MaxCoverBytes,
		MaxSessions:      maxSessions,
		LogConnections:   cfg.LogConnections,
	}, device)
	if err != nil {
		_ = device.Close()
		msg := fmt.Errorf("btun: %w", err)
		btunLog.Print(msg.Error())
		return msg
	}

	var tcpListener net.Listener
	if cfg.TCPListen != "" {
		tcpListener, err = net.Listen("tcp", cfg.TCPListen)
		if err != nil {
			_ = server.Close()
			msg := fmt.Errorf("btun: listen TCP %s: %w", cfg.TCPListen, err)
			btunLog.Print(msg.Error())
			return msg
		}
	}
	var udpConn net.PacketConn
	if cfg.UDPListen != "" {
		udpConn, err = net.ListenPacket("udp", cfg.UDPListen)
		if err != nil {
			if tcpListener != nil {
				_ = tcpListener.Close()
			}
			_ = server.Close()
			msg := fmt.Errorf("btun: listen UDP %s: %w", cfg.UDPListen, err)
			btunLog.Print(msg.Error())
			return msg
		}
	}

	var routing *btunRoutingSpec
	if cfg.ManageRouting {
		spec, routeErr := applyBTUNRouting(cfg, device.Name())
		if routeErr != nil {
			// Routing is a host-configuration concern: the tunnel itself is up,
			// so keep serving and surface the problem instead of refusing to
			// start. Without NAT clients reach the server but not the internet.
			btunLog.Printf("routing not fully applied: %v", routeErr)
		}
		routing = &spec
	}

	btunMu.Lock()
	btunServer = server
	btunDevice = device
	btunTCP = tcpListener
	btunUDP = udpConn
	btunListenTCP = cfg.TCPListen
	btunListenUDP = cfg.UDPListen
	btunSharedPorts = cfg.SharedPorts
	btunRoutingApplied = routing
	btunMu.Unlock()

	btunLog.Printf("starting: tun=%s subnet=%s gateway=%s mtu=%d tcp=%q udp=%q shared_ports=%v auth=panel manage_routing=%v max_sessions=%d log_connections=%v",
		device.Name(), cfg.Subnet, cfg.Gateway, cfg.MTU, cfg.TCPListen, cfg.UDPListen,
		cfg.SharedPorts, cfg.ManageRouting, maxSessions, cfg.LogConnections)

	if tcpListener != nil {
		go func() {
			defer btunRecover("ServeTCP")
			if err := server.ServeTCP(tcpListener); err != nil && !isListenerClosed(err) {
				btunLog.Printf("TCP listener stopped: %v", err)
			}
		}()
	}
	if udpConn != nil {
		go func() {
			defer btunRecover("ServeUDP")
			if err := server.ServeUDP(udpConn); err != nil && !isListenerClosed(err) {
				btunLog.Printf("UDP listener stopped: %v", err)
			}
		}()
	}
	return nil
}

func btunRecover(where string) {
	if r := recover(); r != nil {
		btunLog.Printf("recovered panic in %s: %v", where, r)
	}
}

func startBTUNAutoRestart(cfg *BTUNConfig) {
	interval := btunAutoRestartInterval(cfg)
	if interval <= 0 {
		return
	}
	grace := btunAutoRestartGrace(cfg)
	cfgCopy := *cfg
	ctx, cancel := context.WithCancel(context.Background())

	btunAutoMu.Lock()
	if btunAutoCancel != nil {
		btunAutoCancel()
	}
	btunAutoCancel = cancel
	btunAutoMu.Unlock()

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		btunLog.Printf("auto restart enabled: interval=%s grace=%s mode=hard", interval, grace)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				btunLog.Print("auto restart: stopping listeners, sessions and TUN device")
				stopBTUNInstance()
				if !sleepOrContextDone(ctx, grace) {
					return
				}
				for attempt := 1; ; attempt++ {
					if err := startBTUNInstance(&cfgCopy); err != nil {
						btunLog.Printf("auto restart: start attempt %d failed: %v", attempt, err)
						if !sleepOrContextDone(ctx, 10*time.Second) {
							return
						}
						continue
					}
					btunLog.Print("auto restart: server restarted")
					break
				}
			}
		}
	}()
}

func btunAutoRestartInterval(cfg *BTUNConfig) time.Duration {
	if cfg == nil {
		return 0
	}
	raw := strings.TrimSpace(cfg.AutoRestartInterval)
	if raw == "" || raw == "0" || raw == "0s" || strings.EqualFold(raw, "off") || strings.EqualFold(raw, "disabled") {
		return 0
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		btunLog.Printf("auto restart disabled: invalid interval %q: %v", raw, err)
		return 0
	}
	if d < time.Minute {
		btunLog.Printf("auto restart disabled: interval %q is below minimum 1m", raw)
		return 0
	}
	return d
}

func btunAutoRestartGrace(cfg *BTUNConfig) time.Duration {
	if cfg == nil || strings.TrimSpace(cfg.AutoRestartGrace) == "" {
		return 2 * time.Second
	}
	d, err := time.ParseDuration(strings.TrimSpace(cfg.AutoRestartGrace))
	if err != nil || d < 0 {
		btunLog.Printf("auto restart: invalid grace %q, using 2s", cfg.AutoRestartGrace)
		return 2 * time.Second
	}
	if d > time.Minute {
		return time.Minute
	}
	return d
}

func btunDurationOrDefault(raw string, fallback time.Duration, field string) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		btunLog.Printf("invalid %s %q; using default %s", field, raw, fallback)
		return fallback
	}
	return d
}

// normalizeBTUNConfig fills in defaults and derives the gateway address. It
// mutates cfg so the value persisted by the admin API matches what runs.
func normalizeBTUNConfig(cfg *BTUNConfig) {
	cfg.TCPListen = strings.TrimSpace(cfg.TCPListen)
	cfg.UDPListen = strings.TrimSpace(cfg.UDPListen)
	cfg.TUNName = strings.TrimSpace(cfg.TUNName)
	if cfg.TUNName == "" {
		cfg.TUNName = defaultBTUNName
	}
	cfg.Subnet = strings.TrimSpace(cfg.Subnet)
	if cfg.Subnet == "" {
		cfg.Subnet = defaultBTUNSubnet
	}
	cfg.Gateway = strings.TrimSpace(cfg.Gateway)
	if cfg.Gateway == "" {
		if derived, err := btunGatewayForSubnet(cfg.Subnet); err == nil {
			cfg.Gateway = derived
		}
	}
	if cfg.MTU <= 0 {
		cfg.MTU = defaultBTUNMTU
	}
	if cfg.MaxPacketSize > btunMaxPacketCeiling {
		btunLog.Printf("max_packet_size %d exceeds the %d ceiling; clamping",
			cfg.MaxPacketSize, btunMaxPacketCeiling)
		cfg.MaxPacketSize = btunMaxPacketCeiling
	}
	cfg.WANInterface = strings.TrimSpace(cfg.WANInterface)
}

// btunGatewayForSubnet returns the first usable address of subnet in CIDR form,
// which is the address the TUN interface takes. For 10.77.0.0/16 that is
// 10.77.0.1/16.
func btunGatewayForSubnet(subnet string) (string, error) {
	ip, network, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", err
	}
	if ip.To4() == nil {
		return "", errors.New("BTUN subnet must be IPv4")
	}
	ones, bits := network.Mask.Size()
	if bits != 32 || ones > 30 {
		return "", errors.New("BTUN subnet must contain at least four IPv4 addresses")
	}
	base := network.IP.To4()
	gateway := net.IPv4(base[0], base[1], base[2], base[3]).To4()
	gateway[3] |= 1
	return fmt.Sprintf("%s/%d", gateway.String(), ones), nil
}

// ---------- Host routing ----------

// btunRoutingSpec records exactly which rules were installed, so the same ones
// can be removed later even if the configuration changed in between.
type btunRoutingSpec struct {
	TUNName string
	Subnet  string
	Gateway string
	MTU     int
	WAN     string
}

// applyBTUNRouting configures the TUN interface and the NAT/forward rules that
// let BTUN clients reach the internet. It mirrors deploy/btun/btun-routing from
// the standalone deployment, but runs in-process so the panel owns the state.
func applyBTUNRouting(cfg *BTUNConfig, tunName string) (btunRoutingSpec, error) {
	spec := btunRoutingSpec{
		TUNName: tunName,
		Subnet:  cfg.Subnet,
		Gateway: cfg.Gateway,
		MTU:     cfg.MTU,
		WAN:     cfg.WANInterface,
	}
	if spec.WAN == "" {
		detected, err := detectDefaultWANInterface()
		if err != nil {
			return spec, fmt.Errorf("detect WAN interface: %w (set wan_interface explicitly)", err)
		}
		spec.WAN = detected
		btunLog.Printf("routing: detected WAN interface %s", detected)
	}

	var problems []string
	run := func(name string, args ...string) {
		if out, err := runBTUNCommand(name, args...); err != nil {
			problems = append(problems, fmt.Sprintf("%s %s: %v%s", name, strings.Join(args, " "), err, out))
		}
	}

	if spec.Gateway != "" {
		run("ip", "address", "replace", spec.Gateway, "dev", spec.TUNName)
	}
	run("ip", "link", "set", "dev", spec.TUNName, "mtu", strconv.Itoa(spec.MTU), "up")
	// Only write the sysctl when forwarding is actually off. On most hosts it
	// is already on, and the write is denied in restricted environments
	// (containers, hardened kernels) where forwarding nonetheless works, which
	// would otherwise report a failure for something already correct.
	if !ipForwardingEnabled() {
		run("sysctl", "-w", "net.ipv4.ip_forward=1")
	}

	// Each rule is added only when an identical one is not already present, so
	// repeated restarts do not stack duplicates in the tables.
	ensure := func(check, add []string) {
		if _, err := runBTUNCommand("iptables", check...); err == nil {
			return
		}
		if out, err := runBTUNCommand("iptables", add...); err != nil {
			problems = append(problems, fmt.Sprintf("iptables %s: %v%s", strings.Join(add, " "), err, out))
		}
	}
	ensure(
		[]string{"-t", "nat", "-C", "POSTROUTING", "-s", spec.Subnet, "-o", spec.WAN, "-j", "MASQUERADE"},
		[]string{"-t", "nat", "-A", "POSTROUTING", "-s", spec.Subnet, "-o", spec.WAN, "-j", "MASQUERADE"},
	)
	ensure(
		[]string{"-C", "FORWARD", "-i", spec.TUNName, "-o", spec.WAN, "-j", "ACCEPT"},
		[]string{"-A", "FORWARD", "-i", spec.TUNName, "-o", spec.WAN, "-j", "ACCEPT"},
	)
	ensure(
		[]string{"-C", "FORWARD", "-i", spec.WAN, "-o", spec.TUNName, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
		[]string{"-A", "FORWARD", "-i", spec.WAN, "-o", spec.TUNName, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
	)

	if len(problems) > 0 {
		return spec, errors.New(strings.Join(problems, "; "))
	}
	btunLog.Printf("routing: %s %s up, NAT via %s", spec.TUNName, spec.Gateway, spec.WAN)
	return spec, nil
}

// removeBTUNRouting deletes the rules applyBTUNRouting installed. Failures are
// logged and ignored: the rules may already be gone, or the interface may have
// disappeared with the TUN device.
func removeBTUNRouting(spec btunRoutingSpec) {
	if spec.WAN == "" || spec.TUNName == "" {
		return
	}
	deletes := [][]string{
		{"-t", "nat", "-D", "POSTROUTING", "-s", spec.Subnet, "-o", spec.WAN, "-j", "MASQUERADE"},
		{"-D", "FORWARD", "-i", spec.TUNName, "-o", spec.WAN, "-j", "ACCEPT"},
		{"-D", "FORWARD", "-i", spec.WAN, "-o", spec.TUNName, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
	}
	for _, args := range deletes {
		if _, err := runBTUNCommand("iptables", args...); err != nil {
			btunLog.Printf("routing cleanup: iptables %s: %v", strings.Join(args, " "), err)
		}
	}
}

// ipForwardingEnabled reports whether the kernel already forwards IPv4. A read
// error is treated as "not enabled" so the caller still attempts the write.
func ipForwardingEnabled() bool {
	data, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(data)) == "1"
}

// detectDefaultWANInterface reads the uplink from the default IPv4 route, the
// same way the standalone btun-routing script does.
func detectDefaultWANInterface() (string, error) {
	out, err := runBTUNCommand("ip", "-4", "route", "show", "default")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		for index := 0; index+1 < len(fields); index++ {
			if fields[index] == "dev" {
				return fields[index+1], nil
			}
		}
	}
	return "", errors.New("no default IPv4 route")
}

// runBTUNCommand runs a short host command with a timeout and returns its
// combined output. The output is included in error strings so a failing
// iptables rule is diagnosable from the panel.
func runBTUNCommand(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), btunRouteCommandTimeout)
	defer cancel()
	var output bytes.Buffer
	command := exec.CommandContext(ctx, name, args...)
	command.Stdout = &output
	command.Stderr = &output
	err := command.Run()
	text := strings.TrimSpace(output.String())
	if text != "" {
		text = ": " + text
	}
	return text, err
}

// ---------- Stats ----------

// BTUNStatsSnapshot is what /api/btun returns.
type BTUNStatsSnapshot struct {
	Enabled bool   `json:"enabled"`
	Running bool   `json:"running"`
	Listen  string `json:"listen,omitempty"`
	TUNName string `json:"tunName,omitempty"`
	Subnet  string `json:"subnet,omitempty"`
	btun.StatsSnapshot
}

// GetBTUNStatsSnapshot returns the current BTUN counters. It is safe for
// concurrent use and always returns a copy.
func GetBTUNStatsSnapshot() BTUNStatsSnapshot {
	snapshot := BTUNStatsSnapshot{
		Enabled: btunEnabledInCurrentConfig(),
		Running: btunRunning(),
		Listen:  btunListenList(),
	}
	btunMu.Lock()
	server := btunServer
	device := btunDevice
	btunMu.Unlock()
	if device != nil {
		snapshot.TUNName = device.Name()
	}
	if server != nil {
		snapshot.StatsSnapshot = server.Stats()
	}
	globalCfgMu.RLock()
	if globalCfg != nil && globalCfg.BTUN != nil {
		snapshot.Subnet = globalCfg.BTUN.Subnet
	}
	globalCfgMu.RUnlock()
	return snapshot
}
