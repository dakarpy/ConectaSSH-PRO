package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/tls"
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/ssh"
	"golang.org/x/time/rate"
	"runtime/debug"
)

const (
	// Hard timeouts to ensure half-open connections don't leak goroutines.
	// This also bounds DNSTT SSH handshakes (streamConn now honors deadlines),
	// which travel over DNS and need more headroom than a direct TCP handshake;
	// 45s is generous for slow/lossy DNS paths while still reaping wedged streams.
	sshHandshakeTimeout = 45 * time.Second
	tlsHandshakeTimeout = 15 * time.Second
	// Dial timeout for direct-tcpip backend connections.
	directTCPIPDialTimeout = 10 * time.Second
	// VPN transports must remain connected even when the user is temporarily
	// idle. Dead peers are released by transport errors/request cancellation,
	// not by a short application-level inactivity timer. Operators may still
	// set ssh_idle_timeout explicitly when they intentionally want one.
	defaultSSHIdleTimeout time.Duration = 0
)

// ---------- Config types ----------

// TLSForwarderConfig specifies a TLS listener that accepts encrypted
// connections and passes the decrypted stream directly into the SSH
// handler.  The listener binds to the given address (which should be
// specified in bracket form for IPv6, e.g. "[2001:db8::1]:443") and
// terminates TLS using the provided certificate and key files.  Each
// connection is then handled by the same handleConn logic as the
// plain TCP listeners.  If no TLS forwarders are configured, no
// TLS listeners are started.
type TLSForwarderConfig struct {
	// Listen address for the TLS‑wrapped SSH service.  For IPv6, use
	// bracket form, e.g. "[2001:db8::10]:443" or "[::]:443".
	Listen string `json:"listen"`
	// CertFile is the path to the TLS certificate in PEM format.
	CertFile string `json:"cert_file"`
	// KeyFile is the path to the corresponding private key in PEM format.
	KeyFile string `json:"key_file"`
}

type Config struct {
	Listen string `json:"listen"`

	// ProxyAutoRestartInterval controls a watchdog that periodically hard-restarts
	// the public proxy listeners (listen, extra_listen, and TLS forwarders) and
	// closes active SSH sessions. Empty, "0s", "off", or "disabled" turns it off.
	// Valid examples: "30m", "6h", "24h". Minimum accepted value is 1m.
	ProxyAutoRestartInterval string `json:"proxy_auto_restart_interval,omitempty"`

	// ProxyAutoRestartGrace is the delay between closing proxy listeners/sessions
	// and binding them again during an auto restart. Empty defaults to "2s".
	ProxyAutoRestartGrace string `json:"proxy_auto_restart_grace,omitempty"`

	// Optional extra public listen addresses (multi‑port).  These
	// addresses use the same HTTP‑cleanup and SSH handler as the
	// primary Listen address.  For IPv6, use bracket form, e.g.
	// "[::]:80", "[2001:db8::20]:8080".  Empty slice means no
	// additional listeners.
	ExtraListen []string `json:"extra_listen"`
	// LocalSSHListen is the raw SSH endpoint used by local proxy/tunnel daemons.
	// It is always enabled, defaults to 127.0.0.1:2222, and is restricted to a
	// numeric loopback address so it cannot accidentally become a public port.
	LocalSSHListen string `json:"local_ssh_listen"`
	HostKeyFile    string `json:"host_key_file"`
	Quiet          bool   `json:"quiet"`

	Banner     string `json:"banner"`
	BannerFile string `json:"banner_file"`

	UserCount bool `json:"user_count"`
	// AutoMenu enables the administration menu automatically for root interactive shells.
	AutoMenu bool `json:"auto_menu"`

	// SSHConnectionLimitEnabled controls the per-user max_connections enforcement.
	// The account value remains available for display/check APIs even when disabled.
	SSHConnectionLimitEnabled bool `json:"ssh_connection_limit_enabled"`

	// PAMAuthEnabled turns on Linux system-password login for this server. When
	// true, an SSH login with a username not present in the panel is verified
	// against /etc/shadow; on success the account (regular users, UID >= 1000)
	// is auto-imported into the panel. When false, only panel-managed accounts
	// can log in and previously-imported PAM accounts are refused.
	PAMAuthEnabled bool `json:"pam_auth_enabled"`

	// SSHIdleTimeout controls how long an authenticated SSH connection may
	// remain with no bytes moving in either direction before it is closed and
	// released from the active user count. Empty, "0", or "0s" disables it.
	// VPN/XHTTP connections should normally leave this disabled.
	SSHIdleTimeout string `json:"ssh_idle_timeout,omitempty"`

	// MaxTotalConnections caps the total number of concurrent SSH connections
	// across all users. Once reached, new connections are rejected before the
	// (expensive) SSH handshake, so a surge past normal load cannot exhaust
	// memory/CPU and crash the server. 0 or empty uses the default (10000);
	// set to -1 to disable the global cap entirely.
	MaxTotalConnections int `json:"max_total_connections,omitempty"`

	// Default per-connection bandwidth limits (if user-specific = 0)
	DefaultLimitMbpsUp   int `json:"default_limit_mbps_up"`
	DefaultLimitMbpsDown int `json:"default_limit_mbps_down"`

	Users []UserConfig `json:"users"`

	// DNSTT holds configuration for the DNS tunnel server.  If nil, the DNS
	// tunnel server is disabled.  Domain is the DNS zone used for tunnelled
	// queries (e.g. "t.example.com").  UDPListen specifies the UDP address
	// to listen on (IPv6 syntax like "[::]:5300").  PrivKeyFile points to
	// the private key used for the Noise handshake between client and server.
	DNSTT *DNSTTConfig `json:"dnstt"`

	// UDPGW holds configuration for the integrated UDP gateway.  If nil, the
	// gateway is disabled.  The gateway implements the BadVPN udpgw protocol
	// (connID + X + IPv4 + port framing) and forwards UDP datagrams between a
	// TCP client and arbitrary destinations.  See udpgwstandalone.go for
	// implementation details.
	UDPGW *UDPGWConfig `json:"udpgw"`

	// Optional TLS listeners (stunnel‑like): accept TLS and handle SSH on
	// the same process (no TCP backend).  Each forwarder binds to the
	// given address and terminates TLS using the specified certificate
	// and key.  If no TLS forwarders are defined, the server does not
	// listen for TLS connections.  See serveTLSSSH for implementation.
	TLSForwarders []TLSForwarderConfig `json:"tls_forwarders"`

	// Xray holds configuration for the integrated Xray-core process.  If nil
	// the Xray subprocess is not started.  See xray_integration.go.
	Xray *XrayConfig `json:"xray"`

	// BHTTP holds configuration for the integrated BHTTP (BHP1/BHP2) transport.
	// If nil, the transport is disabled. Sessions are relayed to this process's
	// own SSH server, never to the system sshd. See bhttp_integration.go.
	BHTTP *BHTTPConfig `json:"bhttp"`

	// BTUN holds configuration for the integrated BTUN protocol server. If nil,
	// the server is disabled. BTUN moves IP packets rather than an SSH stream,
	// so it authenticates against the panel's own account database — never PAM
	// or /etc/shadow. See btun_integration.go.
	BTUN *BTUNConfig `json:"btun"`

	// HCR holds configuration for the integrated HCR (HTTP/Custom Relay)
	// transport. If nil, it is disabled. Like BHTTP, each session is relayed to
	// this process's own SSH server, and it can coexist with BHTTP on the same
	// ports. See hcr_integration.go.
	HCR *HCRConfig `json:"hcr"`
}

// DNSTTConfig defines the settings for the integrated dnstt server.  See
// https://www.bamsoftware.com/software/dnstt/ for background on dnstt.  The
// server listens on the UDP address in UDPListen, uses Domain as the root of
// the tunnelled zone, and loads its private key from PrivKeyFile.  The
// corresponding public key must be distributed to clients.
type DNSTTConfig struct {
	// Domain is the primary/root DNS zone reserved for the tunnel (e.g. "t.example.com").
	// It is kept for backward compatibility and is also used as the first client
	// domain when Domains is empty.
	Domain string `json:"domain"`

	// Domains optionally lists all DNS root zones/NS domains accepted by this
	// server. This allows the same DNSTT listener/key to answer for public and
	// local DNS deployments at the same time, for example:
	// ["t.example.com", "t.local.lan"]. The first normalized value is mirrored
	// into Domain for older clients/UI code.
	Domains []string `json:"domains,omitempty"`
	// UDPListen is the UDP address to listen on for incoming DNS tunnel queries.
	// IPv6 addresses must use bracket form, for example "[::]:5300" or
	// "[2001:db8::1234]:53". IPv6 listeners are opened with udp6 so they do
	// not require a spare IPv4 address on the same port.
	UDPListen string `json:"udp_listen"`

	// FakeDNSEnabled starts an extra built-in DNS listener for local/LAN testing.
	// It uses the same DNSTT private key and session pool, but only accepts the
	// FakeDNSDomain zone. This avoids needing a second DNS server for tests such
	// as t.local.lan over a dedicated IPv6 address.
	FakeDNSEnabled bool `json:"fake_dns_enabled,omitempty"`

	// FakeDNSListen is the IPv4/IPv6 UDP address for the built-in local DNS
	// listener. For your case use an IPv6 address, for example
	// "[2001:db8::1234]:53" or "[::]:53".
	FakeDNSListen string `json:"fake_dns_listen,omitempty"`

	// FakeDNSDomain is the local DNSTT zone accepted by the built-in DNS listener.
	// If empty while FakeDNSEnabled is true, it defaults to "t.local.lan".
	FakeDNSDomain string `json:"fake_dns_domain,omitempty"`

	// FakeDNSWorkers controls how many concurrent UDP read/parse workers are used
	// by the built-in local DNS listener. Zero uses a safe automatic default.
	FakeDNSWorkers int `json:"fake_dns_workers,omitempty"`

	// DNSResponseWorkers controls how many DNS response sender shards are used.
	// Zero keeps the safest default of one sender. Increase carefully only when
	// the DNSTT pending queue grows under load.
	DNSResponseWorkers int `json:"dns_response_workers,omitempty"`
	// PrivKeyFile is the path to the Noise server private key.  Generate a
	// keypair with the dnstt tool (use -gen-key) and copy the resulting
	// private key here; the matching public key must be distributed to
	// clients【38494750697905†L172-L209】.
	PrivKeyFile string `json:"privkey_file"`

	// DisableStatsLog disables printing of periodic DNSTT statistics to the
	// process stderr.  When true, the server will still collect tunnel
	// counters and expose them via the admin API, but the log lines like
	// "dnstt: stats 5s: dns_rx=..." will not appear on the CLI.  The default
	// is false, meaning stats are printed.  This flag is useful when running
	// the server in quiet environments where repeated log output should be
	// avoided, but visibility into tunnel health is still desired via the
	// web panel.
	DisableStatsLog bool `json:"disable_stats_log"`

	// DisableConsoleLog disables printing of all DNSTT log lines to stderr.  When
	// true, messages such as new KCP sessions, smux streams, and SSH stream
	// begin/end will not be written to the console.  Instead, they are
	// captured in an in-memory buffer and surfaced via the admin API for
	// display in the web panel.  The default is false, meaning logs are
	// printed to the console.  Set this to true in combination with
	// disable_stats_log if you want a fully quiet DNSTT server.
	DisableConsoleLog bool `json:"disable_console_log"`

	// AutoRestartInterval controls a watchdog that periodically cycles only the
	// integrated DNSTT UDP listener. Empty, "0s", "off", or "disabled" turns it
	// off. Valid examples: "30m", "2h", "6h". Minimum accepted value is 1m.
	AutoRestartInterval string `json:"auto_restart_interval,omitempty"`

	// AutoRestartGrace is the delay between closing the old DNSTT UDP socket and
	// binding a new one during an auto restart. Empty defaults to "2s".
	AutoRestartGrace string `json:"auto_restart_grace,omitempty"`

	// MaxSessions limits concurrently open DNSTT/KCP sessions. Zero uses a safe
	// default for large public servers. Negative disables the limit.
	MaxSessions int `json:"max_sessions,omitempty"`

	// MaxStreams limits concurrently open smux/SSH streams across all DNSTT
	// sessions. Zero uses a safe default. Negative disables the limit.
	MaxStreams int `json:"max_streams,omitempty"`

	// PendingResponses controls the buffer of queued DNS responses waiting for
	// sendLoop. Zero uses the default. Keeping it bounded prevents RAM spikes.
	PendingResponses int `json:"pending_responses,omitempty"`

	// StreamBuffer sets smux MaxStreamBuffer in bytes. Zero uses the default.
	// Lower values reduce RAM use when thousands of clients are connected.
	StreamBuffer int `json:"stream_buffer,omitempty"`

	// UDPReadBuffer and UDPWriteBuffer request OS socket buffers in bytes. Zero
	// uses the default. The kernel may clamp these unless sysctl limits are raised.
	UDPReadBuffer  int `json:"udp_read_buffer,omitempty"`
	UDPWriteBuffer int `json:"udp_write_buffer,omitempty"`

	// LogConnections enables per-session and per-stream DNSTT logs. Leave off on
	// servers with thousands of users because connection logging can become the
	// bottleneck and make crashes more likely.
	LogConnections bool `json:"log_connections,omitempty"`
}

// UDPGWConfig defines the settings for the integrated UDP gateway.  The
// gateway accepts TCP connections speaking the BadVPN udpgw protocol and
// forwards framed UDP datagrams to arbitrary IPv4 destinations.  All
// fields are optional; if a field is zero or empty, a sensible default
// matching the standalone udpgw implementation is used.
type UDPGWConfig struct {
	// Listen is the TCP address to bind for incoming udpgw clients.  Use
	// IPv6 syntax in brackets when necessary (e.g. "[::]:7300").  If
	// empty, the default "0.0.0.0:7300" is used.
	Listen string `json:"listen"`
	// MaxFrame limits the maximum payload length (in bytes) of a frame sent
	// by the client.  The default is 64*1024 (64 KiB).  Frames larger
	// than this are rejected.
	MaxFrame int `json:"max_frame"`
	// Debug enables verbose logging of connections, frames and
	// mappings.
	Debug bool `json:"debug"`
	// HexdumpN controls how many bytes of each payload are hex‑dumped in
	// debug logs.  A value of zero suppresses hex dumps.  Default is 64.
	HexdumpN int `json:"hexdump"`
	// WriteChan sets the size of the buffered channel used for sending
	// reply frames back to the client. Default and hard ceiling is 1024:
	// values above the ceiling are clamped down, so an oversized value left in
	// an old config cannot bloat per-client memory. Zero uses the default.
	WriteChan int `json:"write_chan"`
	// UDPBindIP, if non‑empty, causes each per‑client UDP socket to bind to
	// the specified local IP address.  The port is chosen automatically.
	UDPBindIP string `json:"udp_bind"`
	// UDPRBuf sets the per-client UDP socket read buffer in bytes. This is
	// KERNEL memory allocated per connected client. Default and hard ceiling is
	// 512 KiB; larger values (including old 8 MiB configs) are clamped down so
	// thousands of clients cannot exhaust kernel memory. Zero uses the default.
	UDPRBuf int `json:"udp_rbuf"`
	// UDPWBuf sets the per-client UDP socket write buffer in bytes. Default and
	// hard ceiling is 512 KiB; larger values are clamped down. Zero uses the
	// default.
	UDPWBuf int `json:"udp_wbuf"`
	// MapTTL controls how long a destination->connID mapping remains
	// valid after the last packet from that destination.  Expressed as a
	// duration string.  Default is "90s".
	MapTTL string `json:"map_ttl"`
	// ReapEvery controls how often expired mappings are purged.  Expressed
	// as a duration string.  Default is "10s".
	ReapEvery string `json:"reap_every"`
	// IdleTimeout controls how long a TCP client connection may remain
	// idle (no frames received) before being closed. Expressed as a duration
	// string. Default is "2m".
	IdleTimeout string `json:"idle_timeout"`
	// MaxClientConns limits how many distinct udpgw connIDs a single TCP
	// client connection may keep active at once. This is the primary guard
	// against a single client creating effectively infinite logical UDP
	// sessions and growing RAM usage over time. Default is 10.
	MaxClientConns int `json:"max_client_conns"`
	// MaxMapEntries limits the maximum number of destination->connID
	// mappings kept per client. This protects the server from unbounded
	// growth if a client sprays packets to many unique destinations.
	// Default is 32768.
	MaxMapEntries int `json:"max_map_entries"`
	// MaxClients caps the total number of concurrent UDPGW client TCP
	// connections. Once reached, new clients are rejected (their TCP socket is
	// closed immediately) instead of being accepted, so a surge past normal
	// load cannot exhaust memory and crash the server. Default is 10000.
	// A value <= 0 uses the default.
	MaxClients int `json:"max_clients"`

	// AutoRestartInterval controls a watchdog that periodically hard-restarts
	// the integrated UDPGW listener and closes all connected UDPGW clients. Empty,
	// "0s", "off", or "disabled" turns it off. Valid examples: "30m", "6h", "24h".
	// Minimum accepted value is 1m.
	AutoRestartInterval string `json:"auto_restart_interval,omitempty"`

	// AutoRestartGrace is the delay between closing the old UDPGW listener/clients
	// and binding a new one during an auto restart. Empty defaults to "2s".
	AutoRestartGrace string `json:"auto_restart_grace,omitempty"`
}

type UserConfig struct {
	Username      string `json:"username"`
	Password      string `json:"password"`
	PublicKeyFile string `json:"public_key_file"` // optional .pub path

	// Optional rotating password mode for shared/public accounts. When
	// totp_secret is set, the server accepts a TOTP code as the SSH
	// password. This is useful when you want to make copied credentials
	// expire quickly without relying on a separate API.
	// Secret must be Base32 (with or without padding). Example generated
	// secret: JBSWY3DPEHPK3PXP
	TOTPSecret string `json:"totp_secret"`
	// Period in seconds for each password step. Default: 60.
	TOTPPeriod int `json:"totp_period"`
	// Number of adjacent time windows accepted for clock drift.
	// Default: 1 (previous/current/next).
	TOTPWindow int `json:"totp_window"`
	// Number of digits in the generated TOTP. Default: 6.
	TOTPDigits int `json:"totp_digits"`
	// When true, both the static Password and the TOTP code are accepted.
	// When false and totp_secret is set, only the TOTP code is accepted.
	AllowStaticPassword bool `json:"allow_static_password"`

	// UsePAM enables Linux PAM authentication for the system account matching
	// this username. New users default to true; callers can explicitly disable it.
	UsePAM bool `json:"use_pam"`

	MaxConnections int    `json:"max_connections"`
	ExpiresAt      string `json:"expires_at"` // RFC3339 or empty

	// Per-connection limits (one limiter per SSH connection)
	LimitMbpsUp   int `json:"limit_mbps_up"`   // Mbps upstream
	LimitMbpsDown int `json:"limit_mbps_down"` // Mbps downstream

	// Persistent data quota. Zero means unlimited. When the total uploaded +
	// downloaded bytes reaches the quota, QuotaAction either blocks traffic or
	// throttles the account to QuotaThrottleMbps.
	DataQuotaBytes    int64  `json:"data_quota_bytes"`
	QuotaAction       string `json:"quota_action"`
	QuotaThrottleMbps int    `json:"quota_throttle_mbps"`

	// OwnerUsername is the reseller who created this SSH user.  Empty = superadmin-owned.
	OwnerUsername string `json:"owner_username,omitempty"`
}

type UserState struct {
	Cfg       UserConfig
	ExpiresAt *time.Time
	PubKey    ssh.PublicKey // may be nil

	mu          sync.Mutex
	ActiveConns int
	conns       map[*ssh.ServerConn]struct{} // active SSH connections for this user
	// btunConns counts active BTUN sessions for this user. BTUN carries IP
	// packets instead of an SSH stream, so it has no *ssh.ServerConn to track;
	// it shares max_connections with SSH through this counter.
	btunConns int

	// Persistent per-user tunnel traffic. totalBytes includes reservations made
	// by concurrent copy loops, while directional totals only include bytes that
	// were actually written. The pending counters are flushed to PostgreSQL.
	TotalUplinkBytes     int64
	TotalDownlinkBytes   int64
	totalBytes           int64
	pendingUplinkBytes   int64
	pendingDownlinkBytes int64
	trafficMu            sync.RWMutex
	quotaLimiter         *rate.Limiter
	quotaLimiterMbps     int
}

type UserManager struct {
	mu    sync.RWMutex
	users map[string]*UserState
}

func (m *UserManager) Get(username string) (*UserState, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.users[username]
	return u, ok
}

// AddIfAbsent inserts u only if no user with the same username exists yet, and
// reports whether it was added. Used by PAM auto-import to register a freshly
// authenticated system account without clobbering an existing runtime state.
func (m *UserManager) AddIfAbsent(u *UserState) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.users[u.Cfg.Username]; exists {
		return false
	}
	m.users[u.Cfg.Username] = u
	return true
}

func (m *UserManager) List() []*UserState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*UserState, 0, len(m.users))
	for _, u := range m.users {
		out = append(out, u)
	}
	return out
}

func (m *UserManager) ReplaceAll(newUsers map[string]*UserState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users = newUsers
}

// ReplaceAllPreserveRuntime replaces the user map while keeping the same
// runtime UserState object for users that already exist. This is important:
// active handleConn goroutines hold a pointer to the old UserState and run the
// decrement in a defer. If we copy ActiveConns into a new UserState during a DB
// reload, that later decrement happens on the old object and the visible count
// in the new map stays stuck.
func (m *UserManager) ReplaceAllPreserveRuntime(newUsers map[string]*UserState) {
	m.mu.Lock()
	old := m.users

	for username, nu := range newUsers {
		if ou, ok := old[username]; ok && ou != nil && nu != nil {
			ou.mu.Lock()
			ou.Cfg = nu.Cfg
			ou.ExpiresAt = nu.ExpiresAt
			ou.PubKey = nu.PubKey
			if ou.conns == nil {
				ou.conns = make(map[*ssh.ServerConn]struct{})
			}
			// Self-heal any previously stale counter by trusting the live connection map.
			ou.ActiveConns = len(ou.conns) + ou.btunConns
			ou.mu.Unlock()

			newUsers[username] = ou
		}
	}

	m.users = newUsers
	m.mu.Unlock()
}

// DisconnectUser closes all active SSH connections for the given user.
// Safe if the user does not exist or has no connections.
func (m *UserManager) DisconnectUser(username string) {
	m.mu.RLock()
	u, ok := m.users[username]
	m.mu.RUnlock()
	if !ok {
		return
	}

	u.mu.Lock()
	conns := make([]*ssh.ServerConn, 0, len(u.conns))
	for c := range u.conns {
		conns = append(conns, c)
	}
	u.mu.Unlock()

	for _, c := range conns {
		_ = c.Close()
	}
	// BTUN sessions belong to the same account allowance, so a panel-driven
	// disconnect has to drop them too.
	btunDisconnectUser(username)
}

// DisconnectAll closes every authenticated SSH connection currently tracked by
// the user manager. It is used by the proxy hard auto-restart to mimic a real
// service reboot instead of only reopening listening sockets.
func (m *UserManager) DisconnectAll() int {
	m.mu.RLock()
	states := make([]*UserState, 0, len(m.users))
	for _, u := range m.users {
		states = append(states, u)
	}
	m.mu.RUnlock()

	seen := make(map[*ssh.ServerConn]struct{})
	for _, u := range states {
		if u == nil {
			continue
		}
		u.mu.Lock()
		for c := range u.conns {
			seen[c] = struct{}{}
		}
		u.mu.Unlock()
	}

	for c := range seen {
		_ = c.Close()
	}
	return len(seen) + btunDisconnectAll()
}

// Global state
var (
	userMgr          = &UserManager{users: make(map[string]*UserState)}
	userCountEnabled bool

	sshIdleTimeoutMu      sync.RWMutex
	currentSSHIdleTimeout = defaultSSHIdleTimeout

	displayMu      sync.Mutex
	lastDisplayLen int

	// Server stats (CPU + network interfaces)
	statsMu      sync.RWMutex
	currentStats StatsDTO

	// Optional: persist interface byte counters across process restarts / reboots (requires PG_DSN).
	ifaceTotalsMgr *IfaceTotalsManager
	statsStore     *Store
)

// ---------- Helpers ----------

func publicKeysEqual(a, b ssh.PublicKey) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Type() == b.Type() && bytes.Equal(a.Marshal(), b.Marshal())
}

func mbpsToBytesPerSec(mbps int) int64 {
	if mbps <= 0 {
		return 0
	}
	return int64(mbps) * 1024 * 1024 / 8
}

// copyBufSize is the per-direction relay buffer for tunnel traffic. SSH tunnel
// clients (mobile injection apps) push many low-bandwidth flows, so a large
// buffer wastes heap with no throughput benefit. 16 KiB keeps per-channel heap
// low across thousands of concurrent direct-tcpip channels.
const copyBufSize = 16 * 1024

var copyBufPool = sync.Pool{
	New: func() interface{} { b := make([]byte, copyBufSize); return &b },
}

// copyWithRateLimit relays src->dst through a pooled buffer. Every copy path
// (rate-limited or not) goes through the pool: previously the lim==nil path used
// io.Copy, which allocates a fresh 32 KiB buffer per direction per channel and
// never pools it — at thousands of channels that churn dominated GC pressure.
func copyWithRateLimit(dst io.Writer, src io.Reader, lim *rate.Limiter) (written int64, err error) {
	return copyWithRateLimitContext(context.Background(), dst, src, lim)
}

func copyWithRateLimitContext(ctx context.Context, dst io.Writer, src io.Reader, lim *rate.Limiter) (written int64, err error) {
	bufp := copyBufPool.Get().(*[]byte)
	buf := *bufp
	defer copyBufPool.Put(bufp)

	if ctx == nil {
		ctx = context.Background()
	}

	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			if lim != nil {
				if err := lim.WaitN(ctx, nr); err != nil {
					return written, err
				}
			}

			nw, ew := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}

		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}

	return written, err
}

func parseSSHIdleTimeout(raw string) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "0" || raw == "0s" || strings.EqualFold(raw, "off") || strings.EqualFold(raw, "disabled") {
		return 0
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		log.Printf("invalid ssh_idle_timeout %q: %v; disabling SSH idle timeout", raw, err)
		return 0
	}
	if d < 0 {
		log.Printf("invalid negative ssh_idle_timeout %q; disabling SSH idle timeout", raw)
		return 0
	}
	return d
}

func setSSHIdleTimeoutFromConfig(raw string) {
	d := parseSSHIdleTimeout(raw)
	sshIdleTimeoutMu.Lock()
	currentSSHIdleTimeout = d
	sshIdleTimeoutMu.Unlock()
}

func getSSHIdleTimeout() time.Duration {
	sshIdleTimeoutMu.RLock()
	d := currentSSHIdleTimeout
	sshIdleTimeoutMu.RUnlock()
	return d
}

// defaultMaxTotalConns is the global concurrent SSH connection cap used when
// max_total_connections is unset (0). Keeps headroom above normal load while
// preventing an unbounded surge from exhausting memory/CPU.
const defaultMaxTotalConns = 10000

var (
	// activeSSHConns is the current number of in-flight SSH connections.
	activeSSHConns int64
	// maxTotalConns is the global cap; 0 means unlimited. Set from config.
	maxTotalConns int64 = defaultMaxTotalConns
	// sshConnsRejected counts connections turned away at the global cap.
	sshConnsRejected int64
)

// setMaxTotalConnsFromConfig applies the max_total_connections config value:
// 0 -> default, <0 -> disabled (unlimited), >0 -> that exact cap.
func setMaxTotalConnsFromConfig(v int) {
	var lim int64
	switch {
	case v < 0:
		lim = 0
	case v == 0:
		lim = defaultMaxTotalConns
	default:
		lim = int64(v)
	}
	atomic.StoreInt64(&maxTotalConns, lim)
}

// activityConn tracks real SSH transport activity in both directions. The idle
// monitor uses this instead of a read deadline so download-only or upload-only
// tunnels are considered live and are not disconnected.
type activityConn struct {
	net.Conn
	mu   sync.Mutex
	last time.Time
}

func newActivityConn(c net.Conn) *activityConn {
	return &activityConn{Conn: c, last: time.Now()}
}

func (c *activityConn) touch() {
	c.mu.Lock()
	c.last = time.Now()
	c.mu.Unlock()
}

func (c *activityConn) LastActivity() time.Time {
	c.mu.Lock()
	last := c.last
	c.mu.Unlock()
	return last
}

func (c *activityConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.touch()
	}
	return n, err
}

func (c *activityConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.touch()
	}
	return n, err
}

func monitorSSHIdle(c *activityConn, sshConn *ssh.ServerConn, username string, idleTimeout time.Duration, done <-chan struct{}) {
	if idleTimeout <= 0 {
		return
	}
	checkEvery := idleTimeout / 4
	if checkEvery < 5*time.Second {
		checkEvery = 5 * time.Second
	}
	if checkEvery > 30*time.Second {
		checkEvery = 30 * time.Second
	}

	ticker := time.NewTicker(checkEvery)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			idleFor := time.Since(c.LastActivity())
			if idleFor >= idleTimeout {
				log.Printf("ssh idle timeout: user=%s remote=%s idle=%s limit=%s; closing stale connection",
					username, sshConn.RemoteAddr(), idleFor.Round(time.Second), idleTimeout)
				_ = sshConn.Close()
				_ = c.Close()
				return
			}
		}
	}
}

// ---------- Server stats (CPU + network interfaces) ----------

// per-interface stats returned by /api/stats
type InterfaceStats struct {
	Name    string  `json:"name"`
	RxBytes uint64  `json:"rx_bytes"`
	TxBytes uint64  `json:"tx_bytes"`
	RxMbps  float64 `json:"rx_mbps"`
	TxMbps  float64 `json:"tx_mbps"`
}

type StatsDTO struct {
	CPUPercent float64          `json:"cpu_percent"`
	MemTotal   uint64           `json:"mem_total_bytes"`
	MemUsed    uint64           `json:"mem_used_bytes"`
	MemAvail   uint64           `json:"mem_avail_bytes"`
	MemPercent float64          `json:"mem_percent"`
	Interfaces []InterfaceStats `json:"interfaces"`
}
type ifaceCounters struct {
	RxBytes uint64
	TxBytes uint64
}

func isIgnoredInterface(iface string) bool {
	return iface == "" || iface == "lo"
}

func getCurrentStats() StatsDTO {
	statsMu.RLock()
	defer statsMu.RUnlock()
	return currentStats
}

func setCurrentStats(s StatsDTO) {
	statsMu.Lock()
	currentStats = s
	statsMu.Unlock()
}

// primeCurrentStats fills RAM and interface totals immediately at startup so
// the dashboard does not show placeholder values while waiting for the first
// polling interval. CPU still becomes accurate after the second /proc/stat
// sample, but it is rendered as 0.0% instead of --.
func primeCurrentStats() {
	netMap, _ := readNetDev()
	interfaces := make([]InterfaceStats, 0, len(netMap))
	for name, ctrs := range netMap {
		if isIgnoredInterface(name) {
			continue
		}
		st := InterfaceStats{Name: name}
		if ifaceTotalsMgr != nil {
			rxTotal, txTotal := ifaceTotalsMgr.ApplyKernel(name, ctrs.RxBytes, ctrs.TxBytes)
			st.RxBytes = rxTotal
			st.TxBytes = txTotal
		} else {
			st.RxBytes = ctrs.RxBytes
			st.TxBytes = ctrs.TxBytes
		}
		interfaces = append(interfaces, st)
	}
	sort.Slice(interfaces, func(i, j int) bool { return interfaces[i].Name < interfaces[j].Name })
	memTotal, memAvail, _ := readMemInfo()
	var memUsed uint64
	var memPercent float64
	if memTotal > 0 {
		if memAvail <= memTotal {
			memUsed = memTotal - memAvail
			memPercent = 100.0 * float64(memUsed) / float64(memTotal)
		}
	}
	setCurrentStats(StatsDTO{
		CPUPercent: 0,
		MemTotal:   memTotal,
		MemUsed:    memUsed,
		MemAvail:   memAvail,
		MemPercent: memPercent,
		Interfaces: interfaces,
	})
}

type IfaceTotals struct {
	Iface             string
	TotalRxBytes      uint64
	TotalTxBytes      uint64
	LastKernelRxBytes uint64
	LastKernelTxBytes uint64
	UpdatedAt         time.Time
	ResetAt           time.Time
}

type IfaceTotalsManager struct {
	mu sync.Mutex
	m  map[string]*IfaceTotals
}

func NewIfaceTotalsManager() *IfaceTotalsManager {
	return &IfaceTotalsManager{m: make(map[string]*IfaceTotals)}
}

// ApplyKernel updates cumulative totals using kernel counters (from /proc/net/dev).
// It is resilient to kernel counter resets (e.g. host reboot): if the kernel counter
// goes backwards, it treats the new value as "delta since reset".
func (tm *IfaceTotalsManager) ApplyKernel(iface string, kRx, kTx uint64) (totalRx, totalTx uint64) {
	if isIgnoredInterface(iface) {
		return 0, 0
	}
	tm.mu.Lock()
	defer tm.mu.Unlock()

	now := time.Now()
	st, ok := tm.m[iface]
	if !ok {
		st = &IfaceTotals{Iface: iface, ResetAt: now}
		tm.m[iface] = st
	}
	if st.ResetAt.IsZero() {
		st.ResetAt = now
	}

	// The live interface counters in the Stats tab are a rolling 30-day total.
	// This reset does not touch the vnstat-style daily/monthly history tables.
	if now.Sub(st.ResetAt) >= 30*24*time.Hour {
		st.TotalRxBytes = 0
		st.TotalTxBytes = 0
		st.LastKernelRxBytes = kRx
		st.LastKernelTxBytes = kTx
		st.ResetAt = now
		st.UpdatedAt = now
		return 0, 0
	}

	// RX
	if st.LastKernelRxBytes == 0 && st.TotalRxBytes == 0 {
		st.TotalRxBytes = kRx
	} else if kRx >= st.LastKernelRxBytes {
		st.TotalRxBytes += kRx - st.LastKernelRxBytes
	} else {
		// kernel reset or wrap
		st.TotalRxBytes += kRx
	}
	st.LastKernelRxBytes = kRx

	// TX
	if st.LastKernelTxBytes == 0 && st.TotalTxBytes == 0 {
		st.TotalTxBytes = kTx
	} else if kTx >= st.LastKernelTxBytes {
		st.TotalTxBytes += kTx - st.LastKernelTxBytes
	} else {
		st.TotalTxBytes += kTx
	}
	st.LastKernelTxBytes = kTx

	st.UpdatedAt = now
	return st.TotalRxBytes, st.TotalTxBytes
}

func (tm *IfaceTotalsManager) ResetAllToKernel(netMap map[string]ifaceCounters) []IfaceTotals {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	now := time.Now()
	tm.m = make(map[string]*IfaceTotals, len(netMap))
	out := make([]IfaceTotals, 0, len(netMap))
	for iface, ctrs := range netMap {
		if isIgnoredInterface(iface) {
			continue
		}
		st := &IfaceTotals{
			Iface:             iface,
			TotalRxBytes:      0,
			TotalTxBytes:      0,
			LastKernelRxBytes: ctrs.RxBytes,
			LastKernelTxBytes: ctrs.TxBytes,
			UpdatedAt:         now,
			ResetAt:           now,
		}
		tm.m[iface] = st
		out = append(out, *st)
	}
	return out
}

func (tm *IfaceTotalsManager) Load(rows []IfaceTotals) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	for _, r := range rows {
		if isIgnoredInterface(r.Iface) {
			continue
		}
		cp := r // copy
		tm.m[r.Iface] = &cp
	}
}

func (tm *IfaceTotalsManager) Snapshot() []IfaceTotals {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	out := make([]IfaceTotals, 0, len(tm.m))
	for _, v := range tm.m {
		if v == nil || isIgnoredInterface(v.Iface) {
			continue
		}
		out = append(out, *v)
	}
	return out
}

// startStatsCollector periodically reads /proc/stat and /proc/net/dev
// to compute CPU usage and per-interface traffic in Mbps.
func startStatsCollector() {
	go func() {
		// Recover from any panic so the goroutine doesn't silently die and
		// leave stats frozen.  Log the panic and restart after a short delay.
		defer func() {
			if r := recover(); r != nil {
				log.Printf("startStatsCollector: panic recovered: %v; restarting in 5s", r)
				time.Sleep(5 * time.Second)
				go startStatsCollector()
			}
		}()

		var (
			prevIdle, prevTotal uint64
			prevNet             map[string]ifaceCounters
			prevTime            time.Time
		)

		// Use a ticker for the poll interval so the goroutine can be
		// cleanly stopped in tests and so the flush ticker is always
		// paired with a matching Stop().
		pollTicker := time.NewTicker(2 * time.Second)
		defer pollTicker.Stop()

		var flushTicker *time.Ticker
		if statsStore != nil && ifaceTotalsMgr != nil {
			flushTicker = time.NewTicker(30 * time.Second)
			defer flushTicker.Stop()
		}

		for range pollTicker.C {
			now := time.Now()

			idle, total, err := readCPUStat()
			if err != nil {
				// keep previous CPU if error
			}

			netMap, err := readNetDev()
			if err != nil {
				// keep previous net if error
			}

			// CPU usage
			var cpuPercent float64
			if prevTotal != 0 && total > prevTotal {
				idleDelta := float64(idle - prevIdle)
				totalDelta := float64(total - prevTotal)
				if totalDelta > 0 {
					cpuPercent = 100.0 * (1.0 - idleDelta/totalDelta)
				}
			}

			// Per-interface Mbps (Rx/Tx)
			var interfaces []InterfaceStats
			dt := now.Sub(prevTime).Seconds()
			if netMap != nil {
				for name, ctrs := range netMap {
					if isIgnoredInterface(name) {
						continue
					}
					st := InterfaceStats{
						Name: name,
					}
					// Bytes: if persistence enabled, show cumulative totals across restarts; else show kernel counters.
					if ifaceTotalsMgr != nil {
						rxTotal, txTotal := ifaceTotalsMgr.ApplyKernel(name, ctrs.RxBytes, ctrs.TxBytes)
						st.RxBytes = rxTotal
						st.TxBytes = txTotal
					} else {
						st.RxBytes = ctrs.RxBytes
						st.TxBytes = ctrs.TxBytes
					}
					if prevNet != nil && dt > 0 {
						if prev, ok := prevNet[name]; ok {
							var rxDelta, txDelta uint64
							if ctrs.RxBytes >= prev.RxBytes {
								rxDelta = ctrs.RxBytes - prev.RxBytes
							} else {
								// kernel counter reset or wrap
								rxDelta = ctrs.RxBytes
							}
							if ctrs.TxBytes >= prev.TxBytes {
								txDelta = ctrs.TxBytes - prev.TxBytes
							} else {
								txDelta = ctrs.TxBytes
							}
							if rxDelta > 0 {
								st.RxMbps = float64(rxDelta*8) / dt / 1_000_000
							}
							if txDelta > 0 {
								st.TxMbps = float64(txDelta*8) / dt / 1_000_000
							}
							if statsStore != nil && (rxDelta > 0 || txDelta > 0) {
								addPendingIfaceUsage(name, rxDelta, txDelta)
							}
						}
					}
					interfaces = append(interfaces, st)
				}
			}

			sort.Slice(interfaces, func(i, j int) bool {
				return interfaces[i].Name < interfaces[j].Name
			})

			// RAM usage (/proc/meminfo)
			memTotal, memAvail, _ := readMemInfo()
			var memUsed uint64
			var memPercent float64
			if memTotal > 0 {
				if memAvail <= memTotal {
					memUsed = memTotal - memAvail
					memPercent = 100.0 * float64(memUsed) / float64(memTotal)
				} else {
					memAvail = memTotal
				}
			}

			setCurrentStats(StatsDTO{
				CPUPercent: cpuPercent,
				MemTotal:   memTotal,
				MemUsed:    memUsed,
				MemAvail:   memAvail,
				MemPercent: memPercent,
				Interfaces: interfaces,
			})

			// Persist interface totals and vnstat-style usage periodically (optional).
			if flushTicker != nil && statsStore != nil && ifaceTotalsMgr != nil {
				select {
				case <-flushTicker.C:
					ctx := context.Background()
					_ = statsStore.UpsertIfaceTotals(ctx, ifaceTotalsMgr.Snapshot())
					if deltas := flushPendingIfaceUsage(now); len(deltas) > 0 {
						if err := statsStore.UpsertIfaceUsageDeltas(ctx, deltas); err != nil {
							log.Printf("vnstat usage flush failed: %v", err)
							restorePendingIfaceUsage(deltas)
						}
					}
				default:
				}
			}

			prevIdle, prevTotal = idle, total
			prevNet = netMap
			prevTime = now
		}
	}()
}

func readMemInfo() (totalBytes, availBytes uint64, err error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	var (
		memTotalKB uint64
		memAvailKB uint64
		memFreeKB  uint64
		buffersKB  uint64
		cachedKB   uint64
	)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.TrimSuffix(fields[0], ":")
		val, perr := strconv.ParseUint(fields[1], 10, 64)
		if perr != nil {
			continue
		}
		switch key {
		case "MemTotal":
			memTotalKB = val
		case "MemAvailable":
			memAvailKB = val
		case "MemFree":
			memFreeKB = val
		case "Buffers":
			buffersKB = val
		case "Cached":
			cachedKB = val
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, err
	}
	if memTotalKB == 0 {
		return 0, 0, nil
	}
	if memAvailKB == 0 {
		memAvailKB = memFreeKB + buffersKB + cachedKB
		if memAvailKB > memTotalKB {
			memAvailKB = memTotalKB
		}
	}
	return memTotalKB * 1024, memAvailKB * 1024, nil
}

func readCPUStat() (idle, total uint64, err error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "cpu ") {
			fields := strings.Fields(line)
			if len(fields) < 5 {
				break
			}
			for i := 1; i < len(fields); i++ {
				v, err2 := strconv.ParseUint(fields[i], 10, 64)
				if err2 != nil {
					continue
				}
				total += v
				// idle + iowait
				if i == 4 || i == 5 {
					idle += v
				}
			}
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, err
	}
	return idle, total, nil
}

func readNetDev() (map[string]ifaceCounters, error) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	stats := make(map[string]ifaceCounters)
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum <= 2 {
			// headers
			continue
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		iface := strings.TrimSpace(parts[0])
		if isIgnoredInterface(iface) {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) < 9 {
			continue
		}
		rx, err1 := strconv.ParseUint(fields[0], 10, 64)
		tx, err2 := strconv.ParseUint(fields[8], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		stats[iface] = ifaceCounters{
			RxBytes: rx,
			TxBytes: tx,
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return stats, nil
}

// ---------- Config loading ----------

const defaultInstalledConfigPath = "/opt/sshpanel/config.json"

func resolveMainConfigPath(path string) string {
	path = strings.TrimSpace(path)
	if path != "" {
		return path
	}
	if _, err := os.Stat("config.json"); err == nil {
		return "config.json"
	}
	return defaultInstalledConfigPath
}

func loadConfig(path string) (*Config, map[string]*UserState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, nil, fmt.Errorf("parse config: %w", err)
	}
	// PAM is enabled by default for new installations/configurations. Preserve
	// an explicit false so existing administrators can disable it intentionally.
	var rawConfig map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawConfig); err == nil {
		if _, present := rawConfig["pam_auth_enabled"]; !present {
			cfg.PAMAuthEnabled = true
		}
	}
	if cfg.Xray != nil {
		cfg.Xray.NormalizeDefaults()
	}

	if cfg.Listen == "" {
		cfg.Listen = defaultMainListen
	}
	if cfg.HostKeyFile == "" {
		cfg.HostKeyFile = "ssh_host_rsa_key"
	}

	userMap := make(map[string]*UserState)
	for _, u := range cfg.Users {
		if u.Username == "" {
			return nil, nil, fmt.Errorf("config: user with empty username")
		}
		if _, exists := userMap[u.Username]; exists {
			return nil, nil, fmt.Errorf("config: duplicate user %q", u.Username)
		}

		// Apply default bandwidth limits if not set per-user.
		if u.LimitMbpsUp == 0 {
			u.LimitMbpsUp = cfg.DefaultLimitMbpsUp
		}
		if u.LimitMbpsDown == 0 {
			u.LimitMbpsDown = cfg.DefaultLimitMbpsDown
		}

		st := &UserState{Cfg: u}

		if u.ExpiresAt != "" {
			t, err := time.Parse(time.RFC3339, u.ExpiresAt)
			if err != nil {
				return nil, nil, fmt.Errorf("config: invalid expires_at for user %q: %w", u.Username, err)
			}
			st.ExpiresAt = &t
		}

		// Load per-user public key if configured
		if u.PublicKeyFile != "" {
			pkBytes, err := os.ReadFile(u.PublicKeyFile)
			if err != nil {
				return nil, nil, fmt.Errorf("config: could not read public_key_file for user %q: %w", u.Username, err)
			}
			pubKey, _, _, _, err := ssh.ParseAuthorizedKey(pkBytes)
			if err != nil {
				return nil, nil, fmt.Errorf("config: invalid public key in %s for user %q: %w",
					u.PublicKeyFile, u.Username, err)
			}
			st.PubKey = pubKey
		}

		userMap[u.Username] = st
	}

	return &cfg, userMap, nil
}

// ---------- Database store & admin API ----------

type Store struct {
	db *sql.DB
}

func NewStore(dsn string) (*Store, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(time.Hour)

	if err := db.Ping(); err != nil {
		return nil, err
	}
	store := &Store{db: db}
	ctx := context.Background()
	if err := store.EnsureUsersSchema(ctx); err != nil {
		return nil, err
	}
	if err := store.EnsureAdminUsersSchema(ctx); err != nil {
		return nil, err
	}
	if err := store.EnsureManagedServersSchema(ctx); err != nil {
		return nil, err
	}
	if err := store.EnsureBotSchema(ctx); err != nil {
		return nil, err
	}
	return store, nil
}

const sshPasswordPrefix = "enc:v1:ssh:"

func sealSSHPassword(password string) (string, error) {
	return sealCredential(sshPasswordPrefix, password)
}

func openSSHPassword(password string) (string, error) {
	return openCredential(sshPasswordPrefix, password)
}

func (s *Store) EnsureUsersSchema(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS ssh_users (
			username TEXT PRIMARY KEY,
			password TEXT NOT NULL DEFAULT '',
			max_connections INT NOT NULL DEFAULT 0,
			expires_at TEXT,
			limit_mbps_up INT NOT NULL DEFAULT 0,
			limit_mbps_down INT NOT NULL DEFAULT 0,
			data_quota_bytes BIGINT NOT NULL DEFAULT 0,
			quota_action TEXT NOT NULL DEFAULT 'block',
			quota_throttle_mbps INT NOT NULL DEFAULT 1,
			total_uplink_bytes BIGINT NOT NULL DEFAULT 0,
			total_downlink_bytes BIGINT NOT NULL DEFAULT 0,
			totp_secret TEXT NOT NULL DEFAULT '',
			totp_period INT NOT NULL DEFAULT 60,
			totp_window INT NOT NULL DEFAULT 1,
			totp_digits INT NOT NULL DEFAULT 6,
			allow_static_password BOOLEAN NOT NULL DEFAULT FALSE,
			use_pam BOOLEAN NOT NULL DEFAULT TRUE
		)`,
		`ALTER TABLE ssh_users ADD COLUMN IF NOT EXISTS totp_secret TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE ssh_users ADD COLUMN IF NOT EXISTS totp_period INT NOT NULL DEFAULT 60`,
		`ALTER TABLE ssh_users ADD COLUMN IF NOT EXISTS totp_window INT NOT NULL DEFAULT 1`,
		`ALTER TABLE ssh_users ADD COLUMN IF NOT EXISTS totp_digits INT NOT NULL DEFAULT 6`,
		`ALTER TABLE ssh_users ADD COLUMN IF NOT EXISTS allow_static_password BOOLEAN NOT NULL DEFAULT FALSE`,
		`ALTER TABLE ssh_users ADD COLUMN IF NOT EXISTS use_pam BOOLEAN NOT NULL DEFAULT TRUE`,
		`ALTER TABLE ssh_users ADD COLUMN IF NOT EXISTS data_quota_bytes BIGINT NOT NULL DEFAULT 0`,
		`ALTER TABLE ssh_users ADD COLUMN IF NOT EXISTS quota_action TEXT NOT NULL DEFAULT 'block'`,
		`ALTER TABLE ssh_users ADD COLUMN IF NOT EXISTS quota_throttle_mbps INT NOT NULL DEFAULT 1`,
		`ALTER TABLE ssh_users ADD COLUMN IF NOT EXISTS total_uplink_bytes BIGINT NOT NULL DEFAULT 0`,
		`ALTER TABLE ssh_users ADD COLUMN IF NOT EXISTS total_downlink_bytes BIGINT NOT NULL DEFAULT 0`,
		`ALTER TABLE ssh_users ALTER COLUMN password SET DEFAULT ''`,
		`ALTER TABLE ssh_users ALTER COLUMN use_pam SET DEFAULT TRUE`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return s.migrateSSHPasswords(ctx)
}

func (s *Store) migrateSSHPasswords(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT username, password FROM ssh_users WHERE password <> '' AND password NOT LIKE 'enc:v1:ssh:%'`)
	if err != nil {
		return err
	}
	type legacyPassword struct {
		username string
		password string
	}
	var legacy []legacyPassword
	for rows.Next() {
		var item legacyPassword
		if err := rows.Scan(&item.username, &item.password); err != nil {
			rows.Close()
			return err
		}
		legacy = append(legacy, item)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, item := range legacy {
		sealed, err := sealSSHPassword(item.password)
		if err != nil {
			return fmt.Errorf("encrypt SSH password for %s: %w", item.username, err)
		}
		if _, err := s.db.ExecContext(ctx, `UPDATE ssh_users SET password=$2 WHERE username=$1`, item.username, sealed); err != nil {
			return err
		}
	}
	return nil
}

// LoadUsers loads all users from the ssh_users table into in-memory UserState map.
func (s *Store) LoadUsers(ctx context.Context) (map[string]*UserState, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT username, password, max_connections, expires_at, limit_mbps_up, limit_mbps_down,
		       COALESCE(data_quota_bytes, 0), COALESCE(quota_action, 'block'), COALESCE(quota_throttle_mbps, 1),
		       COALESCE(total_uplink_bytes, 0), COALESCE(total_downlink_bytes, 0),
		       COALESCE(totp_secret, ''), COALESCE(totp_period, 60), COALESCE(totp_window, 1),
		       COALESCE(totp_digits, 6), COALESCE(allow_static_password, FALSE),
		       COALESCE(use_pam, FALSE), COALESCE(owner_username, '')
		FROM ssh_users`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := make(map[string]*UserState)
	for rows.Next() {
		var (
			username            string
			password            string
			maxConnections      int
			expiresAt           sql.NullString
			limitUp             int
			limitDown           int
			dataQuotaBytes      int64
			quotaAction         string
			quotaThrottleMbps   int
			totalUplinkBytes    int64
			totalDownlinkBytes  int64
			totpSecret          string
			totpPeriod          int
			totpWindow          int
			totpDigits          int
			allowStaticPassword bool
			usePAM              bool
			ownerUsername       string
		)
		if err := rows.Scan(&username, &password, &maxConnections, &expiresAt, &limitUp, &limitDown,
			&dataQuotaBytes, &quotaAction, &quotaThrottleMbps, &totalUplinkBytes, &totalDownlinkBytes,
			&totpSecret, &totpPeriod, &totpWindow, &totpDigits, &allowStaticPassword, &usePAM, &ownerUsername); err != nil {
			return nil, err
		}
		password, err = openSSHPassword(password)
		if err != nil {
			return nil, fmt.Errorf("decrypt SSH password for %s: %w", username, err)
		}

		cfg := UserConfig{
			Username:            username,
			Password:            password,
			MaxConnections:      maxConnections,
			LimitMbpsUp:         limitUp,
			LimitMbpsDown:       limitDown,
			DataQuotaBytes:      dataQuotaBytes,
			QuotaAction:         normalizeQuotaAction(quotaAction),
			QuotaThrottleMbps:   quotaThrottleMbps,
			TOTPSecret:          totpSecret,
			TOTPPeriod:          totpPeriod,
			TOTPWindow:          totpWindow,
			TOTPDigits:          totpDigits,
			AllowStaticPassword: allowStaticPassword,
			UsePAM:              usePAM,
			OwnerUsername:       ownerUsername,
		}

		st := &UserState{Cfg: cfg}
		initSSHRuntimeUsage(st, totalUplinkBytes, totalDownlinkBytes)
		if expiresAt.Valid && expiresAt.String != "" {
			t, err := time.Parse(time.RFC3339, expiresAt.String)
			if err != nil {
				log.Printf("invalid expires_at for user %s in db: %v", username, err)
			} else {
				st.ExpiresAt = &t
				st.Cfg.ExpiresAt = expiresAt.String
			}
		}
		users[username] = st
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return users, nil
}

// UpsertUser creates or updates a row in ssh_users.
func (s *Store) UpsertUser(ctx context.Context, u UserConfig) error {
	storedPassword, err := sealSSHPassword(u.Password)
	if err != nil {
		return fmt.Errorf("encrypt SSH password: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO ssh_users (
			username, password, max_connections, expires_at, limit_mbps_up, limit_mbps_down,
			data_quota_bytes, quota_action, quota_throttle_mbps,
			totp_secret, totp_period, totp_window, totp_digits, allow_static_password, use_pam, owner_username
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		ON CONFLICT (username) DO UPDATE
		SET password             = EXCLUDED.password,
		    max_connections      = EXCLUDED.max_connections,
		    expires_at           = EXCLUDED.expires_at,
		    limit_mbps_up        = EXCLUDED.limit_mbps_up,
		    limit_mbps_down      = EXCLUDED.limit_mbps_down,
		    data_quota_bytes     = EXCLUDED.data_quota_bytes,
		    quota_action         = EXCLUDED.quota_action,
		    quota_throttle_mbps  = EXCLUDED.quota_throttle_mbps,
		    totp_secret          = EXCLUDED.totp_secret,
		    totp_period          = EXCLUDED.totp_period,
		    totp_window          = EXCLUDED.totp_window,
		    totp_digits          = EXCLUDED.totp_digits,
		    allow_static_password = EXCLUDED.allow_static_password,
		    use_pam              = EXCLUDED.use_pam`,
		// owner_username is intentionally excluded from UPDATE — ownership is set at creation only.
		u.Username, storedPassword, u.MaxConnections, u.ExpiresAt, u.LimitMbpsUp, u.LimitMbpsDown,
		u.DataQuotaBytes, normalizeQuotaAction(u.QuotaAction), quotaThrottleMbpsOrDefault(u.QuotaThrottleMbps),
		u.TOTPSecret, u.TOTPPeriod, u.TOTPWindow, u.TOTPDigits, u.AllowStaticPassword, u.UsePAM, u.OwnerUsername)
	return err
}

func (s *Store) DeleteUser(ctx context.Context, username string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM ssh_users WHERE username = $1`, username)
	return err
}

// ---------- Optional persistence for interface totals ----------

func (s *Store) EnsureIfaceTotalsTable(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS ssh_iface_totals (
			iface TEXT PRIMARY KEY,
			total_rx_bytes BIGINT NOT NULL DEFAULT 0,
			total_tx_bytes BIGINT NOT NULL DEFAULT 0,
			last_kernel_rx_bytes BIGINT NOT NULL DEFAULT 0,
			last_kernel_tx_bytes BIGINT NOT NULL DEFAULT 0,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			reset_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`ALTER TABLE ssh_iface_totals ADD COLUMN IF NOT EXISTS reset_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) LoadIfaceTotals(ctx context.Context) ([]IfaceTotals, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT iface, total_rx_bytes, total_tx_bytes, last_kernel_rx_bytes, last_kernel_tx_bytes, updated_at, reset_at
		FROM ssh_iface_totals
		WHERE iface <> 'lo'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []IfaceTotals{}
	for rows.Next() {
		var r IfaceTotals
		var updated, resetAt time.Time
		if err := rows.Scan(&r.Iface, &r.TotalRxBytes, &r.TotalTxBytes, &r.LastKernelRxBytes, &r.LastKernelTxBytes, &updated, &resetAt); err != nil {
			return nil, err
		}
		r.UpdatedAt = updated
		r.ResetAt = resetAt
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) UpsertIfaceTotals(ctx context.Context, rows []IfaceTotals) error {
	if len(rows) == 0 {
		return nil
	}
	// Simple loop (small N: number of interfaces). Keeps CPU/DB overhead minimal.
	for _, r := range rows {
		if isIgnoredInterface(r.Iface) {
			continue
		}
		resetAt := r.ResetAt
		if resetAt.IsZero() {
			resetAt = time.Now()
		}
		_, err := s.db.ExecContext(ctx, `
			INSERT INTO ssh_iface_totals (iface, total_rx_bytes, total_tx_bytes, last_kernel_rx_bytes, last_kernel_tx_bytes, updated_at, reset_at)
			VALUES ($1, $2, $3, $4, $5, NOW(), $6)
			ON CONFLICT (iface) DO UPDATE
			SET total_rx_bytes = EXCLUDED.total_rx_bytes,
				total_tx_bytes = EXCLUDED.total_tx_bytes,
				last_kernel_rx_bytes = EXCLUDED.last_kernel_rx_bytes,
				last_kernel_tx_bytes = EXCLUDED.last_kernel_tx_bytes,
				updated_at = NOW(),
				reset_at = EXCLUDED.reset_at`,
			r.Iface, r.TotalRxBytes, r.TotalTxBytes, r.LastKernelRxBytes, r.LastKernelTxBytes, resetAt)
		if err != nil {
			return err
		}
	}
	return nil
}

func reloadUsersFromDB(ctx context.Context, store *Store) {
	if store == nil {
		return
	}
	users, err := store.LoadUsers(ctx)
	if err != nil {
		log.Printf("failed to reload users from db: %v", err)
		return
	}
	userMgr.ReplaceAllPreserveRuntime(users)
	updateUserDisplay()
}

func startAdminAPI(store *Store, addr string) {
	mux := http.NewServeMux()

	// Auth (no session required)
	mux.Handle("/api/auth/login", http.HandlerFunc(handleLogin(store)))

	// Auth (session required)
	mux.Handle("/api/auth/logout", sessionMiddleware(http.HandlerFunc(handleLogout)))
	mux.Handle("/api/auth/me", sessionMiddleware(http.HandlerFunc(handleMe)))

	// SSH user management (session required; role-filtered inside handlers)
	mux.Handle("/api/users", sessionMiddleware(http.HandlerFunc(handleListUsers)))
	mux.Handle("/api/users/create", sessionMiddleware(http.HandlerFunc(handleCreateUser(store))))
	mux.Handle("/api/users/reset-traffic", sessionMiddleware(http.HandlerFunc(handleResetUserTraffic(store))))
	mux.Handle("/api/users/delete", sessionMiddleware(http.HandlerFunc(handleDeleteUser(store))))

	// Server stats: visible to authenticated sessions; reset remains superadmin-only.
	mux.Handle("/api/stats", sessionMiddleware(http.HandlerFunc(handleStats)))
	mux.Handle("/api/stats/interfaces/reset", saSession(http.HandlerFunc(handleResetInterfaceStats(store))))
	mux.Handle("/api/vnstat", saSession(http.HandlerFunc(handleVnstat(store))))
	mux.Handle("/api/vnstat/reset", saSession(http.HandlerFunc(handleVnstatReset(store))))
	mux.Handle("/api/system/logs", saSession(http.HandlerFunc(handleSystemLogs)))
	mux.Handle("/api/system/logs/reset", saSession(http.HandlerFunc(handleSystemLogsReset)))
	mux.Handle("/api/system/update-status", saSession(http.HandlerFunc(handleUpdateStatus)))
	mux.Handle("/api/dnstt", saSession(http.HandlerFunc(handleDnsttStats)))
	mux.Handle("/api/dnstt/logs", saSession(http.HandlerFunc(handleDnsttLogs)))
	mux.Handle("/api/bhttp", saSession(http.HandlerFunc(handleBHTTPStats)))
	mux.Handle("/api/bhttp/logs", saSession(http.HandlerFunc(handleBHTTPLogs)))
	mux.Handle("/api/btun", saSession(http.HandlerFunc(handleBTUNStats)))
	mux.Handle("/api/btun/logs", saSession(http.HandlerFunc(handleBTUNLogs)))
	mux.Handle("/api/hcr", saSession(http.HandlerFunc(handleHCRStats)))
	mux.Handle("/api/hcr/logs", saSession(http.HandlerFunc(handleHCRLogs)))

	// Superadmin-only: reseller management
	mux.Handle("/api/resellers", saSession(http.HandlerFunc(handleListResellers(store))))
	mux.Handle("/api/resellers/create", saSession(http.HandlerFunc(handleCreateReseller(store))))
	mux.Handle("/api/resellers/delete", saSession(http.HandlerFunc(handleDeleteReseller(store))))

	// Master/slave server management. Superadmins can add slave nodes; all authenticated
	// users can read the enabled server list to pick where accounts are created.
	mux.Handle("/api/servers", sessionMiddleware(http.HandlerFunc(handleServers(store))))
	mux.Handle("/api/servers/test", saSession(http.HandlerFunc(handleServerTest(store))))
	mux.Handle("/api/servers/config", saSession(http.HandlerFunc(handleManagedServerConfig(store))))

	// Xray-core management. Service/config/log actions are superadmin-only;
	// authenticated resellers may list inbounds and manage their own Xray clients.
	mux.Handle("/api/xray/status", sessionMiddleware(http.HandlerFunc(handleXrayStatus)))
	mux.Handle("/api/xray/start", saSession(http.HandlerFunc(handleXrayStart)))
	mux.Handle("/api/xray/stop", saSession(http.HandlerFunc(handleXrayStop)))
	mux.Handle("/api/xray/restart", saSession(http.HandlerFunc(handleXrayRestart)))
	mux.Handle("/api/xray/stats/repair", saSession(http.HandlerFunc(handleXrayRepairStats)))
	mux.Handle("/api/xray/config", saSession(http.HandlerFunc(handleXrayConfig)))
	mux.Handle("/api/xray/logs", saSession(http.HandlerFunc(handleXrayLogs)))
	mux.Handle("/api/xray/inbounds", sessionMiddleware(http.HandlerFunc(handleXrayInbounds)))
	mux.Handle("/api/xray/clients/add", sessionMiddleware(http.HandlerFunc(handleXrayClientAdd)))
	mux.Handle("/api/xray/clients/update", sessionMiddleware(http.HandlerFunc(handleXrayClientUpdate)))
	mux.Handle("/api/xray/clients/reset-traffic", sessionMiddleware(http.HandlerFunc(handleXrayClientResetTraffic)))
	mux.Handle("/api/xray/clients/remove", sessionMiddleware(http.HandlerFunc(handleXrayClientRemove)))

	// Superadmin-only: TLS certificate generation
	mux.Handle("/api/tls/generate-selfsigned", saSession(handleManagedProxyOrLocal(store, handleTLSGenerateSelfSigned)))
	mux.Handle("/api/tls/letsencrypt", saSession(handleManagedProxyOrLocal(store, handleTLSLetsEncrypt)))
	mux.Handle("/api/tls/upload-pem", saSession(handleManagedProxyOrLocal(store, handleTLSUploadPEM)))
	mux.Handle("/api/tls/certs", saSession(handleManagedProxyOrLocal(store, handleTLSCertList)))
	mux.Handle("/api/tls/certs/update", saSession(handleManagedProxyOrLocal(store, handleTLSCertUpdate)))

	// Superadmin-only: DNSTT key management
	mux.Handle("/api/dnstt/genkey", saSession(handleManagedProxyOrLocal(store, handleDnsttGenKey)))
	mux.Handle("/api/dnstt/pubkey", saSession(handleManagedProxyOrLocal(store, handleDnsttGetPubKey)))

	// Superadmin-only: server config (read/write config.json + live banner apply)
	mux.Handle("/api/server/config", saSession(http.HandlerFunc(handleServerConfig)))

	// Superadmin-only: Telegram sales bot management
	mux.Handle("/api/bot/config", saSession(http.HandlerFunc(handleBotConfig(store))))
	mux.Handle("/api/bot/plans", saSession(http.HandlerFunc(handleBotPlans(store))))
	mux.Handle("/api/bot/credit-packages", saSession(http.HandlerFunc(handleBotCreditPackages(store))))
	mux.Handle("/api/bot/users", saSession(http.HandlerFunc(handleBotUsers(store))))
	mux.Handle("/api/bot/transactions", saSession(http.HandlerFunc(handleBotTransactions(store))))
	mux.Handle("/api/bot/settings", saSession(http.HandlerFunc(handleBotSettings(store))))
	mux.Handle("/api/bot/test", saSession(http.HandlerFunc(handleBotTest(store))))

	// Public: Mercado Pago payment webhook (validated by signature inside).
	mux.Handle("/api/mp/webhook", http.HandlerFunc(handleMPWebhook))

	// Public: user/UUID check — no auth, CORS *.
	mux.Handle("/check", http.HandlerFunc(handleCheck))

	go func() {
		log.Printf("DragonCoreSSH API listening on %s", addr)
		server := &http.Server{
			Addr:              addr,
			Handler:           secureAPIHandler(mux),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      2 * time.Minute,
			IdleTimeout:       90 * time.Second,
			MaxHeaderBytes:    1 << 20,
		}
		if err := server.ListenAndServe(); err != nil {
			log.Printf("admin http error: %v", err)
		}
	}()
}

// UserDTO is returned by the admin API for listing.
type UserDTO struct {
	Username           string     `json:"username"`
	ActiveConns        int        `json:"active_conns"`
	MaxConnections     int        `json:"max_connections"`
	ExpiresAt          *time.Time `json:"expires_at,omitempty"`
	LimitUpMbps        int        `json:"limit_mbps_up"`
	LimitDownMbps      int        `json:"limit_mbps_down"`
	DataQuotaBytes     int64      `json:"data_quota_bytes"`
	QuotaAction        string     `json:"quota_action"`
	QuotaThrottleMbps  int        `json:"quota_throttle_mbps"`
	TotalUplinkBytes   int64      `json:"total_uplink_bytes"`
	TotalDownlinkBytes int64      `json:"total_downlink_bytes"`
	TotalBytes         int64      `json:"total_bytes"`
	// Live account-wide speed in bytes per second, summed across every
	// connection the user has open.
	UpBytesPerSec       float64 `json:"up_bytes_per_sec"`
	DownBytesPerSec     float64 `json:"down_bytes_per_sec"`
	QuotaExceeded       bool    `json:"quota_exceeded"`
	TOTPSecret          string  `json:"totp_secret,omitempty"`
	TOTPPeriod          int     `json:"totp_period"`
	TOTPWindow          int     `json:"totp_window"`
	TOTPDigits          int     `json:"totp_digits"`
	AllowStaticPassword bool    `json:"allow_static_password"`
	UsePAM              bool    `json:"use_pam"`
	TOTPEnabled         bool    `json:"totp_enabled"`
	OwnerUsername       string  `json:"owner_username,omitempty"`
	ServerID            string  `json:"server_id,omitempty"`
}

func handleListUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	sess := sessionFromCtx(r.Context())
	filterOwner := ""
	if sess != nil && sess.Role == RoleReseller {
		filterOwner = sess.Username
	}
	if proxyManagedServerFromRequest(w, r, statsStore, "/api/users", nil, filterOwner) {
		return
	}
	states := userMgr.List()
	out := make([]UserDTO, 0, len(states))
	for _, u := range states {
		u.mu.Lock()
		c := len(u.conns) + u.btunConns
		u.ActiveConns = c
		cfg := u.Cfg
		expires := u.ExpiresAt
		u.mu.Unlock()
		totalUp := atomic.LoadInt64(&u.TotalUplinkBytes)
		totalDown := atomic.LoadInt64(&u.TotalDownlinkBytes)
		totalBytes := atomic.LoadInt64(&u.totalBytes)

		// Resellers only see their own users
		if sess != nil && sess.Role == RoleReseller && cfg.OwnerUsername != sess.Username {
			continue
		}

		rate := sshUserRate(cfg.Username)

		out = append(out, UserDTO{
			Username:            cfg.Username,
			ActiveConns:         c,
			MaxConnections:      cfg.MaxConnections,
			ExpiresAt:           expires,
			LimitUpMbps:         cfg.LimitMbpsUp,
			LimitDownMbps:       cfg.LimitMbpsDown,
			DataQuotaBytes:      cfg.DataQuotaBytes,
			QuotaAction:         normalizeQuotaAction(cfg.QuotaAction),
			QuotaThrottleMbps:   quotaThrottleMbpsOrDefault(cfg.QuotaThrottleMbps),
			TotalUplinkBytes:    totalUp,
			TotalDownlinkBytes:  totalDown,
			TotalBytes:          totalBytes,
			UpBytesPerSec:       rate.UpBytesPerSec,
			DownBytesPerSec:     rate.DownBytesPerSec,
			QuotaExceeded:       cfg.DataQuotaBytes > 0 && totalBytes >= cfg.DataQuotaBytes,
			TOTPSecret:          cfg.TOTPSecret,
			TOTPPeriod:          cfg.TOTPPeriod,
			TOTPWindow:          cfg.TOTPWindow,
			TOTPDigits:          cfg.TOTPDigits,
			AllowStaticPassword: cfg.AllowStaticPassword,
			UsePAM:              cfg.UsePAM,
			TOTPEnabled:         strings.TrimSpace(cfg.TOTPSecret) != "",
			OwnerUsername:       cfg.OwnerUsername,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// NOTE: Password is pointer to distinguish "field missing" vs "field present".
type UserPayload struct {
	Username            string  `json:"username"`
	Password            *string `json:"password,omitempty"` // nil or empty = keep existing if user already exists
	MaxConnections      int     `json:"max_connections"`
	ExpiresAt           string  `json:"expires_at"`
	LimitUpMbps         int     `json:"limit_mbps_up"`
	LimitDownMbps       int     `json:"limit_mbps_down"`
	DataQuotaBytes      int64   `json:"data_quota_bytes"`
	QuotaAction         string  `json:"quota_action"`
	QuotaThrottleMbps   int     `json:"quota_throttle_mbps"`
	ResetUsage          bool    `json:"reset_usage,omitempty"`
	TOTPSecret          string  `json:"totp_secret"`
	TOTPPeriod          int     `json:"totp_period"`
	TOTPWindow          int     `json:"totp_window"`
	TOTPDigits          int     `json:"totp_digits"`
	AllowStaticPassword bool    `json:"allow_static_password"`
	UsePAM              *bool   `json:"use_pam"`
	OwnerUsername       string  `json:"owner_username,omitempty"`
	ServerID            string  `json:"server_id,omitempty"`
}

func handleCreateUser(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if store == nil {
			http.Error(w, "database not configured", http.StatusServiceUnavailable)
			return
		}

		var p UserPayload
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		p.Username = strings.TrimSpace(p.Username)
		// PAM is enabled by default for API-created users. Send use_pam=false explicitly to disable it.
		usePAM := true
		if p.UsePAM != nil {
			usePAM = *p.UsePAM
		}
		if p.Username == "" {
			http.Error(w, "username required", http.StatusBadRequest)
			return
		}
		if p.MaxConnections < 0 || p.MaxConnections > 10000 {
			http.Error(w, "max_connections must be between 0 and 10000", http.StatusBadRequest)
			return
		}
		if p.LimitUpMbps < 0 || p.LimitUpMbps > 1000000 || p.LimitDownMbps < 0 || p.LimitDownMbps > 1000000 {
			http.Error(w, "bandwidth limits must be between 0 and 1000000 Mbps", http.StatusBadRequest)
			return
		}
		if p.ExpiresAt != "" {
			if _, err := time.Parse(time.RFC3339, p.ExpiresAt); err != nil {
				http.Error(w, "invalid expires_at (RFC3339 required)", http.StatusBadRequest)
				return
			}
		}
		if err := validateQuotaConfig(p.DataQuotaBytes, p.QuotaAction, p.QuotaThrottleMbps); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		ctx := r.Context()
		if ms, remote, err := managedServerFromID(ctx, store, p.ServerID); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} else if remote {
			if !ms.EnableSSH {
				http.Error(w, "SSH creation is disabled for this server", http.StatusForbidden)
				return
			}
			if sess := sessionFromCtx(ctx); sess != nil && sess.Role == RoleReseller {
				currentOwner, exists, ownerErr := remoteSSHUserOwner(ctx, ms, p.Username)
				if ownerErr != nil {
					http.Error(w, "could not verify remote ownership", http.StatusBadGateway)
					return
				}
				if exists && currentOwner != sess.Username {
					http.Error(w, "forbidden", http.StatusForbidden)
					return
				}
				if !exists {
					owner, ok := adminUsers.get(sess.Username)
					used, quotaErr := countOwnedQuotaAcrossManagedServers(ctx, store, sess.Username)
					if quotaErr != nil {
						http.Error(w, "could not verify reseller quota", http.StatusBadGateway)
						return
					}
					if ok && owner.MaxUsers > 0 && used >= owner.MaxUsers {
						http.Error(w, fmt.Sprintf("user limit reached (%d)", owner.MaxUsers), http.StatusForbidden)
						return
					}
				}
				p.OwnerUsername = sess.Username
			}
			p.ServerID = ""
			body, _ := json.Marshal(p)
			status, data, ct, err := proxyManagedServer(ctx, ms, http.MethodPost, "/api/users/create", body, "application/json")
			if err != nil {
				http.Error(w, "remote server error: "+err.Error(), http.StatusBadGateway)
				return
			}
			writeProxyResponse(w, status, data, ct)
			return
		}

		sess := sessionFromCtx(ctx)
		if sess != nil && sess.Role == RoleReseller {
			var existingOwner string
			err := store.db.QueryRowContext(ctx, `SELECT owner_username FROM ssh_users WHERE username=$1`, p.Username).Scan(&existingOwner)
			if err != nil && err != sql.ErrNoRows {
				http.Error(w, "db error", http.StatusInternalServerError)
				return
			}
			if err == nil && existingOwner != sess.Username {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}

		// Decide what password to use:
		// - if payload has non-empty password -> use it
		// - else try to read existing password from DB
		//   - if user exists -> keep existing password
		//   - if not exists and TOTP is enabled -> allow blank password
		//   - otherwise reject (password required for new user)
		var password string

		if p.Password != nil && *p.Password != "" {
			password = *p.Password
		} else {
			var existing string
			err := store.db.QueryRowContext(ctx,
				`SELECT password FROM ssh_users WHERE username = $1`,
				p.Username,
			).Scan(&existing)

			if err == sql.ErrNoRows {
				// PAM users authenticate against the system account, so they
				// need neither a panel password nor a TOTP secret.
				if strings.TrimSpace(p.TOTPSecret) == "" && !usePAM {
					http.Error(w, "password or totp_secret required for new user", http.StatusBadRequest)
					return
				}
				password = ""
			} else if err != nil {
				log.Printf("failed to load existing password for %s: %v", p.Username, err)
				http.Error(w, "db error", http.StatusInternalServerError)
				return
			} else {
				password = existing
			}
		}

		// Determine owner and enforce reseller quota
		ownerUsername := ""
		if sess != nil && sess.Role == RoleReseller {
			ownerUsername = sess.Username
			// Enforce user limit — only count on new user creation
			var existsInDB bool
			_ = store.db.QueryRowContext(ctx,
				`SELECT TRUE FROM ssh_users WHERE username=$1`, p.Username,
			).Scan(&existsInDB)
			if !existsInDB {
				owner, ok := adminUsers.get(sess.Username)
				used, quotaErr := countOwnedQuotaAcrossManagedServers(ctx, store, sess.Username)
				if quotaErr != nil {
					http.Error(w, "could not verify reseller quota", http.StatusBadGateway)
					return
				}
				if ok && owner.MaxUsers > 0 && used >= owner.MaxUsers {
					http.Error(w, fmt.Sprintf("user limit reached (%d)", owner.MaxUsers), http.StatusForbidden)
					return
				}
			}
		} else if sess != nil && sess.Role == RoleSuperAdmin && strings.TrimSpace(p.OwnerUsername) != "" {
			ownerUsername = strings.TrimSpace(p.OwnerUsername)
		}

		cfg := UserConfig{
			Username:            p.Username,
			Password:            password,
			MaxConnections:      p.MaxConnections,
			ExpiresAt:           p.ExpiresAt,
			LimitMbpsUp:         p.LimitUpMbps,
			LimitMbpsDown:       p.LimitDownMbps,
			DataQuotaBytes:      p.DataQuotaBytes,
			QuotaAction:         normalizeQuotaAction(p.QuotaAction),
			QuotaThrottleMbps:   quotaThrottleMbpsOrDefault(p.QuotaThrottleMbps),
			TOTPSecret:          strings.TrimSpace(p.TOTPSecret),
			TOTPPeriod:          p.TOTPPeriod,
			TOTPWindow:          p.TOTPWindow,
			TOTPDigits:          p.TOTPDigits,
			AllowStaticPassword: p.AllowStaticPassword,
			UsePAM:              usePAM,
			OwnerUsername:       ownerUsername,
		}

		if err := store.UpsertUser(ctx, cfg); err != nil {
			log.Printf("failed to upsert user: %v", err)
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		// Force-disconnect all active sessions for this user so new config applies.
		userMgr.DisconnectUser(p.Username)
		if p.ResetUsage {
			if err := resetSSHUserTrafficAccounting(ctx, store, p.Username); err != nil {
				http.Error(w, "could not reset usage", http.StatusInternalServerError)
				return
			}
		}

		reloadUsersFromDB(ctx, store)
		w.WriteHeader(http.StatusCreated)
	}
}

func handleResetUserTraffic(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if store == nil {
			http.Error(w, "database not configured", http.StatusServiceUnavailable)
			return
		}

		var req struct {
			Username string `json:"username"`
			ServerID string `json:"server_id,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		req.Username = strings.TrimSpace(req.Username)
		if req.Username == "" {
			http.Error(w, "username required", http.StatusBadRequest)
			return
		}

		ctx := r.Context()
		if ms, remote, err := managedServerFromID(ctx, store, req.ServerID); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} else if remote {
			if sess := sessionFromCtx(ctx); sess != nil && sess.Role == RoleReseller && !remoteSSHUserOwned(ctx, ms, req.Username, sess.Username) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			req.ServerID = ""
			body, _ := json.Marshal(req)
			status, data, ct, err := proxyManagedServer(ctx, ms, http.MethodPost, "/api/users/reset-traffic", body, "application/json")
			if err != nil {
				http.Error(w, "remote server error: "+err.Error(), http.StatusBadGateway)
				return
			}
			writeProxyResponse(w, status, data, ct)
			return
		}

		var owner string
		if err := store.db.QueryRowContext(ctx, `SELECT owner_username FROM ssh_users WHERE username=$1`, req.Username).Scan(&owner); err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "user not found", http.StatusNotFound)
			} else {
				http.Error(w, "db error", http.StatusInternalServerError)
			}
			return
		}
		if sess := sessionFromCtx(ctx); sess != nil && sess.Role == RoleReseller && strings.TrimSpace(owner) != sess.Username {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		if err := resetSSHUserTrafficAccounting(ctx, store, req.Username); err != nil {
			log.Printf("failed to reset SSH traffic for %s: %v", req.Username, err)
			http.Error(w, "could not reset traffic", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "username": req.Username})
	}
}

func handleDeleteUser(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if store == nil {
			http.Error(w, "database not configured", http.StatusServiceUnavailable)
			return
		}

		username := r.URL.Query().Get("username")
		if username == "" {
			http.Error(w, "username required", http.StatusBadRequest)
			return
		}

		ctx := r.Context()
		if ms, remote, err := managedServerFromID(ctx, store, requestedServerID(r)); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} else if remote {
			if sess := sessionFromCtx(ctx); sess != nil && sess.Role == RoleReseller && !remoteSSHUserOwned(ctx, ms, username, sess.Username) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			remotePath := "/api/users/delete?username=" + url.QueryEscape(username)
			status, data, ct, err := proxyManagedServer(ctx, ms, http.MethodDelete, remotePath, nil, "application/json")
			if err != nil {
				http.Error(w, "remote server error: "+err.Error(), http.StatusBadGateway)
				return
			}
			writeProxyResponse(w, status, data, ct)
			return
		}

		// Resellers may only delete their own users
		sess := sessionFromCtx(ctx)
		if sess != nil && sess.Role == RoleReseller {
			u, ok := userMgr.Get(username)
			if !ok || u.Cfg.OwnerUsername != sess.Username {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}

		if err := store.DeleteUser(ctx, username); err != nil {
			log.Printf("failed to delete user: %v", err)
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}

		// Kick any live sessions for that user
		userMgr.DisconnectUser(username)

		reloadUsersFromDB(ctx, store)
		w.WriteHeader(http.StatusNoContent)
	}
}

// ---------- Stats API handler ----------

func handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if proxyManagedServerFromRequest(w, r, statsStore, "/api/stats", nil, "") {
		return
	}
	stats := getCurrentStats()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(stats)
}

// handleDnsttStats returns the most recent DNSTT statistics snapshot.  These
// counters represent activity in the last 5‑second window.  The handler
// requires a GET request and is protected by the same bearer token as
// other admin API endpoints.
func handleDnsttStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if proxyManagedServerFromRequest(w, r, statsStore, "/api/dnstt", nil, "") {
		return
	}
	// Obtain a copy of the current snapshot.
	stats := GetDNSTTStatsSnapshot()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(stats)
}

// handleDnsttLogs returns the recent DNSTT log lines as a JSON array of strings.
// If DNSTT logging has not been initialised, it returns an empty array.  The
// handler requires a GET request and uses the same bearer token as other
// admin endpoints.
func handleDnsttLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	lines := getDNSTTLogLines()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(lines)
}

// handleBHTTPStats returns the current BHTTP transport counters.
func handleBHTTPStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if proxyManagedServerFromRequest(w, r, statsStore, "/api/bhttp", nil, "") {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(GetBHTTPStatsSnapshot())
}

// handleBHTTPLogs returns the recent BHTTP log lines as a JSON array.
func handleBHTTPLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	lines := getBHTTPLogLines()
	if lines == nil {
		lines = []string{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(lines)
}

// handleHCRStats returns the current HCR transport counters.
func handleHCRStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if proxyManagedServerFromRequest(w, r, statsStore, "/api/hcr", nil, "") {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(GetHCRStatsSnapshot())
}

// handleHCRLogs returns the recent HCR log lines as a JSON array.
func handleHCRLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	lines := getHCRLogLines()
	if lines == nil {
		lines = []string{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(lines)
}

// handleBTUNStats returns the current BTUN protocol server counters.
func handleBTUNStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if proxyManagedServerFromRequest(w, r, statsStore, "/api/btun", nil, "") {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(GetBTUNStatsSnapshot())
}

// handleBTUNLogs returns the recent BTUN log lines as a JSON array.
func handleBTUNLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	lines := getBTUNLogLines()
	if lines == nil {
		lines = []string{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(lines)
}

// ---------- Auth helpers ----------

func normalizeBase32Secret(secret string) string {
	secret = strings.ToUpper(strings.TrimSpace(secret))
	secret = strings.ReplaceAll(secret, " ", "")
	return secret
}

func totpDigitsOrDefault(n int) int {
	if n < 6 || n > 8 {
		return 6
	}
	return n
}

func totpPeriodOrDefault(n int) int64 {
	if n <= 0 {
		return 60
	}
	return int64(n)
}

func totpWindowOrDefault(n int) int {
	if n < 0 {
		return 0
	}
	if n == 0 {
		return 1
	}
	return n
}

func pow10(n int) uint32 {
	v := uint32(1)
	for i := 0; i < n; i++ {
		v *= 10
	}
	return v
}

func generateTOTPCode(secret string, ts time.Time, period int64, digits int) (string, error) {
	secret = normalizeBase32Secret(secret)
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return "", fmt.Errorf("decode TOTP secret: %w", err)
	}
	counter := uint64(ts.Unix() / period)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	h := hmac.New(sha1.New, key)
	_, _ = h.Write(buf[:])
	sum := h.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	mod := pow10(digits)
	return fmt.Sprintf("%0*d", digits, code%mod), nil
}

func matchTOTPPassword(u *UserState, supplied string, now time.Time) bool {
	secret := strings.TrimSpace(u.Cfg.TOTPSecret)
	if secret == "" {
		return false
	}
	period := totpPeriodOrDefault(u.Cfg.TOTPPeriod)
	digits := totpDigitsOrDefault(u.Cfg.TOTPDigits)
	window := totpWindowOrDefault(u.Cfg.TOTPWindow)
	for i := -window; i <= window; i++ {
		stepTime := now.Add(time.Duration(i) * time.Duration(period) * time.Second)
		code, err := generateTOTPCode(secret, stepTime, period, digits)
		if err != nil {
			log.Printf("user %s has invalid TOTP configuration: %v", u.Cfg.Username, err)
			return false
		}
		if supplied == code {
			return true
		}
	}
	return false
}

// ---------- Auth callbacks ----------

func passwordCallback(meta ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
	supplied := string(pass)
	u, ok := userMgr.Get(meta.User())
	now := time.Now()

	// Enforce panel policy (expiry / reseller owner) for known users up front,
	// so neither PAM nor the static password can bypass it.
	if ok {
		if u.ExpiresAt != nil && now.After(*u.ExpiresAt) {
			log.Printf("user %s tried to connect but account is expired", meta.User())
			return nil, fmt.Errorf("account expired")
		}
		if sshUserQuotaBlocked(u) {
			log.Printf("user %s tried to connect after reaching the data quota", meta.User())
			return nil, errDataQuotaExceeded
		}
		if err := ownerIsActive(u.Cfg.OwnerUsername); err != nil {
			return nil, fmt.Errorf("authentication failed: %w", err)
		}
	}

	// System (PAM) login. When enabled server-wide, the Linux system password
	// (/etc/shadow) is accepted for any regular account (UID >= 1000) — whether
	// or not it is already a panel user. Unknown accounts are auto-imported on
	// success. Falls through to panel credentials if PAM does not accept.
	if isPAMAuthEnabled() {
		if isRegularLoginUser(meta.User()) {
			if err := authenticatePAM(meta.User(), supplied); err == nil {
				if !ok {
					importPAMUser(meta.User())
				}
				pamLogf("PAM: %q authenticated against /etc/shadow", meta.User())
				return nil, nil
			} else {
				pamLogf("PAM: %q rejected by /etc/shadow: %v", meta.User(), err)
			}
		} else if !ok {
			pamLogf("PAM: %q is not a regular login account (needs an /etc/passwd entry with UID >= %d)", meta.User(), minLoginUID)
		}
	}

	if !ok {
		pamLogf("auth: user %q rejected (no panel account and PAM did not accept it)", meta.User())
		return nil, fmt.Errorf("authentication failed")
	}

	// Fall back to panel-managed credentials (TOTP and/or static password).
	if strings.TrimSpace(u.Cfg.TOTPSecret) != "" {
		if matchTOTPPassword(u, supplied, now) {
			return nil, nil
		}
		if u.Cfg.AllowStaticPassword && u.Cfg.Password == supplied {
			return nil, nil
		}
		return nil, fmt.Errorf("authentication failed")
	}
	if u.Cfg.Password != supplied {
		return nil, fmt.Errorf("authentication failed")
	}
	return nil, nil
}

func publicKeyCallback(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	u, ok := userMgr.Get(meta.User())
	if !ok {
		return nil, fmt.Errorf("authentication failed")
	}
	if u.ExpiresAt != nil && time.Now().After(*u.ExpiresAt) {
		log.Printf("user %s tried to connect but account is expired", meta.User())
		return nil, fmt.Errorf("account expired")
	}
	if sshUserQuotaBlocked(u) {
		return nil, errDataQuotaExceeded
	}
	if err := ownerIsActive(u.Cfg.OwnerUsername); err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}
	if u.PubKey == nil {
		return nil, fmt.Errorf("no public key configured")
	}
	if !publicKeysEqual(u.PubKey, key) {
		return nil, fmt.Errorf("authentication failed")
	}
	return nil, nil
}

// ---------- Connection handling ----------

func handleConn(tcpConn net.Conn, config *ssh.ServerConfig) {
	trackedConn := newActivityConn(tcpConn)
	defer trackedConn.Close()

	// Global connection cap: reject before the expensive SSH handshake so a
	// surge past normal load cannot exhaust memory/CPU. Count first, then check,
	// so the defer always balances the increment.
	live := atomic.AddInt64(&activeSSHConns, 1)
	defer atomic.AddInt64(&activeSSHConns, -1)
	if lim := atomic.LoadInt64(&maxTotalConns); lim > 0 && live > lim {
		r := atomic.AddInt64(&sshConnsRejected, 1)
		if r == 1 || r%1000 == 0 {
			log.Printf("ssh: global connection cap reached (%d); rejected %d connection(s) so far", lim, r)
		}
		return
	}

	// Prevent goroutine leaks from clients that connect but never complete the SSH handshake.
	_ = trackedConn.SetReadDeadline(time.Now().Add(sshHandshakeTimeout))

	sshConn, chans, reqs, err := ssh.NewServerConn(trackedConn, config)
	if err != nil {
		log.Println("ssh handshake failed:", err)
		return
	}
	// Clear deadlines after a successful handshake. Runtime cleanup is handled
	// by monitorSSHIdle, which checks traffic in both directions.
	_ = trackedConn.SetDeadline(time.Time{})
	username := sshConn.User()
	log.Printf("new SSH connection from %s as %s", sshConn.RemoteAddr(), username)

	u, ok := userMgr.Get(username)
	if !ok {
		log.Printf("user %s not found in config (should not happen if auth is correct)", username)
		sshConn.Close()
		return
	}

	// Track active connection and enforce max_connections. The connection map is
	// treated as the source of truth so stale counters can self-heal.
	u.mu.Lock()
	if u.conns == nil {
		u.conns = make(map[*ssh.ServerConn]struct{})
	}
	// BTUN sessions count against the same allowance, so a user cannot double
	// their limit by mixing transports.
	activeConns := len(u.conns) + u.btunConns
	u.ActiveConns = activeConns
	if u.Cfg.MaxConnections > 0 && activeConns >= u.Cfg.MaxConnections {
		u.mu.Unlock()
		log.Printf("user %s exceeded max_connections (%d)", username, u.Cfg.MaxConnections)
		sshConn.Close()
		return
	}
	u.conns[sshConn] = struct{}{}
	u.ActiveConns = len(u.conns) + u.btunConns
	u.mu.Unlock()

	// Use per-user limit if set; otherwise fall back to the global config default.
	limitUp, limitDown := u.Cfg.LimitMbpsUp, u.Cfg.LimitMbpsDown
	if limitUp == 0 || limitDown == 0 {
		defUp, defDown := getDefaultLimits()
		if limitUp == 0 {
			limitUp = defUp
		}
		if limitDown == 0 {
			limitDown = defDown
		}
	}
	var upLimiter, downLimiter *rate.Limiter
	if limitUp > 0 {
		bps := mbpsToBytesPerSec(limitUp)
		upLimiter = rate.NewLimiter(rate.Limit(bps), int(bps))
	}
	if limitDown > 0 {
		bps := mbpsToBytesPerSec(limitDown)
		downLimiter = rate.NewLimiter(rate.Limit(bps), int(bps))
	}

	updateUserDisplay()

	idleDone := make(chan struct{})
	if idleTimeout := getSSHIdleTimeout(); idleTimeout > 0 {
		go monitorSSHIdle(trackedConn, sshConn, username, idleTimeout, idleDone)
	}

	defer func() {
		close(idleDone)
		u.mu.Lock()
		delete(u.conns, sshConn)
		u.ActiveConns = len(u.conns) + u.btunConns
		u.mu.Unlock()

		updateUserDisplay()
		sshConn.Close()
	}()

	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		switch newChan.ChannelType() {
		case "direct-tcpip":
			go handleDirectTCPIP(newChan, u, upLimiter, downLimiter)
		case "session":
			go handleDummySession(newChan)
		default:
			newChan.Reject(ssh.UnknownChannelType, "unsupported channel type")
		}
	}
}

type directTCPIPReq struct {
	Host       string
	Port       uint32
	OriginAddr string
	OriginPort uint32
}

func handleDirectTCPIP(newChan ssh.NewChannel, u *UserState, upLimiter, downLimiter *rate.Limiter) {
	if sshUserQuotaBlocked(u) {
		newChan.Reject(ssh.Prohibited, "data quota exceeded")
		return
	}
	var req directTCPIPReq
	if err := ssh.Unmarshal(newChan.ExtraData(), &req); err != nil {
		newChan.Reject(ssh.Prohibited, "bad direct-tcpip request")
		return
	}

	target := net.JoinHostPort(req.Host, strconv.FormatUint(uint64(req.Port), 10))
	log.Printf("direct-tcpip: user=%s connecting to %s from %s:%d",
		u.Cfg.Username, target, req.OriginAddr, req.OriginPort)

	dialer := &net.Dialer{Timeout: directTCPIPDialTimeout, KeepAlive: 30 * time.Second}
	backend, err := dialer.Dial("tcp", target)
	if err != nil {
		log.Printf("failed to connect to %s: %v", target, err)
		newChan.Reject(ssh.ConnectionFailed, err.Error())
		return
	}

	ch, reqs, err := newChan.Accept()
	if err != nil {
		_ = backend.Close()
		return
	}

	// Shared closer: when either copy direction finishes (including a
	// half-close that never completes), both sides are force-closed so the
	// other direction unblocks. Close is idempotent, so calling it from both
	// directions is safe and no separate waiter goroutine is needed.
	ctx, cancel := context.WithCancel(context.Background())
	var closeOnce sync.Once
	closeAll := func() {
		closeOnce.Do(func() {
			cancel()
			_ = backend.Close()
			_ = ch.Close()
		})
	}

	// Drain channel requests concurrently so the peer isn't left waiting.
	go func() {
		for req := range reqs {
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}()

	// upstream: SSH channel -> backend, in its own goroutine.
	go func() {
		_, _ = copyWithRateLimitContext(ctx, sshQuotaWriter{w: backend, user: u, uplink: true, ctx: ctx}, ch, upLimiter)
		// Signal to the backend that we are done writing.
		if cw, ok := backend.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		closeAll()
	}()

	// downstream: backend -> SSH channel, run in this goroutine.
	// handleDirectTCPIP already runs as its own goroutine (see handleConn),
	// so reusing it here avoids spawning a third goroutine per channel.
	_, _ = copyWithRateLimitContext(ctx, sshQuotaWriter{w: ch, user: u, uplink: false, ctx: ctx}, backend, downLimiter)
	closeAll()
}

func handleDummySession(newChan ssh.NewChannel) {
	ch, reqs, err := newChan.Accept()
	if err != nil {
		return
	}

	go func() {
		defer ch.Close()
		for req := range reqs {
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}()
}

// ---------- UI / display ----------

func updateUserDisplay() {
	if !userCountEnabled {
		return
	}

	userStates := userMgr.List()
	parts := make([]string, 0, len(userStates))
	for _, u := range userStates {
		u.mu.Lock()
		c := len(u.conns) + u.btunConns
		u.ActiveConns = c
		name := u.Cfg.Username
		u.mu.Unlock()
		parts = append(parts, fmt.Sprintf("%s: %d", name, c))
	}

	sort.Strings(parts)
	line := strings.Join(parts, "  ")
	if line == "" {
		line = "no users"
	}

	displayMu.Lock()
	defer displayMu.Unlock()

	if len(line) < lastDisplayLen {
		line = line + strings.Repeat(" ", lastDisplayLen-len(line))
	}
	lastDisplayLen = len(line)

	fmt.Printf("\r%s", line)
}

// ---------- Main ----------

// ========================
// Port-80 HTTP-clean + SSH
// ========================

// bufferedConn is a net.Conn wrapper whose Read() is served by a bufio.Reader.
// This preserves any bytes already buffered/peeked during HTTP cleanup.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// handleHTTP80Conn applies the same "HTTP injection cleanup" that proxy.go did,
// then hands the cleaned connection directly to the SSH server handler, avoiding
// the extra io.Copy hop to a separate backend SSH process.
func handleHTTP80Conn(raw net.Conn, sshConfig *ssh.ServerConfig) {
	// Best-effort TCP tuning (no hard dependency on TCPConn)
	if tc, ok := raw.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
		_ = tc.SetNoDelay(true)
	}

	// 101 response up-front (keeps behavior identical to the old proxy)
	status := "Switching Protocols"
	_, _ = raw.Write([]byte(fmt.Sprintf("HTTP/1.1 101 %s\r\n\r\n", status)))

	skip200 := false
	br := bufio.NewReaderSize(raw, 4<<10)

	// Drain chained HTTP header blocks with a short rolling deadline so Peek/ReadBytes never stalls.
	cleanWindow := 30 * time.Second
	_ = raw.SetReadDeadline(time.Now().Add(cleanWindow))

	for {
		// swallow stray CR/LF between chained blocks
		if skipped, _ := eatLeadingEOL(br); skipped > 0 {
			log.Printf("[CLEAN] skipped %d EOL bytes between blocks", skipped)
		}

		if lit, _ := eatLiteralBackslashCRLF(br); lit > 0 {
			log.Printf("[CLEAN] skipped %d bytes of literal \"\\r\\n\"", lit)
			// keep rolling the deadline since we consumed data
			_ = raw.SetReadDeadline(time.Now().Add(cleanWindow))
			// continue to try cleaning more
			continue
		}
		if litN, _ := eatLiteralBackslashLF(br); litN > 0 {
			log.Printf("[CLEAN] skipped %d bytes of literal \"\\n\"", litN)
			_ = raw.SetReadDeadline(time.Now().Add(cleanWindow))
			continue
		}

		// peek a bit more so we can classify reliably
		size := 8
		if b := br.Buffered(); b > 0 && b < size {
			size = b
		}
		if size < 1 {
			size = 1
		}

		peek, err := br.Peek(size)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				log.Printf("[CLEAN] timeout; pass-through next=%s", peekPreview(br, 64))
				break
			}
			if err == io.EOF {
				// Normal when payload stops. Proceed.
				log.Printf("[CLEAN] EOF; nothing left")
				break
			}
			log.Println("[CLEAN] peek error:", err)
			break
		}

		// Fast path: HTTP-ish at offset 0 (request-line OR status-line)
		if maybeHTTPStartPrefix(peek) {
			firstLine, headers, err := discardAndCaptureHTTP(br)
			if err != nil {
				log.Println("[CLEAN] discard error:", err)
				break
			}
			if headerHasValue(headers, "npv-x", "ok") {
				cleanWindow = 2 * time.Second
				_ = raw.SetReadDeadline(time.Now().Add(cleanWindow))
				skip200 = true
				status = "OK"
				_, err = raw.Write([]byte(fmt.Sprintf("HTTP/1.1 200 %s\r\n\r\n", status)))
				if err != nil {
					log.Println("Failed to write 200 OK:", err)
					return
				}
				log.Printf("[CLEAN] NPV-X: OK; promote clean window to %s", cleanWindow)
			}
			if bytes.Contains(bytes.ToLower(headers), []byte("x-skip: 200")) {
				skip200 = true
				log.Printf("[CLEAN] detected and stripped X-Skip: 200 header")
			}
			log.Printf("[CLEAN] discarded HTTP block: %q", firstLine)
			_ = raw.SetReadDeadline(time.Now().Add(cleanWindow))
			continue
		}

		// Slow path: scan the already-buffered bytes for a later HTTP token
		if bufN := br.Buffered(); bufN > 0 {
			pbuf, _ := br.Peek(bufN)

			// If we see SSH banner soon, stop cleaning now
			if iSSH := bytes.Index(pbuf, []byte("SSH-")); iSSH >= 0 && iSSH < 64 {
				log.Printf("[CLEAN] SSH banner detected at +%d; stop cleaning", iSSH)
				log.Printf("[CLEAN] pass-through begins; next=%s", peekPreview(br, 64))
				break
			}

			if pos := findHTTPStartIndex(pbuf); pos > 0 {
				// 1) discard junk prefix before the HTTP token
				noise := make([]byte, pos)
				if _, err := io.ReadFull(br, noise); err != nil {
					log.Printf("[CLEAN] error discarding noise prefix: %v", err)
					break
				}
				log.Printf("[CLEAN] discarded NOISE prefix (%d bytes): %q (hex:%s)",
					pos, asciiPreview(noise, 64), hexPreview(noise, 64))

				// 2) discard the HTTP block starting at current position
				firstLine, err := discardOneHTTP(br)
				if err != nil {
					log.Printf("[CLEAN] discard error after noise: %v", err)
					break
				}
				log.Printf("[CLEAN] discarded HTTP block after noise: %q", firstLine)
				_ = raw.SetReadDeadline(time.Now().Add(cleanWindow))
				continue
			}

			// No HTTP tokens; pass-through whatever remains
			log.Printf("[CLEAN] pass-through begins; next=%s", peekPreview(br, 64))
		} else {
			log.Printf("[CLEAN] pass-through (no buffered data)")
		}
		break
	}

	if skip200 {
		log.Printf("[SKIP] X-Skip: 200 detected earlier; not sending 200 OK")
	} else {
		status = "OK"
		_, err := raw.Write([]byte(fmt.Sprintf("HTTP/1.1 200 %s\r\n\r\n", status)))
		if err != nil {
			log.Println("Failed to write 200 OK:", err)
			return
		}
	}

	// Clear deadline before SSH handshake begins.
	_ = raw.SetReadDeadline(time.Time{})

	// A tunnel client may use an HTTP request as cover, exactly like the
	// injection clients this cleanup exists for. The cleanup above consumed
	// that cover and already answered 101/200, so what remains is either the
	// SSH banner or a tunnel handshake; only the latter is handed over.
	if tunnelShareEnabled() {
		reader, taken := tunnelTakeSharedConn(raw, br)
		if taken {
			return
		}
		br = reader
	}

	// Hand off to SSH server, ensuring any buffered bytes are preserved.
	handleConn(&bufferedConn{Conn: raw, r: br}, sshConfig)
}

// serveHTTP80 accepts connections on ln and dispatches each to
// handleHTTP80Conn.  It logs accept errors but otherwise runs
// indefinitely.  This helper is used to support multiple listen
// addresses without duplicating accept loop code.
func serveHTTP80(ln net.Listener) {
	for {
		tcpConn, err := ln.Accept()
		if err != nil {
			if isListenerClosed(err) {
				return
			}
			log.Printf("accept error on %s: %v", ln.Addr().String(), err)
			continue
		}
		go handleProxyConn(tcpConn, getSSHConfig())
	}
}

// handleProxyConn owns one connection accepted on a public proxy port. When
// BHTTP shares these ports it gets first look, because a BHTTP client speaks
// immediately and must not receive the unsolicited "HTTP/1.1 101" that the
// HTTP-injection path opens with. Anything that is not a BHTTP frame falls
// through to handleHTTP80Conn with its bytes untouched.
func handleProxyConn(raw net.Conn, sshConfig *ssh.ServerConfig) {
	// Best-effort TCP tuning here too: the sniff may wrap the connection, and
	// handleHTTP80Conn's own type assertion would then no longer see a TCPConn.
	if tc, ok := raw.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
		_ = tc.SetNoDelay(true)
	}
	if !tunnelShareEnabled() && !nativeSharedEnabled() {
		handleHTTP80Conn(raw, sshConfig)
		return
	}
	reader, taken := tunnelTakeSharedConn(raw, nil)
	if taken {
		return
	}
	reader, taken = nativeTakeSharedConn(raw, reader)
	if taken {
		return
	}
	handleHTTP80Conn(&bufferedConn{Conn: raw, r: reader}, sshConfig)
}

// serveRawSSH accepts connections on ln and passes each directly into
// handleConn.  Unlike serveHTTP80 it does not perform HTTP cleanup
// and starts the SSH handshake immediately. This is used by local proxy and
// tunnel daemons that need a stable SSH upstream.
func serveRawSSH(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if isListenerClosed(err) {
				return
			}
			log.Printf("local accept error on %s: %v", ln.Addr().String(), err)
			continue
		}
		go handleConn(c, getSSHConfig())
	}
}

// serveTLSSSH accepts TLS-wrapped connections on ln.  It forces a
// TLS handshake on each accepted connection so handshake failures are
// surfaced early, then passes the decrypted stream to handleConn.
// There is no backend dial or data copying; the SSH handler runs
// directly on the TLS stream.
func serveTLSSSH(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if isListenerClosed(err) {
				return
			}
			log.Printf("tls accept error on %s: %v", ln.Addr().String(), err)
			continue
		}
		go func(client net.Conn) {
			_ = client.SetDeadline(time.Now().Add(tlsHandshakeTimeout))
			if tc, ok := client.(*tls.Conn); ok {
				if err := tc.Handshake(); err != nil {
					log.Printf("tls handshake error from %s: %v", client.RemoteAddr().String(), err)
					_ = client.Close()
					return
				}
			}
			_ = client.SetDeadline(time.Time{})
			if nativeSharedEnabled() {
				reader, taken := nativeTakeSharedConn(client, nil)
				if taken {
					return
				}
				client = &bufferedConn{Conn: client, r: reader}
			}
			// Inside TLS the stream is either the SSH banner or, when a tunnel
			// transport shares this port, its handshake. The sniff decides on
			// the decrypted bytes, so the TLS certificate and SNI are untouched.
			if tunnelShareEnabled() {
				reader, taken := tunnelTakeSharedConn(client, nil)
				if taken {
					return
				}
				handleConn(&bufferedConn{Conn: client, r: reader}, getSSHConfig())
				return
			}
			handleConn(client, getSSHConfig())
		}(c)
	}
}

var httpMethods = [][]byte{
	// HTTP/1.1 + PATCH
	[]byte("GET "), []byte("HEAD "), []byte("POST "), []byte("PUT "),
	[]byte("DELETE "), []byte("CONNECT "), []byte("OPTIONS "), []byte("TRACE "),
	[]byte("PATCH "),

	// WebDAV (RFC 4918)
	[]byte("PROPFIND "), []byte("PROPPATCH "), []byte("MKCOL "),
	[]byte("COPY "), []byte("MOVE "), []byte("LOCK "), []byte("UNLOCK "),

	// WebDAV SEARCH (RFC 5323)
	[]byte("SEARCH "),

	// WebDAV ACL (RFC 3744)
	[]byte("ACL "),

	// WebDAV Versioning/DeltaV (RFC 3253)
	[]byte("VERSION-CONTROL "), []byte("REPORT "), []byte("CHECKOUT "),
	[]byte("CHECKIN "), []byte("UNCHECKOUT "), []byte("MKWORKSPACE "),
	[]byte("UPDATE "), []byte("LABEL "), []byte("MERGE "),
	[]byte("BASELINE-CONTROL "), []byte("MKACTIVITY "),

	// WebDAV Ordering (RFC 3648)
	[]byte("ORDERPATCH "),

	// WebDAV Bindings (RFC 5842)
	[]byte("BIND "), []byte("UNBIND "), []byte("REBIND "),

	// CalDAV (RFC 4791)
	[]byte("MKCALENDAR "),

	[]byte("x-skip: "),
	[]byte("npv-x: "),
}

func eatLeadingEOL(br *bufio.Reader) (int, error) {
	n := 0
	for {
		b, err := br.Peek(1)
		if err != nil {
			return n, err
		}
		if b[0] != '\r' && b[0] != '\n' {
			return n, nil
		}
		if _, err := br.ReadByte(); err != nil {
			return n, err
		}
		n++
	}
}

func asciiPreview(b []byte, max int) string {
	if len(b) > max {
		b = b[:max]
	}
	out := make([]byte, len(b))
	for i, c := range b {
		if c < 32 || c == 127 {
			out[i] = '.'
		} else {
			out[i] = c
		}
	}
	return string(out)
}

func peekPreview(br *bufio.Reader, max int) string {
	n := br.Buffered()
	if n < 1 {
		n = max
	}
	if n > max {
		n = max
	}
	p, _ := br.Peek(n)
	return fmt.Sprintf("%q (hex:% X)", asciiPreview(p, n), p)
}

func httpStartTokens() [][]byte {
	toks := [][]byte{
		[]byte("HTTP/"), []byte("HTTP/1."), []byte("HTTP/2"), []byte("HTTP/3"),
		[]byte("PRI "), []byte("ICY "),
	}
	toks = append(toks, httpMethods...)
	toks = append(toks, []byte("CONNECT")) // bare
	return toks
}

func findHTTPStartIndex(b []byte) int {
	if len(b) == 0 {
		return -1
	}
	upper := bytes.ToUpper(b)
	min := -1
	for _, t := range httpStartTokens() {
		tu := bytes.ToUpper(t)
		if idx := bytes.Index(upper, tu); idx >= 0 {
			if min == -1 || idx < min {
				min = idx
			}
		}
	}
	return min
}

func hexPreview(b []byte, max int) string {
	if len(b) > max {
		b = b[:max]
	}
	return fmt.Sprintf("% X", b)
}

func eatLiteralBackslashCRLF(br *bufio.Reader) (int, error) {
	count := 0
	for {
		p, err := br.Peek(4)
		if err != nil {
			// If fewer than 4 bytes buffered, nothing more to eat.
			return count, nil
		}
		if len(p) >= 4 && p[0] == '\\' && p[1] == 'r' && p[2] == '\\' && p[3] == 'n' {
			if _, err := br.Discard(4); err != nil {
				return count, err
			}
			count += 4
			continue
		}
		return count, nil
	}
}

func eatLiteralBackslashLF(br *bufio.Reader) (int, error) {
	p, err := br.Peek(2)
	if err != nil || len(p) < 2 {
		return 0, nil
	}
	if p[0] == '\\' && p[1] == 'n' {
		if _, err := br.Discard(2); err != nil {
			return 0, err
		}
		return 2, nil
	}
	return 0, nil
}

func headerHasValue(headers []byte, key, want string) bool {
	lh := bytes.ToLower(headers)
	keyb := []byte(strings.ToLower(key))
	wantb := []byte(strings.ToLower(want))

	// find "<key>:" (allow spaces before colon too)
	i := bytes.Index(lh, keyb)
	for i >= 0 {
		rest := lh[i+len(keyb):]
		rest = bytes.TrimLeft(rest, " \t")
		if len(rest) > 0 && rest[0] == ':' {
			// slice to end-of-line
			line := rest[1:]
			if j := bytes.IndexByte(line, '\n'); j >= 0 {
				line = line[:j]
			}
			line = bytes.TrimSpace(bytes.TrimSuffix(line, []byte{'\r'}))
			return bytes.Equal(line, wantb)
		}
		// keep searching (avoid false positives on substrings)
		next := lh[i+len(keyb):]
		j := bytes.Index(next, keyb)
		if j < 0 {
			return false
		}
		i += len(keyb) + j
	}
	return false
}

func discardAndCaptureHTTP(br *bufio.Reader) (string, []byte, error) {
	const hardCap = 64 << 10 // 64 KiB
	var buf bytes.Buffer
	total := 0

	first, err := br.ReadSlice('\n')
	if err != nil {
		return "", nil, err
	}
	buf.Write(first)
	total += len(first)
	if total > hardCap {
		return "", nil, fmt.Errorf("http header too large")
	}

	for {
		line, err := br.ReadSlice('\n')
		if err != nil {
			return "", nil, err
		}
		total += len(line)
		if total > hardCap {
			return "", nil, fmt.Errorf("http header too large")
		}
		buf.Write(line)
		if (len(line) == 1 && line[0] == '\n') ||
			(len(line) == 2 && line[0] == '\r' && line[1] == '\n') {
			break
		}
	}
	fl := strings.TrimRight(string(first), "\r\n")
	return fl, buf.Bytes(), nil
}

func discardOneHTTP(br *bufio.Reader) (string, error) {
	const hardCap = 64 << 10 // 64 KiB
	total := 0

	// capture first line for printing
	first, err := br.ReadSlice('\n')
	if err != nil {
		return "", err
	}
	total += len(first)
	if total > hardCap {
		return "", fmt.Errorf("http header too large")
	}

	for {
		line, err := br.ReadSlice('\n')
		if err != nil {
			return "", err
		}
		total += len(line)
		if total > hardCap {
			return "", fmt.Errorf("http header too large")
		}

		// End of headers: "\n" or "\r\n"
		if (len(line) == 1 && line[0] == '\n') ||
			(len(line) == 2 && line[0] == '\r' && line[1] == '\n') {
			break
		}
	}
	// Trim trailing CR/LF for nicer logs
	fl := strings.TrimRight(string(first), "\r\n")
	return fl, nil
}

func maybeHTTPStartPrefix(b []byte) bool {
	u := bytes.ToUpper(b)

	// Helper: partial prefix match
	startsWithPartial := func(s string) bool {
		su := []byte(s)
		if len(u) <= len(su) {
			return bytes.Equal(u, su[:len(u)])
		}
		return bytes.HasPrefix(u, su)
	}

	// Status-lines / prefaces (allow partial)
	if startsWithPartial("HTTP/") || startsWithPartial("HTTP/1.") ||
		startsWithPartial("HTTP/2") || startsWithPartial("HTTP/3") ||
		startsWithPartial("PRI ") || startsWithPartial("ICY ") {
		return true
	}

	// Request-lines (methods) with partial match
	for _, m := range httpMethods {
		um := bytes.ToUpper(m)
		if len(u) <= len(um) && bytes.Equal(u, um[:len(u)]) { // partial ok
			return true
		}
		if len(u) >= len(um) && bytes.HasPrefix(u, um) {
			return true
		}
	}
	return false
}

func main() {
	if memTotal, _, err := readMemInfo(); err == nil && memTotal > 0 {
		limit := int64(memTotal) * 80 / 100
		debug.SetMemoryLimit(limit)
		log.Printf("GOMEMLIMIT auto-set to 80%% of RAM: %d MB", limit/1024/1024)
	}

	configPath := flag.String("config", "", "path to JSON config file (default: ./config.json if present, otherwise /opt/sshpanel/config.json)")
	quietFlag := flag.Bool("quiet", false, "override config and disable logs")
	userCountFlag := flag.Bool("usercount", false, "show per-user connection counters (single line)")
	hashAdminPasswordStdin := flag.Bool("hash-admin-password-stdin", false, "read an admin password from stdin and print a bcrypt hash")
	flag.Parse()
	if *hashAdminPasswordStdin {
		password, readErr := io.ReadAll(io.LimitReader(os.Stdin, 1025))
		if readErr != nil {
			log.Fatalf("read admin password: %v", readErr)
		}
		if err := validateAdminPassword(string(password)); err != nil {
			log.Fatal(err)
		}
		hash, hashErr := hashAdminPassword(string(password))
		if hashErr != nil {
			log.Fatal(hashErr)
		}
		fmt.Println(hash)
		return
	}

	resolvedConfigPath := resolveMainConfigPath(*configPath)
	cfg, userMap, err := loadConfig(resolvedConfigPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}
	userMgr.ReplaceAll(userMap)

	// Store config path and live config for hot-reload via admin API.
	globalCfgPath = resolvedConfigPath
	setGlobalCfg(cfg)

	userCountEnabled = cfg.UserCount || *userCountFlag

	var store *Store
	pgDSN := os.Getenv("PG_DSN")
	if pgDSN != "" {
		store, err = NewStore(pgDSN)
		if err != nil {
			log.Fatalf("failed to connect to postgres: %v", err)
		}

		ctx := context.Background()
		dbUsers, err := store.LoadUsers(ctx)
		if err != nil {
			log.Fatalf("failed to load users from database: %v", err)
		}
		if len(dbUsers) > 0 {
			userMgr.ReplaceAll(dbUsers)
		}
	}

	// Bootstrap admin users and reseller expiry checker.
	if store != nil {
		ctx := context.Background()
		if pw, err := store.BootstrapSuperAdmin(ctx); err != nil {
			log.Printf("failed to bootstrap superadmin: %v", err)
		} else if pw != "" {
			log.Printf("=== FIRST RUN: superadmin created — username: admin  password: %s ===", pw)
		}
		if err := loadAdminUsersIntoCache(ctx, store); err != nil {
			log.Printf("failed to load admin users: %v", err)
		}
		startResellerExpiryChecker(store)
		// Start the Telegram sales bot if enabled in the DB config.
		startBotService(store)
	}

	// Optional: initialize interface totals persistence (best-effort).
	if store != nil {
		statsStore = store
		startSSHUserTrafficFlusher(store)
		ctx := context.Background()
		if err := store.EnsureXrayClientsSchema(ctx); err != nil {
			log.Printf("xray clients table: %v", err)
		} else {
			if err := store.ResetXrayActiveConnections(ctx); err != nil {
				log.Printf("xray active connection reset: %v", err)
			}
			startXrayClientExpiryChecker(store)
		}
		if err := store.EnsureXrayConfigSchema(ctx); err != nil {
			log.Printf("xray config table disabled: %v", err)
		}
		if err := store.EnsureIfaceUsageTables(ctx); err != nil {
			log.Printf("vnstat usage tables disabled: %v", err)
		}
		if err := store.EnsureIfaceTotalsTable(ctx); err == nil {
			rows, err2 := store.LoadIfaceTotals(ctx)
			if err2 == nil {
				ifaceTotalsMgr = NewIfaceTotalsManager()
				ifaceTotalsMgr.Load(rows)

				// Bootstrap with current kernel counters once at startup
				if netMap, err3 := readNetDev(); err3 == nil {
					for name, ctrs := range netMap {
						ifaceTotalsMgr.ApplyKernel(name, ctrs.RxBytes, ctrs.TxBytes)
					}
				}
			} else {
				log.Printf("iface totals persistence disabled: %v", err2)
			}
		} else {
			log.Printf("iface totals persistence disabled: %v", err)
		}
	}

	// start background collector for CPU + interface stats
	primeCurrentStats()
	startStatsCollector()

	// Turn the per-account byte counters into live up/down speeds for the panel.
	startSSHUserRateSampler()

	adminAddr := os.Getenv("ADMIN_HTTP_ADDR")
	if adminAddr == "" {
		adminAddr = "127.0.0.1:9090"
	}
	startAdminAPI(store, adminAddr)

	// Start the integrated Xray-core subprocess if configured.
	initXrayManager(cfg.Xray)

	// Global banner text (from config or file) — stored in a global so the
	// admin API can update it on the fly without a restart.
	{
		bt := cfg.Banner
		if bt == "" && cfg.BannerFile != "" {
			if data, err := os.ReadFile(cfg.BannerFile); err == nil {
				bt = string(data)
			} else {
				log.Printf("failed to read banner file %s: %v", cfg.BannerFile, err)
			}
		}
		setBannerText(bt)
	}

	sshConfig := &ssh.ServerConfig{
		PasswordCallback:  passwordCallback,
		PublicKeyCallback: publicKeyCallback,
		NoClientAuth:      false,
	}

	// Optional compatibility mode for legacy SSH clients (weak algorithms).
	// Enable only if you must support older embedded/mobile SSH stacks.
	// Usage: SSH_LEGACY=1 ./server
	if os.Getenv("SSH_LEGACY") == "1" {
		sshConfig.Config = ssh.Config{
			Ciphers: []string{
				// Modern first
				"chacha20-poly1305@openssh.com",
				"aes128-ctr", "aes192-ctr", "aes256-ctr",
				// Legacy (weak)
				"aes128-cbc", "aes192-cbc", "aes256-cbc",
				"3des-cbc",
			},
			KeyExchanges: []string{
				// Modern first
				"curve25519-sha256", "curve25519-sha256@libssh.org",
				"diffie-hellman-group-exchange-sha256",
				// Legacy (weak)
				"diffie-hellman-group14-sha1",
				"diffie-hellman-group1-sha1",
			},
			MACs: []string{
				// Modern first
				"hmac-sha2-256", "hmac-sha2-512",
				// Legacy (weak)
				"hmac-sha1",
			},
		}
		log.Println("[SSH] legacy crypto enabled (weak algorithms allowed)")
	}

	// Fancy per-user banner:
	// - Optional global banner first
	// - Then block:
	//   Username: user
	//   -----------------
	//   Expiration: 10/12/2025
	//   -----------------
	//   Max Upload: 10 Mbps
	//   -----------------
	//   Max Download: 10 Mbps
	sshConfig.BannerCallback = func(meta ssh.ConnMetadata) string {
		var sb strings.Builder

		// Global / custom banner (reads live value so admin-panel edits apply immediately)
		if bt := getBannerText(); bt != "" {
			sb.WriteString(bt)
			if !strings.HasSuffix(bt, "\n") {
				sb.WriteString("\n")
			}
			sb.WriteString("\n") // extra blank line before user block
		}

		u, ok := userMgr.Get(meta.User())
		if !ok {
			// If user not found (should be rare), just return global banner
			return sb.String()
		}

		u.mu.Lock()
		exp := u.ExpiresAt
		maxConnections := u.Cfg.MaxConnections
		name := u.Cfg.Username
		u.mu.Unlock()

		// Date: dd/MM/yyyy
		expStr := "Sin límite"
		if exp != nil {
			expStr = exp.Local().Format("02/01/2006")
		}
		connStr := "Sin límite"
		if maxConnections > 0 {
			connStr = strconv.Itoa(maxConnections)
		}

		const sep = "---------------------------------------------------"
		sb.WriteString("\n<br>" + sep + "<br>\n")
		sb.WriteString("Información de la Cuenta")
		sb.WriteString("\n<br>" + sep + "<br>\n")
		sb.WriteString("👤 Usuario: ")
		sb.WriteString(name)
		sb.WriteString("\n<br><br>\n")
		sb.WriteString("📆 Vencimiento: ")
		sb.WriteString(expStr)
		sb.WriteString("\n<br><br>\n")
		sb.WriteString("📲 Límite de conexión: ")
		sb.WriteString(connStr)
		sb.WriteString("\n<br>" + sep + "<br>\n")
		return sb.String()
	}

	hostKeyBytes, err := os.ReadFile(cfg.HostKeyFile)
	if err != nil {
		log.Fatalf("failed to load host key %s: %v", cfg.HostKeyFile, err)
	}
	hostKey, err := ssh.ParsePrivateKey(hostKeyBytes)
	if err != nil {
		log.Fatalf("failed to parse host key: %v", err)
	}

	// Enforce RSA host key (ssh-rsa) for maximum compatibility with legacy SSH clients.
	// If you need ed25519 or other key types, remove this check.
	if hostKey.PublicKey().Type() != ssh.KeyAlgoRSA {
		log.Fatalf("host key %s is %s; this build requires RSA (ssh-rsa). Generate an RSA key with: ssh-keygen -t rsa -b 2048 -f %s -N \"\"", cfg.HostKeyFile, hostKey.PublicKey().Type(), cfg.HostKeyFile)
	}
	sshConfig.AddHostKey(hostKey)

	// Store SSH config globally so hot-reloaded serve loops always use the latest.
	setSSHConfig(sshConfig)

	// Logging setup.
	quietLogs := cfg.Quiet || *quietFlag || userCountEnabled
	if quietLogs {
		log.SetOutput(io.Discard)
	}
	startPanelLogLimiter()

	// Initialise default per-connection bandwidth limits and SSH inactivity cleanup.
	setDefaultLimits(cfg.DefaultLimitMbpsUp, cfg.DefaultLimitMbpsDown)
	setSSHIdleTimeoutFromConfig(cfg.SSHIdleTimeout)
	setMaxTotalConnsFromConfig(cfg.MaxTotalConnections)
	setPAMAuthEnabled(cfg.PAMAuthEnabled)

	// Initialise listener pools (used for initial startup and hot-reload alike).
	publicPool = newListenerPool(serveHTTP80)
	localPool = newListenerPool(serveRawSSH)
	tlsPool = newTLSListenerPool()

	for _, msg := range normalizeRuntimePorts(cfg) {
		log.Printf("startup config fallback: %s", msg)
	}

	// Keep a plain, loopback-only SSH endpoint available to local proxy and
	// tunnel daemons. It has its own listener pool, so cycling the public proxy
	// ports does not close this socket.
	for _, e := range localPool.Sync([]string{cfg.LocalSSHListen}) {
		log.Printf("failed to start internal SSH listener: %v", e)
	}

	// Start the integrated DNSTT and UDPGW if configured. Startup errors are logged
	// but do not crash the panel; the admin UI exposes the logs and service status.
	if err := startDNSTT(cfg.DNSTT, sshConfig); err != nil {
		log.Printf("dnstt auto-start failed: %v", err)
	}
	if err := startUDPGW(cfg.UDPGW); err != nil {
		log.Printf("udpgw auto-start failed: %v", err)
	}

	// Start the integrated BHTTP transport and BTUN protocol server. Both relay
	// into this process (BHTTP into the built-in SSH server, BTUN into its own
	// TUN device with panel-backed authentication), so neither depends on the
	// system sshd. Startup errors are logged and surfaced in the admin UI.
	if err := startBHTTP(cfg.BHTTP); err != nil {
		log.Printf("bhttp auto-start failed: %v", err)
	}
	if err := startBTUN(cfg.BTUN); err != nil {
		log.Printf("btun auto-start failed: %v", err)
	}
	if err := startHCR(cfg.HCR); err != nil {
		log.Printf("hcr auto-start failed: %v", err)
	}

	// Start public SSH listeners (listen + extra_listen).
	publicAddrs := append([]string{cfg.Listen}, cfg.ExtraListen...)
	for _, e := range publicPool.Sync(publicAddrs) {
		log.Printf("failed to start listener: %v", e)
	}

	// Start TLS forwarder listeners if configured.
	for _, e := range tlsPool.Sync(cfg.TLSForwarders) {
		log.Printf("failed to start TLS listener: %v", e)
	}

	// Start proxy hard auto-restart after the initial listeners are bound.
	startProxyAutoRestart(cfg)

	// Print user counts once at startup.
	updateUserDisplay()

	// Block forever.  Individual accept loops run in goroutines.
	select {}
}
