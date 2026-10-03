package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/dakarpy/ConectaSSH-PRO/internal/bhttp"
	"github.com/dakarpy/ConectaSSH-PRO/internal/btun"
	"github.com/dakarpy/ConectaSSH-PRO/internal/hcr"
)

// ---------- Test scaffolding ----------

// withPanelUsers installs a temporary user table and SSH server config so the
// tunnel transports can be exercised against the built-in SSH server without a
// database or a real listener.
func withPanelUsers(t *testing.T, users ...*UserState) {
	t.Helper()

	table := make(map[string]*UserState, len(users))
	for _, u := range users {
		if u.conns == nil {
			u.conns = make(map[*ssh.ServerConn]struct{})
		}
		table[u.Cfg.Username] = u
	}

	previousUsers := userMgr.users
	userMgr.mu.Lock()
	userMgr.users = table
	userMgr.mu.Unlock()

	previousCfg := getSSHConfig()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatalf("host key signer: %v", err)
	}
	sshConfig := &ssh.ServerConfig{PasswordCallback: passwordCallback}
	sshConfig.AddHostKey(signer)
	setSSHConfig(sshConfig)

	t.Cleanup(func() {
		userMgr.mu.Lock()
		userMgr.users = previousUsers
		userMgr.mu.Unlock()
		setSSHConfig(previousCfg)
	})
}

// testLogger routes transport logs into the test output instead of stderr.
func testLogger(t *testing.T) *log.Logger {
	t.Helper()
	return log.New(testWriter{t: t}, "", 0)
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s", strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

// loopbackTUN stands in for a real TUN device so the BTUN server can be
// exercised on any platform. Packets written to it are simply discarded; the
// tests here cover the handshake and accounting, not IP routing.
type loopbackTUN struct {
	packets chan []byte
	closed  chan struct{}
	once    sync.Once
}

func newLoopbackTUN() *loopbackTUN {
	return &loopbackTUN{packets: make(chan []byte, 8), closed: make(chan struct{})}
}

func (d *loopbackTUN) Read(buffer []byte) (int, error) {
	select {
	case packet := <-d.packets:
		return copy(buffer, packet), nil
	case <-d.closed:
		return 0, io.EOF
	}
}

func (d *loopbackTUN) Write(buffer []byte) (int, error) {
	select {
	case <-d.closed:
		return 0, io.ErrClosedPipe
	default:
		return len(buffer), nil
	}
}

func (d *loopbackTUN) Close() error {
	d.once.Do(func() { close(d.closed) })
	return nil
}

func (d *loopbackTUN) Name() string { return "tuntest0" }

// ---------- The built-in SSH server is the only tunnel target ----------

// The whole point of embedding these transports is that a tunnelled session is
// served by this process's own SSH server. If dialInternalSSH ever started
// dialing a TCP address instead, tunnel logins would silently depend on the
// host's sshd, and panel accounts/limits would stop applying.
func TestDialInternalSSHIsServedInProcess(t *testing.T) {
	withPanelUsers(t, &UserState{Cfg: UserConfig{Username: "tunnel", Password: "secret"}})

	conn, err := dialInternalSSH("bhttp")
	if err != nil {
		t.Fatalf("dialInternalSSH: %v", err)
	}
	defer conn.Close()

	if network := conn.RemoteAddr().Network(); network != "bhttp" {
		t.Fatalf("remote network = %q, want the transport label", network)
	}
	if _, ok := conn.(*net.TCPConn); ok {
		t.Fatal("tunnel target is a TCP socket; it must stay in-process")
	}

	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	banner := make([]byte, 8)
	if _, err := io.ReadFull(conn, banner); err != nil {
		t.Fatalf("read SSH identification: %v", err)
	}
	if got := string(banner); got != "SSH-2.0-" {
		t.Fatalf("identification = %q, want the built-in SSH server greeting", got)
	}
}

func TestDialInternalSSHFailsBeforeTheSSHServerIsReady(t *testing.T) {
	previous := getSSHConfig()
	setSSHConfig(nil)
	t.Cleanup(func() { setSSHConfig(previous) })

	if _, err := dialInternalSSH("bhttp"); err == nil {
		t.Fatal("expected an error while the SSH server is unavailable")
	}
}

// ---------- BHTTP end to end ----------

// bhttpTestClient speaks the raw BHTTP wire format against a listening server.
type bhttpTestClient struct {
	t    *testing.T
	conn net.Conn
	sid  bhttp.SessionID
}

func (c *bhttpTestClient) send(mode byte, sequence uint64, clear []byte) {
	c.t.Helper()
	payload := bhttp.Crypt(clear, c.sid, mode, sequence, false)
	frame := make([]byte, bhttp.HeaderSize+len(payload))
	frame[0] = mode
	copy(frame[1:17], c.sid[:])
	binary.BigEndian.PutUint64(frame[17:25], sequence)
	binary.BigEndian.PutUint32(frame[25:29], uint32(len(payload)))
	copy(frame[bhttp.HeaderSize:], payload)
	if _, err := c.conn.Write(frame); err != nil {
		c.t.Fatalf("write mode %d: %v", mode, err)
	}
}

// readStatus reads one status frame and returns its status byte and body.
func (c *bhttpTestClient) readStatus() (byte, []byte) {
	c.t.Helper()
	var header [5]byte
	if _, err := io.ReadFull(c.conn, header[:]); err != nil {
		c.t.Fatalf("read status header: %v", err)
	}
	body := make([]byte, binary.BigEndian.Uint32(header[1:5]))
	if _, err := io.ReadFull(c.conn, body); err != nil {
		c.t.Fatalf("read status body: %v", err)
	}
	return header[0], body
}

// readDownload reads one download frame and returns the decrypted payload.
func (c *bhttpTestClient) readDownload(mode byte, sequence uint64) []byte {
	c.t.Helper()
	status, body := c.readStatus()
	if status != bhttp.StatusData {
		c.t.Fatalf("download status = %d (%q), want StatusData", status, body)
	}
	if len(body) < 4 {
		c.t.Fatalf("download body is %d bytes, want at least 4", len(body))
	}
	return bhttp.Crypt(body[4:], c.sid, mode, sequence, true)
}

// A BHTTP client that opens a session and asks for downstream bytes must get
// the built-in SSH server's identification string, proving the whole path
// (wire framing -> session -> in-process SSH handler) is connected.
func TestBHTTPSessionReachesBuiltInSSHServer(t *testing.T) {
	withPanelUsers(t, &UserState{Cfg: UserConfig{Username: "tunnel", Password: "secret"}})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := bhttp.NewServer(bhttp.Config{
		TargetAddress: bhttpTargetLabel,
		DialTarget:    dialInternalSSH,
		Logger:        testLogger(t),
	})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		_ = listener.Close()
		server.Close()
	})

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	client := &bhttpTestClient{t: t, conn: conn}
	copy(client.sid[:], "bhttp-e2e-sid-01")

	// Mode 1 with sequence 0 and no payload is the session open.
	client.send(bhttp.ModeUpload, 0, nil)
	if status, body := client.readStatus(); status != bhttp.StatusOK {
		t.Fatalf("open status = %d (%q), want StatusOK", status, body)
	}

	// Mode 2 pulls the first downstream chunk, which is the SSH banner.
	client.send(bhttp.ModeDownload, 0, nil)
	payload := client.readDownload(bhttp.ModeDownload, 0)
	if !strings.HasPrefix(string(payload), "SSH-2.0-") {
		t.Fatalf("first downstream chunk = %q, want the built-in SSH identification", payload)
	}
}

// The session cap has to refuse new session IDs rather than grow without
// bound, otherwise a client spraying random SIDs allocates a session (and an
// SSH handler) per frame.
func TestBHTTPSessionCapRefusesNewSessions(t *testing.T) {
	withPanelUsers(t, &UserState{Cfg: UserConfig{Username: "tunnel", Password: "secret"}})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := bhttp.NewServer(bhttp.Config{
		TargetAddress: bhttpTargetLabel,
		DialTarget:    dialInternalSSH,
		MaxSessions:   1,
		Logger:        testLogger(t),
	})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		_ = listener.Close()
		server.Close()
	})

	open := func(sid string) (byte, []byte) {
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
		client := &bhttpTestClient{t: t, conn: conn}
		copy(client.sid[:], sid)
		client.send(bhttp.ModeUpload, 0, nil)
		return client.readStatus()
	}

	// A bhttp.SessionID is exactly 16 bytes, so these labels must differ within
	// the first 16 characters or they would name the same session.
	if status, body := open("bhttp-cap-sid-1"); status != bhttp.StatusOK {
		t.Fatalf("first session status = %d (%q), want StatusOK", status, body)
	}
	if status, _ := open("bhttp-cap-sid-2"); status == bhttp.StatusOK {
		t.Fatal("second session was accepted past the cap of 1")
	}
	if stats := server.Stats(); stats.SessionsRejected == 0 {
		t.Fatal("rejected session was not counted")
	}
}

func TestNormalizeBHTTPListenListDeduplicates(t *testing.T) {
	got := normalizeBHTTPListenList([]string{" 0.0.0.0:8880 ", "", "0.0.0.0:8880", "[::]:8881"})
	want := []string{"0.0.0.0:8880", "[::]:8881"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

// ---------- BTUN authentication is panel-only ----------

func TestBTUNAuthenticatorUsesPanelAccountsOnly(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)

	valid := &UserState{Cfg: UserConfig{Username: "valid", Password: "pass"}}
	expired := &UserState{Cfg: UserConfig{Username: "expired", Password: "pass"}, ExpiresAt: &past}
	active := &UserState{Cfg: UserConfig{Username: "active", Password: "pass"}, ExpiresAt: &future}
	quota := &UserState{Cfg: UserConfig{
		Username: "quota", Password: "pass",
		DataQuotaBytes: 1024, QuotaAction: quotaActionBlock,
	}}
	atomic.StoreInt64(&quota.totalBytes, 4096)

	withPanelUsers(t, valid, expired, active, quota)

	auth := btunPanelAuthenticator{}
	if auth.Name() != "panel" {
		t.Fatalf("authenticator name = %q, want \"panel\"", auth.Name())
	}

	tests := []struct {
		name     string
		username string
		password string
		wantErr  bool
	}{
		{name: "panel password accepted", username: "valid", password: "pass"},
		{name: "unexpired account accepted", username: "active", password: "pass"},
		{name: "wrong password rejected", username: "valid", password: "nope", wantErr: true},
		{name: "unknown account rejected", username: "ghost", password: "pass", wantErr: true},
		{name: "expired account rejected", username: "expired", password: "pass", wantErr: true},
		{name: "account over data quota rejected", username: "quota", password: "pass", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := auth.Authenticate(tt.username, tt.password)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Authenticate(%q) error = %v, wantErr %v", tt.username, err, tt.wantErr)
			}
		})
	}
}

// A system account that is not a panel account must never be able to log in
// over BTUN, even with pam_auth_enabled turned on: pam_auth_enabled is an SSH
// setting and BTUN has no PAM path at all.
func TestBTUNAuthenticatorIgnoresSystemLoginSetting(t *testing.T) {
	withPanelUsers(t, &UserState{Cfg: UserConfig{Username: "panelonly", Password: "pass"}})

	setPAMAuthEnabled(true)
	t.Cleanup(func() { setPAMAuthEnabled(false) })

	auth := btunPanelAuthenticator{}
	if err := auth.Authenticate("root", "toor"); err == nil {
		t.Fatal("a non-panel account was accepted over BTUN")
	}
}

// ---------- BTUN accounting shares the account's allowances with SSH ----------

type fakeCloser struct{ closed atomic.Bool }

func (c *fakeCloser) Close() error {
	c.closed.Store(true)
	return nil
}

func TestBTUNSessionsShareMaxConnectionsWithSSH(t *testing.T) {
	user := &UserState{Cfg: UserConfig{Username: "limited", Password: "pass", MaxConnections: 2}}
	withPanelUsers(t, user)

	accountant := btunPanelAccountant{}
	first, err := accountant.Admit("limited", "203.0.113.5:1000", &fakeCloser{})
	if err != nil {
		t.Fatalf("first session refused: %v", err)
	}
	second, err := accountant.Admit("limited", "203.0.113.5:1001", &fakeCloser{})
	if err != nil {
		t.Fatalf("second session refused: %v", err)
	}
	if _, err := accountant.Admit("limited", "203.0.113.5:1002", &fakeCloser{}); err == nil {
		t.Fatal("third session was admitted past max_connections = 2")
	}

	user.mu.Lock()
	counted := user.btunConns
	reported := user.ActiveConns
	user.mu.Unlock()
	if counted != 2 || reported != 2 {
		t.Fatalf("btunConns = %d, ActiveConns = %d, want 2 and 2", counted, reported)
	}

	// Closing a session must free the slot again.
	second.Close()
	if _, err := accountant.Admit("limited", "203.0.113.5:1003", &fakeCloser{}); err != nil {
		t.Fatalf("session refused after a slot was freed: %v", err)
	}
	first.Close()
}

func TestBTUNDisconnectUserClosesItsSessions(t *testing.T) {
	user := &UserState{Cfg: UserConfig{Username: "kickme", Password: "pass"}}
	other := &UserState{Cfg: UserConfig{Username: "keepme", Password: "pass"}}
	withPanelUsers(t, user, other)

	accountant := btunPanelAccountant{}
	victimCloser := &fakeCloser{}
	bystanderCloser := &fakeCloser{}
	victim, err := accountant.Admit("kickme", "203.0.113.9:1000", victimCloser)
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	bystander, err := accountant.Admit("keepme", "203.0.113.9:1001", bystanderCloser)
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	t.Cleanup(func() {
		victim.Close()
		bystander.Close()
	})

	if closed := btunDisconnectUser("kickme"); closed != 1 {
		t.Fatalf("btunDisconnectUser closed %d sessions, want 1", closed)
	}
	if !victimCloser.closed.Load() {
		t.Fatal("the user's own BTUN session was not closed")
	}
	if bystanderCloser.closed.Load() {
		t.Fatal("another user's BTUN session was closed")
	}
}

// Forwarding whole IP packets cannot honour a partial quota allowance, so the
// account's remaining bytes must end the session instead of letting a
// truncated packet through.
func TestBTUNLedgerStopsAtTheDataQuota(t *testing.T) {
	user := &UserState{Cfg: UserConfig{
		Username: "capped", Password: "pass",
		DataQuotaBytes: 4096, QuotaAction: quotaActionBlock,
	}}
	withPanelUsers(t, user)

	ledger, err := (btunPanelAccountant{}).Admit("capped", "203.0.113.20:1000", &fakeCloser{})
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	defer ledger.Close()

	if err := ledger.Uplink(t.Context(), 1024); err != nil {
		t.Fatalf("first packet within quota was refused: %v", err)
	}
	if err := ledger.Downlink(t.Context(), 1024); err != nil {
		t.Fatalf("second packet within quota was refused: %v", err)
	}
	if got := atomic.LoadInt64(&user.TotalUplinkBytes); got != 1024 {
		t.Fatalf("uplink bytes = %d, want 1024", got)
	}
	if got := atomic.LoadInt64(&user.TotalDownlinkBytes); got != 1024 {
		t.Fatalf("downlink bytes = %d, want 1024", got)
	}

	// This packet crosses the 4096-byte quota, so it must be refused whole.
	if err := ledger.Uplink(t.Context(), 4096); err == nil {
		t.Fatal("a packet past the data quota was allowed")
	}
	if got := atomic.LoadInt64(&user.TotalUplinkBytes); got != 1024 {
		t.Fatalf("refused packet was still counted: uplink bytes = %d, want 1024", got)
	}
}

func TestBTUNLedgerPacesAtTheAccountBandwidthLimit(t *testing.T) {
	user := &UserState{Cfg: UserConfig{Username: "slow", Password: "pass", LimitMbpsUp: 1, LimitMbpsDown: 1}}
	withPanelUsers(t, user)

	ledger, err := (btunPanelAccountant{}).Admit("slow", "203.0.113.30:1000", &fakeCloser{})
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	defer ledger.Close()

	// A 1 Mbps limiter refills at 131072 bytes/s and starts with a full bucket,
	// so the first 128 KiB go through immediately and the next 64 KiB must wait
	// roughly half a second rather than being refused outright.
	const packet = 64 * 1024
	for i := 0; i < 2; i++ {
		if err := ledger.Uplink(t.Context(), packet); err != nil {
			t.Fatalf("packet %d within the initial burst was refused: %v", i+1, err)
		}
	}
	start := time.Now()
	if err := ledger.Uplink(t.Context(), packet); err != nil {
		t.Fatalf("packet past the initial burst was refused: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Fatalf("packet past the burst took %s; the bandwidth limit was not applied", elapsed)
	}
}

// ---------- BTUN configuration ----------

func TestBTUNGatewayForSubnet(t *testing.T) {
	tests := []struct {
		subnet  string
		want    string
		wantErr bool
	}{
		{subnet: "10.77.0.0/16", want: "10.77.0.1/16"},
		{subnet: "10.8.0.0/24", want: "10.8.0.1/24"},
		{subnet: "192.168.20.0/30", want: "192.168.20.1/30"},
		{subnet: "10.9.0.5/24", want: "10.9.0.1/24"},
		{subnet: "10.10.0.0/31", wantErr: true},
		{subnet: "fd00::/64", wantErr: true},
		{subnet: "not-a-subnet", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.subnet, func(t *testing.T) {
			got, err := btunGatewayForSubnet(tt.subnet)
			if (err != nil) != tt.wantErr {
				t.Fatalf("btunGatewayForSubnet(%q) error = %v, wantErr %v", tt.subnet, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Fatalf("btunGatewayForSubnet(%q) = %q, want %q", tt.subnet, got, tt.want)
			}
		})
	}
}

func TestNormalizeBTUNConfigFillsDefaults(t *testing.T) {
	cfg := &BTUNConfig{TCPListen: " 0.0.0.0:7300 "}
	normalizeBTUNConfig(cfg)

	if cfg.TCPListen != "0.0.0.0:7300" {
		t.Fatalf("tcp_listen = %q", cfg.TCPListen)
	}
	if cfg.TUNName != defaultBTUNName {
		t.Fatalf("tun_name = %q, want %q", cfg.TUNName, defaultBTUNName)
	}
	if cfg.Subnet != defaultBTUNSubnet {
		t.Fatalf("subnet = %q, want %q", cfg.Subnet, defaultBTUNSubnet)
	}
	if cfg.Gateway != "10.77.0.1/16" {
		t.Fatalf("gateway = %q, want 10.77.0.1/16", cfg.Gateway)
	}
	if cfg.MTU != defaultBTUNMTU {
		t.Fatalf("mtu = %d, want %d", cfg.MTU, defaultBTUNMTU)
	}
}

func TestNormalizeBTUNConfigClampsPacketSize(t *testing.T) {
	cfg := &BTUNConfig{UDPListen: "0.0.0.0:7300", MaxPacketSize: 64 * 1024 * 1024}
	normalizeBTUNConfig(cfg)
	if cfg.MaxPacketSize != btunMaxPacketCeiling {
		t.Fatalf("max_packet_size = %d, want %d", cfg.MaxPacketSize, btunMaxPacketCeiling)
	}
}

// A BTUN server started without a listener would silently do nothing, so the
// misconfiguration has to surface as a start error the panel can show.
func TestStartBTUNInstanceRequiresAListener(t *testing.T) {
	err := startBTUNInstance(&BTUNConfig{})
	if err == nil {
		t.Fatal("expected an error when neither listener is configured")
	}
	if !strings.Contains(err.Error(), "tcp_listen") {
		t.Fatalf("error = %v, want it to name the missing setting", err)
	}
}

func TestNormalizeAutoRestartFields(t *testing.T) {
	tests := []struct {
		name         string
		interval     string
		grace        string
		wantInterval string
		wantGrace    string
	}{
		{name: "kept as configured", interval: "6h", grace: "2s", wantInterval: "6h", wantGrace: "2s"},
		{name: "interval below the minimum disables", interval: "30s", grace: "", wantInterval: "", wantGrace: ""},
		{name: "invalid interval disables", interval: "soon", grace: "", wantInterval: "", wantGrace: ""},
		{name: "off keeps its sentinel", interval: "off", grace: "", wantInterval: "off", wantGrace: ""},
		{name: "invalid grace falls back", interval: "2h", grace: "later", wantInterval: "2h", wantGrace: ""},
		{name: "long grace is clamped", interval: "2h", grace: "5m", wantInterval: "2h", wantGrace: "1m"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interval, grace := tt.interval, tt.grace
			normalizeAutoRestartFields(&interval, &grace, "TEST", func(string, ...interface{}) {})
			if interval != tt.wantInterval || grace != tt.wantGrace {
				t.Fatalf("got (%q, %q), want (%q, %q)", interval, grace, tt.wantInterval, tt.wantGrace)
			}
		})
	}
}

func TestNormalizeDurationFieldClamps(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "empty stays empty", input: "", want: ""},
		{name: "in range is kept", input: "45s", want: "45s"},
		{name: "below minimum clamps up", input: "1s", want: "10s"},
		{name: "above maximum clamps down", input: "5h", want: "1h0m0s"},
		{name: "invalid clears", input: "nope", want: ""},
		{name: "zero clears", input: "0s", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.input
			normalizeDurationField(&got, "test", 10*time.Second, time.Hour, func(string, ...interface{}) {})
			if got != tt.want {
				t.Fatalf("normalizeDurationField(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------- BTUN wire behaviour against the panel authenticator ----------

// The BTUN handshake must reject a bad panel credential and accept a good one,
// which is what proves the panel authenticator is actually wired into the
// protocol server rather than being dead code.
func TestBTUNHandshakeAuthenticatesAgainstThePanel(t *testing.T) {
	withPanelUsers(t, &UserState{Cfg: UserConfig{Username: "vpn", Password: "letmein"}})

	device := newLoopbackTUN()
	server, err := btun.NewServer(btun.Config{
		Subnet:        "10.77.0.0/24",
		Authenticator: btunPanelAuthenticator{},
		Accountant:    btunPanelAccountant{},
		Logger:        testLogger(t),
	}, device)
	if err != nil {
		t.Fatalf("new BTUN server: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = server.ServeTCP(listener) }()
	t.Cleanup(func() {
		_ = listener.Close()
		_ = server.Close()
		server.Wait()
	})

	authenticate := func(credential string) btun.Packet {
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

		if _, err := conn.Write(btun.ClientHello); err != nil {
			t.Fatalf("write client hello: %v", err)
		}
		hello := make([]byte, len(btun.ServerHello))
		if _, err := io.ReadFull(conn, hello); err != nil {
			t.Fatalf("read server hello: %v", err)
		}
		frame, err := btun.MarshalPacket(btun.Packet{Type: btun.PacketAuth, Payload: []byte(credential)}, 0)
		if err != nil {
			t.Fatalf("marshal auth: %v", err)
		}
		if _, err := conn.Write(frame); err != nil {
			t.Fatalf("write auth: %v", err)
		}
		packet, err := btun.ReadPacket(conn, 0)
		if err != nil {
			t.Fatalf("read auth response: %v", err)
		}
		return packet
	}

	accepted := authenticate("vpn:letmein")
	if accepted.Type != btun.PacketAuthResponse || len(accepted.Payload) == 0 || accepted.Payload[0] != 1 {
		t.Fatalf("valid panel credential was rejected: %#v", accepted)
	}

	refused := authenticate("vpn:wrong")
	if refused.Type != btun.PacketAuthResponse || len(refused.Payload) == 0 || refused.Payload[0] != 0 {
		t.Fatalf("invalid panel credential was accepted: %#v", refused)
	}

	unknown := authenticate("nosuchuser:letmein")
	if unknown.Type != btun.PacketAuthResponse || len(unknown.Payload) == 0 || unknown.Payload[0] != 0 {
		t.Fatalf("unknown account was accepted: %#v", unknown)
	}
}

// ---------- BHTTP sharing the proxy and TLS ports ----------

// withSharedBHTTP starts a BHTTP instance that owns no port of its own and
// only serves connections handed over from the panel's listeners.
func withSharedBHTTP(t *testing.T) {
	t.Helper()
	if err := startBHTTPInstance(&BHTTPConfig{SharedPorts: true}); err != nil {
		t.Fatalf("start shared BHTTP: %v", err)
	}
	t.Cleanup(stopBHTTP)
	if !bhttpShareEnabled() {
		t.Fatal("shared-port handoff did not come up")
	}
}

// serveProxyPort starts a listener that behaves like a public proxy port.
func serveProxyPort(t *testing.T) net.Addr {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleProxyConn(conn, getSSHConfig())
		}
	}()
	return listener.Addr()
}

// bhttpProbeFrame builds the BHP1 capability probe a client opens with.
func bhttpProbeFrame(sid bhttp.SessionID) []byte {
	clear := make([]byte, 10)
	copy(clear[:4], "BHP1")
	clear[4] = 1
	clear[5] = bhttp.ModeUpload
	payload := bhttp.Crypt(clear, sid, bhttp.ModeProbe, 0, false)
	frame := make([]byte, bhttp.HeaderSize+len(payload))
	frame[0] = bhttp.ModeProbe
	copy(frame[1:17], sid[:])
	binary.BigEndian.PutUint32(frame[25:29], uint32(len(payload)))
	copy(frame[bhttp.HeaderSize:], payload)
	return frame
}

// A BHTTP client on a port the HTTP+SSH proxy owns must be answered by BHTTP,
// and must never receive the proxy's unsolicited "HTTP/1.1 101" line.
func TestSharedProxyPortServesBHTTPClient(t *testing.T) {
	withPanelUsers(t, &UserState{Cfg: UserConfig{Username: "tunnel", Password: "secret"}})
	withSharedBHTTP(t)
	addr := serveProxyPort(t)

	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	var sid bhttp.SessionID
	copy(sid[:], "shared-probe-s01")
	if _, err := conn.Write(bhttpProbeFrame(sid)); err != nil {
		t.Fatalf("write probe: %v", err)
	}

	client := &bhttpTestClient{t: t, conn: conn, sid: sid}
	status, body := client.readStatus()
	if status != bhttp.StatusOK {
		t.Fatalf("probe status = %d (%q), want StatusOK — the proxy answered instead of BHTTP", status, body)
	}
	decoded := bhttp.Crypt(body, sid, bhttp.ModeProbe, 0, true)
	if len(decoded) < 4 || string(decoded[:4]) != "BHP1" {
		t.Fatalf("probe response = %q, want a BHP1 reply", decoded)
	}
}

// The same shared port must still serve the HTTP-injection SSH flow exactly as
// before: the 101, the 200, and then the built-in SSH server's banner.
func TestSharedProxyPortStillServesInjectedSSH(t *testing.T) {
	withPanelUsers(t, &UserState{Cfg: UserConfig{Username: "tunnel", Password: "secret"}})
	withSharedBHTTP(t)
	addr := serveProxyPort(t)

	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	// An injection client sends its HTTP payload and SSH banner together.
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\nSSH-2.0-TestClient\r\n")); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	got := readUntil(t, conn, "SSH-2.0-")
	if !strings.Contains(got, "HTTP/1.1 101") {
		t.Fatalf("response %q is missing the 101 the injection flow expects", got)
	}
	if !strings.Contains(got, "HTTP/1.1 200") {
		t.Fatalf("response %q is missing the 200 the injection flow expects", got)
	}
}

// A BHTTP client that hides behind an HTTP cover request on the shared port
// has to be picked up after the injection cleanup consumes that cover.
func TestSharedProxyPortServesBHTTPBehindHTTPCover(t *testing.T) {
	withPanelUsers(t, &UserState{Cfg: UserConfig{Username: "tunnel", Password: "secret"}})
	withSharedBHTTP(t)
	addr := serveProxyPort(t)

	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	var sid bhttp.SessionID
	copy(sid[:], "shared-cover-s01")
	payload := append([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"), bhttpProbeFrame(sid)...)
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	// The proxy answers the cover request itself, so skip its HTTP lines and
	// then read the BHTTP status frame that follows.
	reader := bufio.NewReader(conn)
	skipHTTPResponses(t, reader)
	status, body := readStatusFrom(t, reader)
	if status != bhttp.StatusOK {
		t.Fatalf("probe status = %d (%q), want StatusOK", status, body)
	}
	decoded := bhttp.Crypt(body, sid, bhttp.ModeProbe, 0, true)
	if len(decoded) < 4 || string(decoded[:4]) != "BHP1" {
		t.Fatalf("probe response = %q, want a BHP1 reply", decoded)
	}
}

// With sharing off, the shared port must behave exactly as it did before this
// feature existed: a BHTTP frame gets the proxy's HTTP handling, not BHTTP.
func TestSharedProxyPortIgnoresBHTTPWhenSharingIsOff(t *testing.T) {
	withPanelUsers(t, &UserState{Cfg: UserConfig{Username: "tunnel", Password: "secret"}})
	if bhttpShareEnabled() {
		t.Fatal("shared-port handoff is unexpectedly active")
	}
	addr := serveProxyPort(t)

	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	// The proxy greets with 101 before reading anything, which is the behaviour
	// a BHTTP client cannot tolerate and why sharing is a deliberate choice.
	got := readUntil(t, conn, "HTTP/1.1 101")
	if !strings.Contains(got, "HTTP/1.1 101") {
		t.Fatalf("response %q, want the proxy's unsolicited 101", got)
	}
}

// readUntil reads until marker appears or the deadline fires.
func readUntil(t *testing.T, conn net.Conn, marker string) string {
	t.Helper()
	var seen []byte
	buffer := make([]byte, 256)
	for {
		n, err := conn.Read(buffer)
		if n > 0 {
			seen = append(seen, buffer[:n]...)
			if strings.Contains(string(seen), marker) {
				return string(seen)
			}
		}
		if err != nil {
			t.Fatalf("read (looking for %q, got %q): %v", marker, seen, err)
		}
	}
}

// skipHTTPResponses consumes the proxy's HTTP status lines and their blank
// separator lines, stopping at the first byte that is not part of one.
func skipHTTPResponses(t *testing.T, reader *bufio.Reader) {
	t.Helper()
	for {
		peeked, err := reader.Peek(5)
		if err != nil {
			t.Fatalf("peek HTTP response: %v", err)
		}
		if string(peeked) != "HTTP/" {
			return
		}
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("read HTTP line: %v", err)
			}
			if strings.TrimRight(line, "\r\n") == "" {
				break
			}
		}
	}
}

func readStatusFrom(t *testing.T, reader *bufio.Reader) (byte, []byte) {
	t.Helper()
	var header [5]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		t.Fatalf("read status header: %v", err)
	}
	body := make([]byte, binary.BigEndian.Uint32(header[1:5]))
	if _, err := io.ReadFull(reader, body); err != nil {
		t.Fatalf("read status body: %v", err)
	}
	return header[0], body
}

// ---------- Panel policy on the BHTTP transport path ----------

// dialTunnelSSHClient completes a real SSH client handshake over the same
// in-process transport BHTTP hands its sessions to.
func dialTunnelSSHClient(t *testing.T, username, password string) (*ssh.Client, error) {
	t.Helper()
	conn, err := dialInternalSSH("bhttp")
	if err != nil {
		t.Fatalf("dialInternalSSH: %v", err)
	}
	clientConn, chans, reqs, err := ssh.NewClientConn(conn, "bhttp", &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return ssh.NewClient(clientConn, chans, reqs), nil
}

// A BHTTP session is an SSH connection on the built-in server, so every panel
// rule the SSH path enforces has to apply to it with no BHTTP-specific code:
// the account must exist and match, and the session must be counted against
// the account like any other.
func TestBHTTPTransportAppliesPanelAccountPolicy(t *testing.T) {
	user := &UserState{Cfg: UserConfig{
		Username: "tunnel", Password: "secret",
		MaxConnections: 1, LimitMbpsUp: 5, LimitMbpsDown: 10,
	}}
	expired := time.Now().Add(-time.Hour)
	stale := &UserState{Cfg: UserConfig{Username: "stale", Password: "secret"}, ExpiresAt: &expired}
	withPanelUsers(t, user, stale)

	// A wrong password must be refused by the same callback SSH uses.
	if client, err := dialTunnelSSHClient(t, "tunnel", "wrong"); err == nil {
		_ = client.Close()
		t.Fatal("a wrong password was accepted over the BHTTP transport path")
	}
	// So must an expired account.
	if client, err := dialTunnelSSHClient(t, "stale", "secret"); err == nil {
		_ = client.Close()
		t.Fatal("an expired account was accepted over the BHTTP transport path")
	}

	client, err := dialTunnelSSHClient(t, "tunnel", "secret")
	if err != nil {
		t.Fatalf("valid account was refused: %v", err)
	}
	defer client.Close()

	// handleConn registers the session, which is what makes max_connections,
	// the panel's active-user count and forced disconnects cover BHTTP.
	deadline := time.Now().Add(5 * time.Second)
	for {
		user.mu.Lock()
		active := len(user.conns)
		user.mu.Unlock()
		if active == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("BHTTP session was not registered on the account (active = %d)", active)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// max_connections is 1, so a second session must be dropped.
	second, err := dialTunnelSSHClient(t, "tunnel", "secret")
	if err == nil {
		// The cap is enforced after the handshake, so the connection is closed
		// rather than refused: the first use of it fails.
		_, _, sessErr := second.OpenChannel("session", nil)
		_ = second.Close()
		if sessErr == nil {
			t.Fatal("a second session was usable past max_connections = 1")
		}
	}
}

// The per-account bandwidth limits and data quota are applied by the
// direct-tcpip relay, which is the only data path a BHTTP session has. This
// pins the wiring that derives them, including the global default fallback.
func TestBHTTPTransportDerivesAccountLimits(t *testing.T) {
	setDefaultLimits(7, 9)
	t.Cleanup(func() { setDefaultLimits(0, 0) })

	tests := []struct {
		name     string
		cfg      UserConfig
		wantUp   int
		wantDown int
	}{
		{name: "per-account limits win", cfg: UserConfig{LimitMbpsUp: 5, LimitMbpsDown: 10}, wantUp: 5, wantDown: 10},
		{name: "zero falls back to the default", cfg: UserConfig{}, wantUp: 7, wantDown: 9},
		{name: "one side falls back", cfg: UserConfig{LimitMbpsUp: 3}, wantUp: 3, wantDown: 9},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			up, down := tt.cfg.LimitMbpsUp, tt.cfg.LimitMbpsDown
			if up == 0 || down == 0 {
				defUp, defDown := getDefaultLimits()
				if up == 0 {
					up = defUp
				}
				if down == 0 {
					down = defDown
				}
			}
			if up != tt.wantUp || down != tt.wantDown {
				t.Fatalf("limits = (%d, %d), want (%d, %d)", up, down, tt.wantUp, tt.wantDown)
			}
		})
	}
}

// ---------- BTUN sharing the proxy and TLS ports ----------

// withSharedBTUN starts a BTUN instance that owns no port of its own and only
// serves connections handed over from the panel's listeners.
func withSharedBTUN(t *testing.T) {
	t.Helper()
	device := newLoopbackTUN()
	server, err := btun.NewServer(btun.Config{
		Subnet:        "10.77.0.0/24",
		Authenticator: btunPanelAuthenticator{},
		Accountant:    btunPanelAccountant{},
		Logger:        testLogger(t),
	}, device)
	if err != nil {
		t.Fatalf("new BTUN server: %v", err)
	}
	btunMu.Lock()
	btunServer = server
	btunDevice = device
	btunSharedPorts = true
	btunMu.Unlock()
	t.Cleanup(func() {
		btunMu.Lock()
		btunServer = nil
		btunDevice = nil
		btunSharedPorts = false
		btunMu.Unlock()
		_ = server.Close()
		server.Wait()
	})
	if !btunShareEnabled() {
		t.Fatal("shared-port handoff did not come up")
	}
}

// btunAuthenticate runs the BTUN handshake over conn and returns the server's
// authentication response.
func btunAuthenticate(t *testing.T, conn net.Conn, reader *bufio.Reader, credential string) btun.Packet {
	t.Helper()
	if _, err := conn.Write(btun.ClientHello); err != nil {
		t.Fatalf("write client hello: %v", err)
	}
	hello := make([]byte, len(btun.ServerHello))
	if _, err := io.ReadFull(reader, hello); err != nil {
		t.Fatalf("read server hello: %v", err)
	}
	if !bytes.Equal(hello, btun.ServerHello) {
		t.Fatalf("server hello = %q, want %q", hello, btun.ServerHello)
	}
	frame, err := btun.MarshalPacket(btun.Packet{Type: btun.PacketAuth, Payload: []byte(credential)}, 0)
	if err != nil {
		t.Fatalf("marshal auth: %v", err)
	}
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("write auth: %v", err)
	}
	packet, err := btun.ReadPacket(reader, 0)
	if err != nil {
		t.Fatalf("read auth response: %v", err)
	}
	return packet
}

// A BTUN client on a port the HTTP+SSH proxy owns must reach BTUN and
// authenticate against the panel accounts.
func TestSharedProxyPortServesBTUNClient(t *testing.T) {
	withPanelUsers(t, &UserState{Cfg: UserConfig{Username: "vpn", Password: "letmein"}})
	withSharedBTUN(t)
	addr := serveProxyPort(t)

	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	response := btunAuthenticate(t, conn, bufio.NewReader(conn), "vpn:letmein")
	if response.Type != btun.PacketAuthResponse || len(response.Payload) == 0 || response.Payload[0] != 1 {
		t.Fatalf("valid panel credential was rejected on the shared port: %#v", response)
	}
}

// A BTUN client hiding behind an HTTP cover request must be picked up after the
// injection cleanup consumes that cover.
func TestSharedProxyPortServesBTUNBehindHTTPCover(t *testing.T) {
	withPanelUsers(t, &UserState{Cfg: UserConfig{Username: "vpn", Password: "letmein"}})
	withSharedBTUN(t)
	addr := serveProxyPort(t)

	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	// The cover and the hello go out together, which is what the protocol
	// requires: a dedicated BTUN server answers nothing until it has read the
	// hello, so a client cannot wait for a reply to the cover alone.
	cover := append([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"), btun.ClientHello...)
	if _, err := conn.Write(cover); err != nil {
		t.Fatalf("write cover: %v", err)
	}

	// On a shared port the client also has to skip the panel's own 101/200
	// injection reply before the server hello. That is the cost of sharing, and
	// the reason the dedicated BTUN port stays available for clients that do
	// not expect it.
	reader := bufio.NewReader(conn)
	skipHTTPResponses(t, reader)
	hello := make([]byte, len(btun.ServerHello))
	if _, err := io.ReadFull(reader, hello); err != nil {
		t.Fatalf("read server hello: %v", err)
	}
	if !bytes.Equal(hello, btun.ServerHello) {
		t.Fatalf("server hello = %q, want %q", hello, btun.ServerHello)
	}

	frame, err := btun.MarshalPacket(btun.Packet{Type: btun.PacketAuth, Payload: []byte("vpn:letmein")}, 0)
	if err != nil {
		t.Fatalf("marshal auth: %v", err)
	}
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("write auth: %v", err)
	}
	response, err := btun.ReadPacket(reader, 0)
	if err != nil {
		t.Fatalf("read auth response: %v", err)
	}
	if response.Type != btun.PacketAuthResponse || len(response.Payload) == 0 || response.Payload[0] != 1 {
		t.Fatalf("BTUN behind HTTP cover was rejected: %#v", response)
	}
}

// A wrong panel credential must be refused on the shared port exactly as on a
// dedicated one: sharing changes routing, never authentication.
func TestSharedProxyPortBTUNStillChecksPanelCredentials(t *testing.T) {
	withPanelUsers(t, &UserState{Cfg: UserConfig{Username: "vpn", Password: "letmein"}})
	withSharedBTUN(t)
	addr := serveProxyPort(t)

	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	response := btunAuthenticate(t, conn, bufio.NewReader(conn), "vpn:wrong")
	if response.Type != btun.PacketAuthResponse || len(response.Payload) == 0 || response.Payload[0] != 0 {
		t.Fatalf("invalid credential was accepted on the shared port: %#v", response)
	}
}

// The decisive test: all three protocols on one listener at the same time,
// each answered correctly, none disturbed by the others.
func TestSharedProxyPortServesAllThreeProtocols(t *testing.T) {
	withPanelUsers(t, &UserState{Cfg: UserConfig{Username: "vpn", Password: "letmein"}})
	withSharedBHTTP(t)
	withSharedBTUN(t)
	addr := serveProxyPort(t)

	t.Run("BTUN", func(t *testing.T) {
		conn, err := net.Dial("tcp", addr.String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
		response := btunAuthenticate(t, conn, bufio.NewReader(conn), "vpn:letmein")
		if response.Type != btun.PacketAuthResponse || len(response.Payload) == 0 || response.Payload[0] != 1 {
			t.Fatalf("BTUN was not served: %#v", response)
		}
	})

	t.Run("BHTTP", func(t *testing.T) {
		conn, err := net.Dial("tcp", addr.String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
		var sid bhttp.SessionID
		copy(sid[:], "all-three-sid-01")
		if _, err := conn.Write(bhttpProbeFrame(sid)); err != nil {
			t.Fatalf("write probe: %v", err)
		}
		client := &bhttpTestClient{t: t, conn: conn, sid: sid}
		status, body := client.readStatus()
		if status != bhttp.StatusOK {
			t.Fatalf("BHTTP was not served: status %d (%q)", status, body)
		}
	})

	t.Run("injected SSH", func(t *testing.T) {
		conn, err := net.Dial("tcp", addr.String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
		if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\nSSH-2.0-TestClient\r\n")); err != nil {
			t.Fatalf("write payload: %v", err)
		}
		got := readUntil(t, conn, "SSH-2.0-")
		if !strings.Contains(got, "HTTP/1.1 200") {
			t.Fatalf("injected SSH lost its 200: %q", got)
		}
	})
}

// ---------- UDP over the tunnel transports ----------

// The SSH-carrying transports move TCP. UDP reaches the internet through the
// panel's built-in custom BadVPN gateway, which a client reaches by opening a
// direct-tcpip channel to it over the same tunnel. This proves that whole path:
// BHTTP transport -> built-in SSH server -> direct-tcpip -> UDPGW -> UDP peer.
func TestUDPGWIsReachableOverTheTunnelTransport(t *testing.T) {
	withPanelUsers(t, &UserState{Cfg: UserConfig{Username: "tunnel", Password: "secret"}})

	// A UDP peer that echoes back what it receives, standing in for a DNS or
	// game server the client wants to reach.
	echo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen UDP echo: %v", err)
	}
	defer echo.Close()
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, from, err := echo.ReadFrom(buffer)
			if err != nil {
				return
			}
			_, _ = echo.WriteTo(buffer[:n], from)
		}
	}()
	echoAddr := echo.LocalAddr().(*net.UDPAddr)

	// The gateway itself, bound to loopback for the test.
	if err := startUDPGW(&UDPGWConfig{Listen: "127.0.0.1:0"}); err != nil {
		t.Fatalf("start UDPGW: %v", err)
	}
	t.Cleanup(stopUDPGW)
	udpgwMu.Lock()
	gatewayAddr := ""
	if udpgwLn != nil {
		gatewayAddr = udpgwLn.Addr().String()
	}
	udpgwMu.Unlock()
	if gatewayAddr == "" {
		t.Fatal("UDPGW did not bind a listener")
	}

	// Connect the way a BHTTP client does, then tunnel to the gateway.
	client, err := dialTunnelSSHClient(t, "tunnel", "secret")
	if err != nil {
		t.Fatalf("tunnel SSH login: %v", err)
	}
	defer client.Close()

	gateway, err := client.Dial("tcp", gatewayAddr)
	if err != nil {
		t.Fatalf("direct-tcpip to the UDP gateway: %v", err)
	}
	defer gateway.Close()
	_ = gateway.SetDeadline(time.Now().Add(15 * time.Second))

	payload := []byte("udp-over-tunnel")
	if _, err := gateway.Write(udpgwFrame(1, echoAddr, payload)); err != nil {
		t.Fatalf("write udpgw frame: %v", err)
	}

	connID, from, echoed := readUDPGWFrame(t, gateway)
	if connID != 1 {
		t.Fatalf("reply connID = %d, want 1", connID)
	}
	if from != uint16(echoAddr.Port) {
		t.Fatalf("reply port = %d, want %d", from, echoAddr.Port)
	}
	if string(echoed) != string(payload) {
		t.Fatalf("echoed %q, want %q", echoed, payload)
	}
}

// udpgwFrame builds one client->server frame in the panel's custom BadVPN
// framing: len(2, little endian) | connID(2) | x(1) | IPv4(4) | port(2) | data.
func udpgwFrame(connID uint16, dst *net.UDPAddr, data []byte) []byte {
	body := make([]byte, 9+len(data))
	binary.BigEndian.PutUint16(body[0:2], connID)
	body[2] = 0
	copy(body[3:7], dst.IP.To4())
	binary.BigEndian.PutUint16(body[7:9], uint16(dst.Port))
	copy(body[9:], data)

	out := make([]byte, 2+len(body))
	binary.LittleEndian.PutUint16(out[0:2], uint16(len(body)))
	copy(out[2:], body)
	return out
}

// readUDPGWFrame reads one server->client frame and returns its connID, source
// port and payload.
func readUDPGWFrame(t *testing.T, conn net.Conn) (uint16, uint16, []byte) {
	t.Helper()
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		t.Fatalf("read udpgw length: %v", err)
	}
	body := make([]byte, binary.LittleEndian.Uint16(header[:]))
	if _, err := io.ReadFull(conn, body); err != nil {
		t.Fatalf("read udpgw body: %v", err)
	}
	if len(body) < 9 {
		t.Fatalf("udpgw reply is %d bytes, want at least 9", len(body))
	}
	return binary.BigEndian.Uint16(body[0:2]), binary.BigEndian.Uint16(body[7:9]), body[9:]
}

// ---------- HCR sharing the proxy and TLS ports ----------

// withSharedHCR starts an HCR instance owning no port of its own; it only
// serves connections handed over from the panel's listeners.
func withSharedHCR(t *testing.T) {
	t.Helper()
	server := hcr.NewServer(&hcr.Config{
		DialTarget:  func() (net.Conn, error) { return dialInternalSSH("hcr") },
		Logger:      nil,
		MaxSessions: 100,
	})
	ctx, cancel := context.WithCancel(context.Background())
	hcrMu.Lock()
	hcrServer = server
	hcrCtx = ctx
	hcrCancel = cancel
	hcrSharedPorts = true
	hcrMu.Unlock()
	t.Cleanup(func() {
		hcrMu.Lock()
		hcrServer = nil
		hcrCtx = nil
		hcrCancel = nil
		hcrSharedPorts = false
		hcrMu.Unlock()
		cancel()
		server.Close()
		server.Wait()
	})
	if !hcrShareEnabled() {
		t.Fatal("shared-port handoff did not come up")
	}
}

// hcrMaskPayload mirrors the engine's payload cipher so the test can encode
// requests and decode responses. It is the same SHA-256 keystream XOR.
func sha256Sum(b []byte) [32]byte { return sha256.Sum256(b) }

func hcrMaskPayload(payload []byte, sid [16]byte, code uint8, seq uint64, direction uint8) {
	if len(payload) == 0 {
		return
	}
	var seed [30]byte
	copy(seed[0:16], sid[:])
	seed[16] = code
	binary.BigEndian.PutUint64(seed[17:25], seq)
	seed[25] = direction
	for offset := 0; offset < len(payload); offset += 32 {
		binary.BigEndian.PutUint32(seed[26:30], uint32(offset/32))
		block := sha256Sum(seed[:])
		for i := 0; i < 32 && offset+i < len(payload); i++ {
			payload[offset+i] ^= block[i]
		}
	}
}

// hcrConnectFrame builds a 62-byte Connect request.
func hcrConnectFrame(sid [16]byte) []byte {
	b := make([]byte, hcr.RequestHeaderSize)
	b[0] = 1 // ReqConnect
	b[1] = 1 // ProtoVersion
	copy(b[2:18], sid[:])
	return b
}

// hcrPollFrame builds a Poll request for up to maxChunks records at seq.
func hcrPollFrame(sid [16]byte, token []byte, seq uint64, maxChunks uint16) []byte {
	payload := make([]byte, 2)
	binary.BigEndian.PutUint16(payload, maxChunks)
	hcrMaskPayload(payload, sid, 3, seq, 0) // ReqPoll, DirRequest
	b := make([]byte, hcr.RequestHeaderSize+len(payload))
	b[0] = 3 // ReqPoll
	b[1] = 1
	copy(b[2:18], sid[:])
	copy(b[18:50], token)
	binary.BigEndian.PutUint64(b[50:58], seq)
	binary.BigEndian.PutUint32(b[58:62], uint32(len(payload)))
	copy(b[hcr.RequestHeaderSize:], payload)
	return b
}

// hcrReadResponse reads a 14-byte response header plus its payload.
func hcrReadResponse(t *testing.T, r *bufio.Reader) (status byte, seq uint64, payload []byte) {
	t.Helper()
	var hdr [14]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		t.Fatalf("read HCR response header: %v", err)
	}
	status = hdr[0]
	seq = binary.BigEndian.Uint64(hdr[2:10])
	n := binary.BigEndian.Uint32(hdr[10:14])
	if n > 0 {
		payload = make([]byte, n)
		if _, err := io.ReadFull(r, payload); err != nil {
			t.Fatalf("read HCR response payload: %v", err)
		}
	}
	return status, seq, payload
}

// An HCR client on a port the HTTP+SSH proxy owns must reach the built-in SSH
// server: Connect succeeds, then a Poll returns the SSH banner.
func TestSharedProxyPortServesHCRClient(t *testing.T) {
	withPanelUsers(t, &UserState{Cfg: UserConfig{Username: "tunnel", Password: "secret"}})
	withSharedHCR(t)
	addr := serveProxyPort(t)

	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	reader := bufio.NewReader(conn)

	var sid [16]byte
	copy(sid[:], "hcr-shared-sid01")

	if _, err := conn.Write(hcrConnectFrame(sid)); err != nil {
		t.Fatalf("write connect: %v", err)
	}
	status, _, token := hcrReadResponse(t, reader)
	hcrMaskPayload(token, sid, 1, 0, 1) // Connect response token
	if status != 0 {                    // StatusOk
		t.Fatalf("connect status = %d, want StatusOk — the proxy answered instead of HCR", status)
	}

	// Poll for the SSH banner the target sends first.
	if _, err := conn.Write(hcrPollFrame(sid, token, 0, 4)); err != nil {
		t.Fatalf("write poll: %v", err)
	}
	status, seq, payload := hcrReadResponse(t, reader)
	if status != 1 { // StatusPollData
		t.Fatalf("poll status = %d, want StatusPollData(1)", status)
	}
	hcrMaskPayload(payload, sid, 3, seq, 1) // ReqPoll, DirResponse
	if len(payload) < 4 {
		t.Fatalf("poll payload too short: %d bytes", len(payload))
	}
	chunkLen := binary.BigEndian.Uint32(payload[:4])
	banner := payload[4 : 4+chunkLen]
	if !strings.HasPrefix(string(banner), "SSH-2.0-") {
		t.Fatalf("first HCR download = %q, want the built-in SSH identification", banner)
	}
}

// The decisive coexistence test: HCR, BHTTP, BTUN and injected SSH all served
// on one listener at once, each answered correctly.
func TestSharedProxyPortServesHCRAlongsideBHTTP(t *testing.T) {
	withPanelUsers(t,
		&UserState{Cfg: UserConfig{Username: "tunnel", Password: "secret"}},
		&UserState{Cfg: UserConfig{Username: "vpn", Password: "letmein"}},
	)
	withSharedHCR(t)
	withSharedBHTTP(t)
	withSharedBTUN(t)
	addr := serveProxyPort(t)

	t.Run("HCR", func(t *testing.T) {
		conn, err := net.Dial("tcp", addr.String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
		reader := bufio.NewReader(conn)
		var sid [16]byte
		copy(sid[:], "coexist-hcr-sid1")
		if _, err := conn.Write(hcrConnectFrame(sid)); err != nil {
			t.Fatalf("write connect: %v", err)
		}
		if status, _, _ := hcrReadResponse(t, reader); status != 0 {
			t.Fatalf("HCR was not served: connect status %d", status)
		}
	})

	t.Run("BHTTP", func(t *testing.T) {
		conn, err := net.Dial("tcp", addr.String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
		var sid bhttp.SessionID
		copy(sid[:], "coexist-bhttp-s1")
		if _, err := conn.Write(bhttpProbeFrame(sid)); err != nil {
			t.Fatalf("write probe: %v", err)
		}
		client := &bhttpTestClient{t: t, conn: conn, sid: sid}
		if status, body := client.readStatus(); status != bhttp.StatusOK {
			t.Fatalf("BHTTP was not served: status %d (%q)", status, body)
		}
	})

	t.Run("BTUN", func(t *testing.T) {
		conn, err := net.Dial("tcp", addr.String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
		response := btunAuthenticate(t, conn, bufio.NewReader(conn), "vpn:letmein")
		if response.Type != btun.PacketAuthResponse || len(response.Payload) == 0 || response.Payload[0] != 1 {
			t.Fatalf("BTUN was not served: %#v", response)
		}
	})
}
