package bhttp

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Config struct {
	TargetAddress  string
	SessionTimeout time.Duration
	DialTimeout    time.Duration
	MaxV2Lanes     int
	// DownloadChunk caps bytes per download frame. Zero uses 65536.
	DownloadChunk int
	// MaxBatchCount caps frames requested by one batch. Zero uses 256.
	MaxBatchCount int
	Logger        *log.Logger
	DialTarget    func(string) (net.Conn, error)
	// MaxConnections caps concurrently accepted client sockets across every
	// listener served by this server. Zero or negative disables the cap.
	MaxConnections int
	// MaxSessions caps concurrently tracked BHTTP sessions. Zero or negative
	// disables the cap. A session is one logical tunnel; BHTTP v2 attaches
	// several sockets ("lanes") to the same session.
	MaxSessions int
	// LogConnections enables one log line per accepted socket. Leave it off on
	// busy servers.
	LogConnections bool
}

// StatsSnapshot is the counter set the admin panel reads.
type StatsSnapshot struct {
	StartedAt           time.Time `json:"startedAt"`
	ActiveConnections   int64     `json:"activeConnections"`
	ActiveSessions      int64     `json:"activeSessions"`
	Accepted            uint64    `json:"accepted"`
	ConnectionsRejected uint64    `json:"connectionsRejected"`
	SessionsRejected    uint64    `json:"sessionsRejected"`
	SessionsExpired     uint64    `json:"sessionsExpired"`
	Probes              uint64    `json:"probes"`
	ProbesV2            uint64    `json:"probesV2"`
	HTTPUpgrades        uint64    `json:"httpUpgrades"`
	LanesAttached       uint64    `json:"lanesAttached"`
	LanesRejected       uint64    `json:"lanesRejected"`
	UploadBytes         uint64    `json:"uploadBytes"`
	DownloadBytes       uint64    `json:"downloadBytes"`
	TargetFailures      uint64    `json:"targetFailures"`
	ProtocolErrors      uint64    `json:"protocolErrors"`
}

type counters struct {
	accepted            atomic.Uint64
	connectionsRejected atomic.Uint64
	sessionsRejected    atomic.Uint64
	sessionsExpired     atomic.Uint64
	probes              atomic.Uint64
	probesV2            atomic.Uint64
	httpUpgrades        atomic.Uint64
	lanesAttached       atomic.Uint64
	lanesRejected       atomic.Uint64
	uploadBytes         atomic.Uint64
	downloadBytes       atomic.Uint64
	targetFailures      atomic.Uint64
	protocolErrors      atomic.Uint64
	activeConnections   atomic.Int64
}

type Server struct {
	config   Config
	sessions *SessionManager
	closed   chan struct{}
	once     sync.Once
	wait     sync.WaitGroup
	connMu   sync.Mutex
	active   map[net.Conn]struct{}
	started  time.Time
	stats    counters
}

const (
	bhttpV2Version       = 2
	bhttpV2FeatureLanes  = 1 << 0
	bhttpV2FeatureResume = 1 << 1
	bhttpV2FeatureAck    = 1 << 2
	bhttpV2MaxLanes      = 128
	laneUpload           = 1
	laneDownload         = 2
	laneDuplex           = 3
)

func NewServer(config Config) *Server {
	if config.TargetAddress == "" {
		config.TargetAddress = "127.0.0.1:22"
	}
	if config.SessionTimeout <= 0 {
		config.SessionTimeout = 2 * time.Minute
	}
	if config.DialTimeout <= 0 {
		config.DialTimeout = 10 * time.Second
	}
	if config.MaxV2Lanes <= 0 {
		config.MaxV2Lanes = bhttpV2MaxLanes
	}
	if config.DownloadChunk <= 0 {
		config.DownloadChunk = 65536
	}
	if config.DownloadChunk > MaxDownloadSize {
		config.DownloadChunk = MaxDownloadSize
	}
	if config.MaxBatchCount <= 0 {
		config.MaxBatchCount = 256
	}
	if config.MaxBatchCount > 256 {
		config.MaxBatchCount = 256
	}
	if config.Logger == nil {
		config.Logger = log.Default()
	}
	if config.DialTarget == nil {
		dialer := net.Dialer{Timeout: config.DialTimeout, KeepAlive: 30 * time.Second}
		config.DialTarget = func(address string) (net.Conn, error) {
			connection, err := dialer.Dial("tcp", address)
			if err == nil {
				if tcp, ok := connection.(*net.TCPConn); ok {
					_ = tcp.SetNoDelay(true)
				}
			}
			return connection, err
		}
	}
	server := &Server{
		config:   config,
		sessions: NewSessionManager(config.SessionTimeout),
		closed:   make(chan struct{}),
		active:   make(map[net.Conn]struct{}),
		started:  time.Now(),
	}
	server.sessions.limit = config.MaxSessions
	server.sessions.rejected = &server.stats.sessionsRejected
	server.wait.Add(1)
	go server.cleanupLoop()
	return server
}

func (server *Server) cleanupLoop() {
	defer server.wait.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			removed := server.sessions.Cleanup(now)
			if removed > 0 {
				server.stats.sessionsExpired.Add(uint64(removed))
				server.config.Logger.Printf("cleaned %d stale BHTTP sessions", removed)
			}
		case <-server.closed:
			return
		}
	}
}

func (server *Server) Serve(listener net.Listener) error {
	for {
		connection, err := listener.Accept()
		if err != nil {
			select {
			case <-server.closed:
				return nil
			default:
				return err
			}
		}
		if tcp, ok := connection.(*net.TCPConn); ok {
			_ = tcp.SetNoDelay(true)
		}
		server.stats.accepted.Add(1)
		if !server.track(connection) {
			continue
		}
		server.wait.Add(1)
		go func() {
			defer server.wait.Done()
			server.run(connection)
		}()
	}
}

// ServeConn serves one already-accepted connection, for listeners this server
// does not own. A port shared with SSH or HTTP routes a client here once the
// first bytes have been identified as BHTTP; the connection is then counted,
// capped and closed exactly like one from Serve's own accept loop.
//
// It blocks until the connection ends. It reports whether the connection was
// admitted: a refused connection has already been closed, and the caller must
// not keep using it either way.
func (server *Server) ServeConn(connection net.Conn) bool {
	select {
	case <-server.closed:
		_ = connection.Close()
		return false
	default:
	}
	server.stats.accepted.Add(1)
	if !server.track(connection) {
		return false
	}
	server.wait.Add(1)
	defer server.wait.Done()
	server.run(connection)
	return true
}

// track registers a connection against the socket cap. It reports whether the
// connection was admitted; a rejected connection is closed here.
func (server *Server) track(connection net.Conn) bool {
	server.connMu.Lock()
	// Reject past the socket cap before any protocol work, so a surge cannot
	// exhaust memory the way an unbounded accept loop would.
	if limit := server.config.MaxConnections; limit > 0 && len(server.active) >= limit {
		server.connMu.Unlock()
		rejected := server.stats.connectionsRejected.Add(1)
		if rejected == 1 || rejected%1000 == 0 {
			server.config.Logger.Printf("connection cap reached (%d); rejected %d client(s) so far",
				limit, rejected)
		}
		_ = connection.Close()
		return false
	}
	server.active[connection] = struct{}{}
	server.connMu.Unlock()
	server.stats.activeConnections.Add(1)
	if server.config.LogConnections {
		server.config.Logger.Printf("client %s connected", connection.RemoteAddr())
	}
	return true
}

// run drives one tracked connection to completion and releases it.
func (server *Server) run(connection net.Conn) {
	defer func() {
		server.connMu.Lock()
		delete(server.active, connection)
		server.connMu.Unlock()
		server.stats.activeConnections.Add(-1)
		_ = connection.Close()
		if server.config.LogConnections {
			server.config.Logger.Printf("client %s disconnected", connection.RemoteAddr())
		}
	}()
	if err := server.handleConnection(connection); err != nil && !isNormalClose(err) {
		server.stats.protocolErrors.Add(1)
		server.config.Logger.Printf("client %s: %v", connection.RemoteAddr(), err)
	}
}

func isNormalClose(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "connection reset")
}

func (server *Server) handleConnection(connection net.Conn) error {
	reader := bufio.NewReader(connection)
	first, err := reader.Peek(1)
	if err != nil {
		return err
	}
	if first[0] == ModeProbe {
		request, err := ReadRequest(reader)
		if err != nil {
			return err
		}
		server.stats.probes.Add(1)
		if isV2Probe(request) {
			server.stats.probesV2.Add(1)
		}
		return handleProbeLimit(connection, request, server.config.MaxV2Lanes)
	}
	if first[0] > ModeLane {
		if err := handleHTTPUpgrade(reader, connection); err != nil {
			return err
		}
		server.stats.httpUpgrades.Add(1)
	}
	var laneRole byte
	var laneLease *LaneLease
	defer func() {
		if laneLease != nil {
			laneLease.ReleaseLane()
		}
	}()
	for {
		request, err := ReadRequest(reader)
		if err != nil {
			return err
		}
		if request.Mode == ModeLane {
			if laneLease != nil {
				return errors.New("BHTTP v2 lane already attached")
			}
			role, attached, attachErr := server.attachLane(connection, request)
			if attachErr != nil {
				return attachErr
			}
			laneRole = role
			laneLease = attached
			continue
		}
		if laneRole == laneUpload && request.Mode != ModeUpload {
			return errors.New("BHTTP v2 upload lane received non-upload request")
		}
		if laneRole == laneDownload && request.Mode != ModeDownload &&
			request.Mode != ModeBatch && request.Mode != ModeACK {
			return errors.New("BHTTP v2 download lane received invalid request")
		}
		session := server.sessions.GetOrCreate(request.SID)
		if session == nil {
			_ = WriteStatus(connection, StatusError, []byte("BHTTP session limit reached"))
			return errors.New("BHTTP session limit reached")
		}
		session.touch()
		if err := server.handleRequest(connection, session, request, laneRole != 0); err != nil {
			return err
		}
	}
}

func handleHTTPUpgrade(reader *bufio.Reader, writer io.Writer) error {
	var request bytes.Buffer
	for request.Len() < 64*1024 {
		value, err := reader.ReadByte()
		if err != nil {
			return err
		}
		request.WriteByte(value)
		if bytes.HasSuffix(request.Bytes(), []byte("\r\n\r\n")) {
			return writeAll(writer, []byte("HTTP/1.1 101 DTunnel\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nHTTP/1.1 200 DTunnel\r\n\r\n"))
		}
	}
	return errors.New("HTTP upgrade header is too large")
}

// isV2Probe reports whether a probe payload announces the BHP2 capability
// handshake rather than the original BHP1 profile.
func isV2Probe(request Request) bool {
	clear := Crypt(request.Payload, request.SID, ModeProbe, request.Seq, false)
	return len(clear) == 10 && bytes.Equal(clear[:4], []byte("BHP2")) && clear[4] == bhttpV2Version
}

// Stats returns a snapshot of the server counters for the admin panel.
func (server *Server) Stats() StatsSnapshot {
	return StatsSnapshot{
		StartedAt:           server.started,
		ActiveConnections:   server.stats.activeConnections.Load(),
		ActiveSessions:      int64(server.sessions.Len()),
		Accepted:            server.stats.accepted.Load(),
		ConnectionsRejected: server.stats.connectionsRejected.Load(),
		SessionsRejected:    server.stats.sessionsRejected.Load(),
		SessionsExpired:     server.stats.sessionsExpired.Load(),
		Probes:              server.stats.probes.Load(),
		ProbesV2:            server.stats.probesV2.Load(),
		HTTPUpgrades:        server.stats.httpUpgrades.Load(),
		LanesAttached:       server.stats.lanesAttached.Load(),
		LanesRejected:       server.stats.lanesRejected.Load(),
		UploadBytes:         server.stats.uploadBytes.Load(),
		DownloadBytes:       server.stats.downloadBytes.Load(),
		TargetFailures:      server.stats.targetFailures.Load(),
		ProtocolErrors:      server.stats.protocolErrors.Load(),
	}
}

func handleProbe(writer io.Writer, request Request) error {
	return handleProbeLimit(writer, request, bhttpV2MaxLanes)
}

func handleProbeLimit(writer io.Writer, request Request, maxLanes int) error {
	clear := Crypt(request.Payload, request.SID, ModeProbe, request.Seq, false)
	if len(clear) == 10 && bytes.Equal(clear[:4], []byte("BHP2")) && clear[4] == bhttpV2Version {
		response := make([]byte, 14)
		copy(response[:4], []byte("BHP2"))
		response[4] = bhttpV2Version
		binary.BigEndian.PutUint32(response[6:10], bhttpV2FeatureLanes|bhttpV2FeatureResume|bhttpV2FeatureAck)
		binary.BigEndian.PutUint32(response[10:14], uint32(maxLanes))
		return WriteStatus(writer, StatusOK, Crypt(response, request.SID, ModeProbe, request.Seq, true))
	}
	if len(clear) < 10 || !bytes.Equal(clear[:4], []byte("BHP1")) || clear[4] != 1 {
		return WriteStatus(writer, StatusError, []byte("invalid BHTTP v1 probe"))
	}
	submode := clear[5]
	parameter := int(binary.BigEndian.Uint32(clear[6:10]))
	if submode > ModeACK {
		return WriteStatus(writer, StatusError, []byte("unsupported BHTTP probe mode"))
	}
	expected := 10
	if submode == ModeUpload && parameter >= 10 {
		expected = parameter
	}
	if len(clear) != expected {
		return WriteStatus(writer, StatusError, []byte("invalid BHTTP v1 probe length"))
	}
	for index := 10; index < len(clear); index++ {
		if clear[index] != byte(index*31) {
			return WriteStatus(writer, StatusError, []byte("invalid BHTTP v1 probe pattern"))
		}
	}
	responseSize := 10
	if submode == ModeDownload && parameter > responseSize {
		responseSize = parameter
	}
	if responseSize > MaxPayload {
		return WriteStatus(writer, StatusError, []byte("BHTTP v1 probe too large"))
	}
	response := make([]byte, responseSize)
	copy(response[:4], []byte("BHP1"))
	response[4] = 1
	response[5] = submode
	binary.BigEndian.PutUint32(response[6:10], uint32(parameter))
	for index := 10; index < len(response); index++ {
		response[index] = byte(index * 31)
	}
	encrypted := Crypt(response, request.SID, ModeProbe, request.Seq, true)
	count := 1
	if submode == ModeACK {
		count = parameter
		if count < 1 {
			count = 1
		}
		if count > 256 {
			count = 256
		}
	}
	for index := 0; index < count; index++ {
		if err := WriteStatus(writer, StatusOK, encrypted); err != nil {
			return err
		}
	}
	return nil
}

func (server *Server) handleRequest(writer io.Writer, session *Session, request Request, version2 bool) error {
	switch request.Mode {
	case ModeUpload:
		payload := request.Payload
		if len(payload) > 0 {
			payload = Crypt(payload, request.SID, request.Mode, request.Seq, false)
		}
		if request.Seq == 0 && len(payload) == 0 {
			if err := session.OpenTarget(server.config.TargetAddress, server.config.DialTarget); err != nil {
				server.stats.targetFailures.Add(1)
				return WriteStatus(writer, StatusError, []byte("SSH target unavailable"))
			}
			return WriteStatus(writer, StatusOK, nil)
		}
		if err := session.OpenTarget(server.config.TargetAddress, server.config.DialTarget); err != nil {
			server.stats.targetFailures.Add(1)
			return WriteStatus(writer, StatusError, []byte("SSH target unavailable"))
		}
		if err := session.WriteUpload(request.Seq, payload); err != nil {
			return WriteStatus(writer, StatusError, []byte("SSH upload failed"))
		}
		server.stats.uploadBytes.Add(uint64(len(payload)))
		if !version2 {
			return WriteStatus(writer, StatusOK, nil)
		}
		ack := make([]byte, 9)
		if sequence, ok := session.UploadCommitted(); ok {
			ack[0] = 1
			binary.BigEndian.PutUint64(ack[1:], sequence)
		}
		return WriteStatus(writer, StatusOK, ack)

	case ModeDownload:
		chunks := session.AssignDownload(request.Seq, 1, server.config.DownloadChunk)
		server.stats.downloadBytes.Add(uint64(len(chunks[0])))
		return WriteDownload(writer, request.SID, request.Mode, request.Seq, chunks[0])

	case ModeBatch:
		clear := Crypt(request.Payload, request.SID, request.Mode, request.Seq, false)
		if len(clear) != 6 {
			return WriteStatus(writer, StatusError, []byte("invalid BHTTP batch request"))
		}
		limit := int(binary.BigEndian.Uint32(clear[:4]))
		count := int(binary.BigEndian.Uint16(clear[4:6]))
		if limit < 1 {
			limit = 1
		}
		if limit > MaxDownloadSize {
			limit = MaxDownloadSize
		}
		if count < 1 {
			count = 1
		}
		if count > server.config.MaxBatchCount {
			count = server.config.MaxBatchCount
		}
		chunks := session.AssignDownload(request.Seq, count, limit)
		for offset, chunk := range chunks {
			server.stats.downloadBytes.Add(uint64(len(chunk)))
			if err := WriteDownload(writer, request.SID, request.Mode, request.Seq+uint64(offset), chunk); err != nil {
				return err
			}
		}
		return nil

	case ModeACK:
		session.Acknowledge(request.Seq)
		return WriteStatus(writer, StatusOK, nil)
	}
	return fmt.Errorf("unsupported BHTTP mode %d", request.Mode)
}

func (server *Server) attachLane(writer io.Writer, request Request) (byte, *LaneLease, error) {
	clear := Crypt(request.Payload, request.SID, ModeLane, request.Seq, false)
	if len(clear) != 12 || !bytes.Equal(clear[:4], []byte("BLN2")) || clear[4] != bhttpV2Version {
		server.stats.lanesRejected.Add(1)
		_ = WriteStatus(writer, StatusError, []byte("invalid BHTTP v2 lane hello"))
		return 0, nil, errors.New("invalid BHTTP v2 lane hello")
	}
	role := clear[5]
	if role != laneUpload && role != laneDownload && role != laneDuplex {
		server.stats.lanesRejected.Add(1)
		_ = WriteStatus(writer, StatusError, []byte("invalid BHTTP v2 lane role"))
		return 0, nil, errors.New("invalid BHTTP v2 lane role")
	}
	requireResume := binary.BigEndian.Uint16(clear[6:8])&1 != 0
	laneID := binary.BigEndian.Uint32(clear[8:12])
	session, resumed := server.sessions.Get(request.SID)
	if requireResume && !resumed {
		server.stats.lanesRejected.Add(1)
		_ = WriteStatus(writer, StatusError, []byte("BHTTP v2 session expired"))
		return 0, nil, errors.New("BHTTP v2 resume rejected: session expired")
	}
	if !resumed {
		session, _ = server.sessions.GetOrCreateState(request.SID)
		if session == nil {
			server.stats.lanesRejected.Add(1)
			_ = WriteStatus(writer, StatusError, []byte("BHTTP session limit reached"))
			return 0, nil, errors.New("BHTTP session limit reached")
		}
	}
	lease, acquired := session.AcquireLane(laneID, server.config.MaxV2Lanes)
	if !acquired {
		server.stats.lanesRejected.Add(1)
		_ = WriteStatus(writer, StatusError, []byte("BHTTP v2 lane limit exceeded"))
		return 0, nil, errors.New("BHTTP v2 lane limit exceeded")
	}
	attached := true
	defer func() {
		if attached {
			lease.ReleaseLane()
		}
	}()
	if err := session.OpenTarget(server.config.TargetAddress, server.config.DialTarget); err != nil {
		server.stats.targetFailures.Add(1)
		_ = WriteStatus(writer, StatusError, []byte("SSH target unavailable"))
		return 0, nil, err
	}
	response := make([]byte, 18)
	copy(response[:4], []byte("BOK2"))
	response[4] = bhttpV2Version
	if resumed {
		response[5] = 1
	}
	binary.BigEndian.PutUint32(response[6:10], bhttpV2FeatureLanes|bhttpV2FeatureResume|bhttpV2FeatureAck)
	if sequence, ok := session.UploadCommitted(); ok {
		binary.BigEndian.PutUint64(response[10:18], sequence+1)
	}
	encoded := Crypt(response, request.SID, ModeLane, request.Seq, true)
	if err := WriteStatus(writer, StatusOK, encoded); err != nil {
		return 0, nil, err
	}
	session.touch()
	attached = false
	server.stats.lanesAttached.Add(1)
	return role, lease, nil
}

func (server *Server) Close() {
	server.once.Do(func() {
		close(server.closed)
		server.connMu.Lock()
		connections := make([]net.Conn, 0, len(server.active))
		for connection := range server.active {
			connections = append(connections, connection)
		}
		server.connMu.Unlock()
		for _, connection := range connections {
			_ = connection.Close()
		}
		server.sessions.Close()
	})
}

func (server *Server) Wait() {
	server.wait.Wait()
}
