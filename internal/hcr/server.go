package hcr

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// HCR SERVER (0.0.3 - Patch 1) - RECONSTRUÇÃO EM GOLANG
//
// O HCR (HTTP/Custom Relay) atua como servidor proxy/túnel de alta performance
// para o ecossistema UDP-Custom / HTTP Custom. O protocolo encapsula fluxos
// arbitrários de rede (tipicamente conexões SSH no alvo 127.0.0.1:22) em pacotes
// binários estruturados sobre TCP ou TLS (porta padrão :8880).
//
// ESTRUTURA DO PROTOCOLO BINÁRIO REVERSO:
// 1. Requisição do Cliente (Client Request Header) - 62 bytes fixos:
//    - [0:1]   Code (uint8): Código da operação (1..6)
//    - [1:2]   Version (uint8): Versão do protocolo (deve ser 0x01)
//    - [2:18]  SessionID ([16]byte): Identificador UUID da sessão
//    - [18:50] AuthKey ([32]byte): Token de autenticação / PSK
//    - [50:58] Sequence (uint64 BigEndian): Offset de sequência de stream
//    - [58:62] PayloadLen (uint32 BigEndian): Tamanho do payload subsequente
//    - [62:]   Payload ([]byte): Dados da requisição
//
// 2. Resposta do Servidor (Server Response Header) - 14 bytes fixos:
//    - [0:1]   Status (uint8): 0=OK, 3=Closed, 4=Error
//    - [1:2]   Version (uint8): Versão do protocolo (0x01)
//    - [2:10]  Sequence (uint64 BigEndian): Offset de sequência confirmado
//    - [10:14] PayloadLen (uint32 BigEndian): Tamanho do payload de resposta
//    - [14:]   Payload ([]byte): Dados da resposta
// ============================================================================

const (
	VersionString = "0.0.3 - Patch 1"
	ProtoVersion  = 1

	// Tamanhos dos cabeçalhos binários
	RequestHeaderSize  = 62 // 1 + 1 + 16 + 32 + 8 + 4
	ResponseHeaderSize = 14 // 1 + 1 + 8 + 4

	// Limite máximo de frame por payload (256 KB) deduzido de FUN_0065c580 (0x40000)
	MaxPayloadLimit = 262144
)

// Códigos de Requisição (Request Codes)
const (
	ReqConnect uint8 = 1 // Inicia nova sessão e conecta ao alvo
	ReqData    uint8 = 2 // Envia dados do cliente para o alvo (Upload)
	ReqPoll    uint8 = 3 // Solicita dados recebidos do alvo (Download/Long-polling)
	ReqAck     uint8 = 4 // Confirmação de recebimento pelo cliente até Sequence
	ReqClose   uint8 = 5 // Encerra explicitamente a sessão
	ReqPing    uint8 = 6 // Keepalive / Checagem de status da sessão
)

// Códigos de Resposta (Response Status Codes)
const (
	StatusOk          uint8 = 0 // Operação bem-sucedida (ReqConnect, ReqData, ReqAck, ReqPing)
	StatusPollData    uint8 = 1 // Download com dados entregues (ReqPoll, FUN_00664300 linha 345282)
	StatusPollTimeout uint8 = 2 // Long-poll expirado sem dados no intervalo (ReqPoll, FUN_00664300 linha 345408)
	StatusClosed      uint8 = 3 // Sessão ou conexão com o alvo encerrada (FUN_00664300 linha 345311)
	StatusError       uint8 = 4 // Erro / Requisição rejeitada
)

// Erros do Protocolo
var (
	ErrInvalidRequest   = errors.New("INVALID_REQUEST")
	ErrAuthFailed       = errors.New("AUTH_FAILED")
	ErrTargetBroken     = errors.New("TARGET_BROKEN")
	ErrTargetUnavail    = errors.New("target_unavailable")
	ErrGlobalLimit      = errors.New("global_session_limit")
	ErrSourceLimit      = errors.New("source_session_limit")
	ErrAckInvalid       = errors.New("ACK_INVALID")
	ErrSessionCollision = errors.New("session_id_collision")
)

// Direções do Fluxo para Cifra de Payload (de FUN_0065d160 em hcr.c)
const (
	DirRequest  uint8 = 0 // Cliente -> Servidor (Request payload)
	DirResponse uint8 = 1 // Servidor -> Cliente (Response payload)
)

// maskPayload aplica a cifra de fluxo simétrica (CTR-mode com SHA-256) no payload
// conforme a implementação reversa da função FUN_0065d160 em hcr.c.
// Semente de 30 bytes:
// [0:16]  SessionID (16 bytes)
// [16]    Code (uint8)
// [17:25] Sequence (uint64 BigEndian)
// [25]    Direction (uint8: 1=Req, 2=Resp)
// [26:30] BlockIndex (uint32 BigEndian)
func maskPayload(payload []byte, sessionID [16]byte, code uint8, seq uint64, direction uint8) {
	pLen := len(payload)
	if pLen == 0 {
		return
	}
	var seed [30]byte
	copy(seed[0:16], sessionID[:])
	seed[16] = code
	binary.BigEndian.PutUint64(seed[17:25], seq)
	seed[25] = direction

	for offset := 0; offset < pLen; offset += 32 {
		blockIndex := uint32(offset / 32)
		binary.BigEndian.PutUint32(seed[26:30], blockIndex)
		block := sha256.Sum256(seed[:])
		chunkLen := 32
		if pLen-offset < 32 {
			chunkLen = pLen - offset
		}
		p := payload[offset : offset+chunkLen]
		b := block[:chunkLen]
		rem := chunkLen
		for rem >= 8 {
			v1 := binary.LittleEndian.Uint64(p)
			v2 := binary.LittleEndian.Uint64(b)
			binary.LittleEndian.PutUint64(p, v1^v2)
			p = p[8:]
			b = b[8:]
			rem -= 8
		}
		for i := 0; i < rem; i++ {
			p[i] ^= b[i]
		}
	}
}

// Config holds the HCR engine settings. The panel owns the listeners and TLS,
// so this carries no listen address, transport or certificate: the integration
// hands the engine an already-accepted connection (ServeConn) or a plain
// listener (Serve).
type Config struct {
	// TargetAddr is dialed for each session when DialTarget is nil. In the
	// panel this stays empty and DialTarget points at the built-in SSH server.
	TargetAddr string
	// DialTarget, when set, supplies the per-session target connection. The
	// panel uses it to hand every HCR session to its own in-process SSH server,
	// so HCR logins are panel accounts with the usual limits — no system sshd.
	DialTarget func() (net.Conn, error)
	// Logger receives engine events. Nil uses a discard logger.
	Logger *slog.Logger

	MaxConnections       int
	MaxSessions          int
	MaxSourceSessions    int
	DownloadPollTimeout  time.Duration
	MaxDownloadFrame     int
	IdleSessionTimeout   time.Duration
	SessionStatsInterval time.Duration
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func shortID(id [16]byte) string {
	return hex.EncodeToString(id[:4])
}

func reqCodeNameShort(c uint8) string {
	switch c {
	case ReqConnect:
		return "Connect"
	case ReqData:
		return "Data"
	case ReqPoll:
		return "Poll"
	case ReqAck:
		return "Ack"
	case ReqClose:
		return "Close"
	case ReqPing:
		return "Ping"
	default:
		return fmt.Sprintf("Code(%d)", c)
	}
}

func statusCodeNameShort(s uint8) string {
	switch s {
	case StatusOk:
		return "Ok(0)"
	case StatusPollData:
		return "PollData(1)"
	case StatusPollTimeout:
		return "PollTimeout(2)"
	case StatusClosed:
		return "Closed(3)"
	case StatusError:
		return "Error(4)"
	default:
		return fmt.Sprintf("Status(%d)", s)
	}
}

func reqCodeName(c uint8) string {
	return reqCodeNameShort(c)
}

func statusCodeName(s uint8) string {
	return statusCodeNameShort(s)
}

// RequestHeader representa o cabeçalho de 62 bytes enviado pelo cliente
type RequestHeader struct {
	Code       uint8
	Version    uint8
	SessionID  [16]byte
	AuthKey    [32]byte
	Sequence   uint64
	PayloadLen uint32
}

// ResponseHeader representa o cabeçalho de 14 bytes enviado pelo servidor
type ResponseHeader struct {
	Status     uint8
	Version    uint8
	Sequence   uint64
	PayloadLen uint32
}

// UnmarshalRequestHeader lê e decodifica os 62 bytes fixos da requisição
func UnmarshalRequestHeader(buf []byte) (*RequestHeader, error) {
	if len(buf) < RequestHeaderSize {
		return nil, io.ErrUnexpectedEOF
	}
	code := buf[0]
	if code < 1 || code > 6 {
		return nil, ErrInvalidRequest
	}
	version := buf[1]
	if version != ProtoVersion {
		return nil, ErrInvalidRequest
	}

	h := &RequestHeader{
		Code:       code,
		Version:    version,
		Sequence:   binary.BigEndian.Uint64(buf[50:58]),
		PayloadLen: binary.BigEndian.Uint32(buf[58:62]),
	}
	copy(h.SessionID[:], buf[2:18])
	copy(h.AuthKey[:], buf[18:50])

	if h.PayloadLen > MaxPayloadLimit {
		return nil, ErrInvalidRequest
	}
	return h, nil
}

// MarshalResponseHeader serializa o cabeçalho de 14 bytes do servidor
func MarshalResponseHeader(status uint8, seq uint64, payloadLen uint32) []byte {
	buf := make([]byte, ResponseHeaderSize)
	buf[0] = status
	buf[1] = ProtoVersion
	binary.BigEndian.PutUint64(buf[2:10], seq)
	binary.BigEndian.PutUint32(buf[10:14], payloadLen)
	return buf
}

// DownloadFrame armazena um pedaço de dados vindo do alvo para entrega ao cliente
type DownloadFrame struct {
	Seq  uint64
	Data []byte
}

// Session mantém o estado do túnel entre o cliente HCR e a conexão TCP com o alvo
type Session struct {
	ID        [16]byte
	Token     [32]byte
	SourceIP  string
	Target    net.Conn
	CreatedAt time.Time

	mu sync.Mutex

	// Controle de escrita no alvo (Upload)
	targetClosed  bool
	targetWriteCh chan []byte       // Fila assíncrona FIFO para escrita contínua no alvo
	writeSeq      uint64            // Próximo pacote de upload esperado do cliente (0, 1, 2, ...)
	upBuffer      map[uint64][]byte // Buffer de upload para pacotes recebidos fora de ordem

	// Controle de leitura do alvo (Download/Poll)
	cond         *sync.Cond
	dataNotify   chan struct{} // Canal de broadcast (fechado para acordar todos os polls simultâneos)
	downBuffer   []*DownloadFrame
	downSeq      uint64 // Próximo offset a ser atribuído para dados lidos do alvo
	ackSeq       uint64 // Offset confirmado pelo cliente via REQ_ACK
	hasAcked     bool   // Indica se o cliente já enviou ao menos um ACK
	deliveredSeq uint64 // Maior offset entregue ao cliente
	pendingBytes int    // Total de bytes acumulados no buffer de download
	maxFrame     int    // Tamanho máximo por frame lido do alvo

	lastActive atomic.Int64 // Unix nanoseconds
}

// notifyDataLocked fecha o canal de notificação atual (acordando todos os workers de poll em broadcast)
// e cria um novo canal vazio. DEVE ser chamado com s.mu bloqueado.
func (s *Session) notifyDataLocked() {
	if s.dataNotify != nil {
		close(s.dataNotify)
		s.dataNotify = make(chan struct{})
	}
}

func (s *Session) touch() {
	s.lastActive.Store(time.Now().UnixNano())
}

func (s *Session) isIdle(timeout time.Duration) bool {
	last := s.lastActive.Load()
	return time.Since(time.Unix(0, last)) > timeout
}

func (s *Session) hasFramesFrom(seq uint64) bool {
	if len(s.downBuffer) == 0 {
		return false
	}
	firstSeq := s.downBuffer[0].Seq
	lastSeq := s.downBuffer[len(s.downBuffer)-1].Seq
	return seq >= firstSeq && seq <= lastSeq
}

func (s *Session) getFramesFrom(startSeq uint64, maxChunks int, maxBytes int) []*DownloadFrame {
	if len(s.downBuffer) == 0 {
		return nil
	}
	firstSeq := s.downBuffer[0].Seq
	if startSeq < firstSeq {
		return nil
	}
	startIndex := int(startSeq - firstSeq)
	if startIndex >= len(s.downBuffer) {
		return nil
	}
	var result []*DownloadFrame
	totalBytes := 0
	for i := startIndex; i < len(s.downBuffer) && len(result) < maxChunks; i++ {
		f := s.downBuffer[i]
		frameBytes := len(f.Data) + 4
		if len(result) > 0 && totalBytes+frameBytes > maxBytes {
			break
		}
		result = append(result, f)
		totalBytes += frameBytes
	}
	return result
}

// SessionManager gerencia o ciclo de vida e limites das sessões ativas
type SessionManager struct {
	mu          sync.RWMutex
	sessions    map[[16]byte]*Session
	sourceCount map[string]int

	cfg    *Config
	logger *slog.Logger
}

func NewSessionManager(cfg *Config, logger *slog.Logger) *SessionManager {
	return &SessionManager{
		sessions:    make(map[[16]byte]*Session),
		sourceCount: make(map[string]int),
		cfg:         cfg,
		logger:      logger,
	}
}

func (m *SessionManager) CreateSession(id [16]byte, sourceIP string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Validação de colisão de ID
	if _, exists := m.sessions[id]; exists {
		return nil, ErrSessionCollision
	}

	// Validação de limite global de sessões
	if m.cfg.MaxSessions > 0 && len(m.sessions) >= m.cfg.MaxSessions {
		return nil, ErrGlobalLimit
	}

	// Validação de limite de sessões por IP de origem
	if m.cfg.MaxSourceSessions > 0 {
		if count := m.sourceCount[sourceIP]; count >= m.cfg.MaxSourceSessions {
			return nil, ErrSourceLimit
		}
	}

	// Open the per-session target. In the panel this is the built-in SSH server
	// (DialTarget); standalone it dials TargetAddr over TCP.
	var targetConn net.Conn
	var err error
	if m.cfg.DialTarget != nil {
		targetConn, err = m.cfg.DialTarget()
	} else {
		targetConn, err = net.DialTimeout("tcp", m.cfg.TargetAddr, 5*time.Second)
	}
	if err != nil {
		m.logger.Warn("target_unavailable", "target", m.cfg.TargetAddr, "err", err)
		return nil, ErrTargetUnavail
	}

	if tcpConn, ok := targetConn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetReadBuffer(1024 * 1024)
		_ = tcpConn.SetWriteBuffer(1024 * 1024)
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	maxFrame := m.cfg.MaxDownloadFrame
	if maxFrame <= 0 || maxFrame > MaxPayloadLimit-4 {
		maxFrame = 6144
	}

	sess := &Session{
		ID:            id,
		SourceIP:      sourceIP,
		Target:        targetConn,
		CreatedAt:     time.Now(),
		dataNotify:    make(chan struct{}),
		targetWriteCh: make(chan []byte, 2048),
		upBuffer:      make(map[uint64][]byte),
		maxFrame:      maxFrame,
	}
	if _, err := rand.Read(sess.Token[:]); err != nil {
		targetConn.Close()
		return nil, fmt.Errorf("token_generation_failed")
	}
	sess.cond = sync.NewCond(&sess.mu)
	sess.touch()

	m.sessions[id] = sess
	m.sourceCount[sourceIP]++

	// Goroutines assíncronas para streaming com o alvo (Upload e Download desacoplados)
	go m.writeTargetLoop(sess)
	go m.readTargetLoop(sess)

	return sess, nil
}

// writeTargetLoop consome continuamente a fila de upload e grava no alvo TCP de forma sequencial
func (m *SessionManager) writeTargetLoop(s *Session) {
	for data := range s.targetWriteCh {
		if len(data) == 0 {
			continue
		}
		if _, err := s.Target.Write(data); err != nil {
			s.mu.Lock()
			if !s.targetClosed {
				s.targetClosed = true
				s.notifyDataLocked()
			}
			s.mu.Unlock()
			break
		}
	}
}

func (m *SessionManager) GetSession(id [16]byte) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sess, ok := m.sessions[id]
	return sess, ok
}

// Len reports how many sessions are currently tracked.
func (m *SessionManager) Len() int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return int64(len(m.sessions))
}

func (m *SessionManager) CloseSession(id [16]byte) {
	m.mu.Lock()
	sess, ok := m.sessions[id]
	if !ok {
		m.mu.Unlock()
		return
	}
	delete(m.sessions, id)
	if m.sourceCount[sess.SourceIP] > 0 {
		m.sourceCount[sess.SourceIP]--
		if m.sourceCount[sess.SourceIP] == 0 {
			delete(m.sourceCount, sess.SourceIP)
		}
	}
	m.mu.Unlock()

	sess.mu.Lock()
	if !sess.targetClosed {
		sess.targetClosed = true
		sess.Target.Close()
		sess.notifyDataLocked()
	}
	sess.mu.Unlock()
}

// CloseAll encerra todas as conexões de sessões ativas (durante o shutdown do servidor)
func (m *SessionManager) CloseAll() {
	m.mu.Lock()
	var toClose []*Session
	for _, sess := range m.sessions {
		toClose = append(toClose, sess)
	}
	m.sessions = make(map[[16]byte]*Session)
	m.sourceCount = make(map[string]int)
	m.mu.Unlock()

	for _, sess := range toClose {
		sess.mu.Lock()
		if !sess.targetClosed {
			sess.targetClosed = true
			sess.Target.Close()
			sess.notifyDataLocked()
		}
		sess.mu.Unlock()
	}
}

// readTargetLoop lê os dados enviados pelo servidor alvo (ex: banner SSH) e enfileira no buffer de download
func (m *SessionManager) readTargetLoop(s *Session) {
	buf := make([]byte, s.maxFrame)
	for {
		// Controle de fluxo de 4MB (FUN_0065e1a0 em hcr.c):
		// Se pendingBytes >= 4MB, aguarda no broadcast do canal até que ACKs liberem espaço
		s.mu.Lock()
		for s.pendingBytes >= 4*1024*1024 && !s.targetClosed {
			notifyCh := s.dataNotify
			s.mu.Unlock()
			<-notifyCh
			s.mu.Lock()
		}
		if s.targetClosed {
			s.mu.Unlock()
			break
		}
		readSize := s.maxFrame
		if remain := 4*1024*1024 - s.pendingBytes; remain < readSize {
			readSize = remain
		}
		s.mu.Unlock()

		n, err := s.Target.Read(buf[:readSize])
		if n > 0 {
			s.mu.Lock()
			dataCopy := make([]byte, n)
			copy(dataCopy, buf[:n])

			frame := &DownloadFrame{
				Seq:  s.downSeq,
				Data: dataCopy,
			}
			s.downBuffer = append(s.downBuffer, frame)
			s.downSeq++
			s.pendingBytes += n
			s.touch()
			s.notifyDataLocked()
			s.mu.Unlock()
		}
		if err != nil {
			s.mu.Lock()
			s.targetClosed = true
			s.notifyDataLocked()
			s.mu.Unlock()
			break
		}
	}
}

// ReapIdleSessions limpa sessões inativas periodicamente
func (m *SessionManager) ReapIdleSessions() int {
	var toClose [][16]byte

	m.mu.RLock()
	for id, sess := range m.sessions {
		if sess.isIdle(m.cfg.IdleSessionTimeout) {
			toClose = append(toClose, id)
		}
	}
	m.mu.RUnlock()

	for _, id := range toClose {
		m.CloseSession(id)
	}
	return len(toClose)
}

// ============================================================================
// HCR Server Core
// ============================================================================

// ---------- Stats ----------

type counters struct {
	accepted          atomic.Uint64
	connectionsReject atomic.Uint64
	activeConns       atomic.Int64
	sessionsCreated   atomic.Uint64
	sessionsRejected  atomic.Uint64
	uploadBytes       atomic.Uint64
	downloadBytes     atomic.Uint64
	protocolErrors    atomic.Uint64
}

// StatsSnapshot is what the admin panel reads.
type StatsSnapshot struct {
	StartedAt           time.Time `json:"startedAt"`
	ActiveConnections   int64     `json:"activeConnections"`
	ActiveSessions      int64     `json:"activeSessions"`
	Accepted            uint64    `json:"accepted"`
	ConnectionsRejected uint64    `json:"connectionsRejected"`
	SessionsCreated     uint64    `json:"sessionsCreated"`
	SessionsRejected    uint64    `json:"sessionsRejected"`
	UploadBytes         uint64    `json:"uploadBytes"`
	DownloadBytes       uint64    `json:"downloadBytes"`
	ProtocolErrors      uint64    `json:"protocolErrors"`
}

// Server is the embeddable HCR engine. The panel owns listeners and TLS; the
// server only speaks the plaintext HCR frame protocol on a connection handed to
// Serve or ServeConn.
type Server struct {
	cfg      *Config
	sessions *SessionManager
	logger   *slog.Logger
	sem      chan struct{}
	started  time.Time
	stats    counters

	closed    chan struct{}
	closeOnce sync.Once
	wait      sync.WaitGroup
}

// NewServer builds an HCR engine. Logger defaults to a discard logger.
func NewServer(cfg *Config) *Server {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	if cfg.DownloadPollTimeout <= 0 {
		cfg.DownloadPollTimeout = 10 * time.Second
	}
	if cfg.IdleSessionTimeout <= 0 {
		cfg.IdleSessionTimeout = 2 * time.Minute
	}
	if cfg.DownloadPollTimeout <= 0 {
		cfg.DownloadPollTimeout = 8 * time.Second
	}
	if cfg.MaxDownloadFrame <= 0 || cfg.MaxDownloadFrame > MaxPayloadLimit-4 {
		cfg.MaxDownloadFrame = 6144
	}
	var sem chan struct{}
	if cfg.MaxConnections > 0 {
		sem = make(chan struct{}, cfg.MaxConnections)
	}
	server := &Server{
		cfg:      cfg,
		sessions: NewSessionManager(cfg, logger),
		logger:   logger,
		sem:      sem,
		started:  time.Now(),
		closed:   make(chan struct{}),
	}
	if cfg.SessionStatsInterval > 0 {
		server.wait.Add(1)
		go server.sessionStatsLoop()
	}
	return server
}

// Serve accepts plaintext HCR connections on a listener the panel owns. TLS, if
// any, is terminated by the panel's TLS forwarder before this point.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	s.wait.Add(1)
	defer s.wait.Done()
	go s.idleReaperLoop(ctx)
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-s.closed:
				return nil
			case <-ctx.Done():
				return nil
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if !s.admit(conn) {
			continue
		}
		s.wait.Add(1)
		go func(c net.Conn) {
			defer s.wait.Done()
			defer s.release(c)
			s.serve(ctx, c)
		}(conn)
	}
}

// ServeConn serves one already-accepted, already-classified plaintext
// connection — the shared-port handoff path. It blocks until the connection
// ends and reports whether it was admitted.
func (s *Server) ServeConn(ctx context.Context, conn net.Conn) bool {
	select {
	case <-s.closed:
		_ = conn.Close()
		return false
	default:
	}
	if !s.admit(conn) {
		return false
	}
	s.wait.Add(1)
	defer s.wait.Done()
	defer s.release(conn)
	s.serve(ctx, conn)
	return true
}

// admit charges a connection against the max-connections cap.
func (s *Server) admit(conn net.Conn) bool {
	s.stats.accepted.Add(1)
	if s.sem != nil {
		select {
		case s.sem <- struct{}{}:
		default:
			s.stats.connectionsReject.Add(1)
			_ = conn.Close()
			return false
		}
	}
	s.stats.activeConns.Add(1)
	return true
}

func (s *Server) release(conn net.Conn) {
	if s.sem != nil {
		<-s.sem
	}
	s.stats.activeConns.Add(-1)
	_ = conn.Close()
}

// serve runs the HCR frame loop on one connection.
func (s *Server) serve(ctx context.Context, conn net.Conn) {
	remote := conn.RemoteAddr().String()
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
	}
	hdrBuf := make([]byte, RequestHeaderSize)
	for {
		if _, err := io.ReadFull(conn, hdrBuf); err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				s.logger.Warn("read_header_failed", "remote", remote, "err", err)
			}
			return
		}
		req, err := UnmarshalRequestHeader(hdrBuf)
		if err != nil {
			s.stats.protocolErrors.Add(1)
			s.logger.Warn("unmarshal_header_failed", "remote", remote, "err", err)
			return
		}
		var payload []byte
		if req.PayloadLen > 0 {
			payload = make([]byte, req.PayloadLen)
			if _, err := io.ReadFull(conn, payload); err != nil {
				s.logger.Warn("read_payload_failed", "remote", remote, "err", err)
				return
			}
			maskPayload(payload, req.SessionID, req.Code, req.Sequence, DirRequest)
		}
		if s.dispatchRequest(ctx, conn, req, payload) {
			return
		}
	}
}

// Close stops the server: no new sessions, all existing ones dropped.
func (s *Server) Close() {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.sessions.CloseAll()
	})
}

// Wait blocks until every serving goroutine has returned.
func (s *Server) Wait() { s.wait.Wait() }

// Stats returns a counter snapshot for the admin panel.
func (s *Server) Stats() StatsSnapshot {
	return StatsSnapshot{
		StartedAt:           s.started,
		ActiveConnections:   s.stats.activeConns.Load(),
		ActiveSessions:      s.sessions.Len(),
		Accepted:            s.stats.accepted.Load(),
		ConnectionsRejected: s.stats.connectionsReject.Load(),
		SessionsCreated:     s.stats.sessionsCreated.Load(),
		SessionsRejected:    s.stats.sessionsRejected.Load(),
		UploadBytes:         s.stats.uploadBytes.Load(),
		DownloadBytes:       s.stats.downloadBytes.Load(),
		ProtocolErrors:      s.stats.protocolErrors.Load(),
	}
}

// dispatchRequest processa os códigos de operação 1..6
func (s *Server) dispatchRequest(ctx context.Context, conn net.Conn, req *RequestHeader, payload []byte) bool {
	remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	if req.Code != ReqConnect {
		sess, ok := s.sessions.GetSession(req.SessionID)
		if !ok {
			s.writeResponse(conn, req.SessionID, req.Code, StatusError, req.Sequence, []byte(ErrAuthFailed.Error()))
			return true
		}
		if subtle.ConstantTimeCompare(sess.Token[:], req.AuthKey[:]) != 1 {
			s.writeResponse(conn, req.SessionID, req.Code, StatusError, req.Sequence, []byte(ErrAuthFailed.Error()))
			return true
		}
	}

	switch req.Code {
	case ReqConnect: // 1: Iniciar sessão
		// Validações estritas do protocolo (de FUN_00663a00):
		// - Sequence deve ser 0
		// - PayloadLen deve ser 0
		// - SessionID não pode ser nulo
		var zeroID [16]byte
		var zeroToken [32]byte
		if req.Sequence != 0 || req.PayloadLen != 0 || req.SessionID == zeroID || req.AuthKey != zeroToken {
			s.logger.Warn("connect_rejected_invalid",
				"remote", remoteIP,
				"seq", req.Sequence,
				"payload_len", req.PayloadLen,
				"is_zero_id", req.SessionID == zeroID,
			)
			s.writeResponse(conn, req.SessionID, req.Code, StatusError, req.Sequence, []byte(ErrInvalidRequest.Error()))
			return false
		}

		sess, err := s.sessions.CreateSession(req.SessionID, remoteIP)
		if err != nil {
			s.stats.sessionsRejected.Add(1)
			s.logger.Error("connect_target_failed", "remote", remoteIP, "sess", shortID(req.SessionID), "err", err)
			s.writeResponse(conn, req.SessionID, req.Code, StatusError, req.Sequence, []byte(err.Error()))
			return false
		}
		s.stats.sessionsCreated.Add(1)

		s.logger.Info("connect_session_created", "remote", remoteIP, "sess", shortID(req.SessionID), "target", s.cfg.TargetAddr)
		// Confirmação de conexão com token de 32 bytes de volta (SessionID + 16 zeros)
		s.writeResponse(conn, req.SessionID, req.Code, StatusOk, 0, append([]byte(nil), sess.Token[:]...))
		sess.touch()
		return false

	case ReqData: // 2: Upload de dados para o alvo
		sess, ok := s.sessions.GetSession(req.SessionID)
		if !ok {
			s.logger.Warn("data_session_not_found", "session_id", hex.EncodeToString(req.SessionID[:]))
			s.writeResponse(conn, req.SessionID, req.Code, StatusError, req.Sequence, []byte(ErrAuthFailed.Error()))
			return true
		}

		if len(payload) == 0 {
			s.logger.Warn("data_empty_payload", "session_id", hex.EncodeToString(req.SessionID[:]))
			s.writeResponse(conn, req.SessionID, req.Code, StatusError, req.Sequence, []byte(ErrInvalidRequest.Error()))
			return false
		}

		sess.mu.Lock()
		if sess.targetClosed {
			sess.mu.Unlock()
			s.logger.Warn("data_target_already_closed", "session_id", hex.EncodeToString(req.SessionID[:]))
			s.writeResponse(conn, req.SessionID, req.Code, StatusClosed, req.Sequence, []byte(ErrTargetBroken.Error()))
			return false
		}

		// Validação de sequence para upload (FUN_00661240 em hcr.c):
		// Sequence de upload é o índice ordinal do pacote enviado pelo cliente (0, 1, 2...)
		if req.Sequence < sess.writeSeq {
			// Pacote duplicado já processado anteriormente (idempotente)
			respSeq := sess.writeSeq
			sess.touch()
			sess.mu.Unlock()
			s.logger.Debug("data_duplicate_packet_ignored", "session_id", hex.EncodeToString(req.SessionID[:]), "req_seq", req.Sequence, "write_seq", respSeq)
			s.writeResponse(conn, req.SessionID, req.Code, StatusOk, respSeq, nil)
			return false
		}

		if req.Sequence > sess.writeSeq {
			// Pacote fora de ordem
			if req.Sequence-sess.writeSeq > 255 {
				respSeq := sess.writeSeq
				sess.mu.Unlock()
				s.logger.Warn("data_seq_too_far_ahead", "session_id", hex.EncodeToString(req.SessionID[:]), "req_seq", req.Sequence, "write_seq", respSeq)
				s.writeResponse(conn, req.SessionID, req.Code, StatusError, respSeq, []byte("SEQUENCE_INVALID"))
				return false
			}
			if sess.upBuffer == nil {
				sess.upBuffer = make(map[uint64][]byte)
			}
			bufCopy := make([]byte, len(payload))
			copy(bufCopy, payload)
			sess.upBuffer[req.Sequence] = bufCopy
			respSeq := sess.writeSeq
			sess.touch()
			sess.mu.Unlock()
			s.logger.Debug("data_buffered_out_of_order", "session_id", hex.EncodeToString(req.SessionID[:]), "req_seq", req.Sequence, "waiting_for", respSeq)
			s.writeResponse(conn, req.SessionID, req.Code, StatusOk, respSeq, nil)
			return false
		}

		// req.Sequence == sess.writeSeq: agrupa pacotes contíguos e despacha para escrita assíncrona
		sess.writeSeq++
		toWrite := payload

		// Descarrega quaisquer pacotes subsequentes contíguos que já estavam no upBuffer
		for {
			nextPayload, exists := sess.upBuffer[sess.writeSeq]
			if !exists {
				break
			}
			delete(sess.upBuffer, sess.writeSeq)
			sess.writeSeq++
			toWrite = append(toWrite, nextPayload...)
		}

		if !sess.targetClosed && sess.targetWriteCh != nil {
			select {
			case sess.targetWriteCh <- toWrite:
			default:
				go func(ch chan []byte, data []byte) {
					ch <- data
				}(sess.targetWriteCh, toWrite)
			}
		}

		respSeq := sess.writeSeq
		sess.touch()
		sess.mu.Unlock()

		s.stats.uploadBytes.Add(uint64(len(payload)))
		s.logger.Debug("DATA_OK", "sess", shortID(req.SessionID), "seq", req.Sequence, "bytes", len(payload), "newWriteSeq", respSeq)
		s.writeResponse(conn, req.SessionID, req.Code, StatusOk, respSeq, nil)
		return false

	case ReqPoll: // 3: Download / Polling de dados do alvo
		sess, ok := s.sessions.GetSession(req.SessionID)
		if !ok {
			s.logger.Warn("poll_session_not_found", "sess", shortID(req.SessionID))
			s.writeResponse(conn, req.SessionID, req.Code, StatusError, req.Sequence, []byte(ErrAuthFailed.Error()))
			return true
		}

		maxChunks := 1
		if len(payload) == 2 {
			maxChunks = int(binary.BigEndian.Uint16(payload[:2]))
		} else if len(payload) != 0 {
			s.logger.Warn("poll_invalid_payload_len", "len", len(payload))
			s.writeResponse(conn, req.SessionID, req.Code, StatusError, req.Sequence, []byte(ErrInvalidRequest.Error()))
			return false
		}
		if maxChunks <= 0 {
			maxChunks = 1
		}
		if maxChunks > 32 {
			maxChunks = 32
		}

		maxFrame := s.cfg.MaxDownloadFrame
		if maxFrame <= 0 || maxFrame > MaxPayloadLimit-4 {
			maxFrame = 6144
		}

		sess.mu.Lock()
		sess.touch()

		// Validação de ACK no hcr.c (FUN_0065d4c0 / linha 341072 e 345332):
		// Se já houve ACK e req.Sequence <= ackSeq: não é erro fatal, retorna StatusPollTimeout (2)
		if sess.hasAcked && req.Sequence <= sess.ackSeq {
			sess.mu.Unlock()
			s.logger.Debug("poll_already_acked", "sess", shortID(req.SessionID), "req_seq", req.Sequence, "ack_seq", sess.ackSeq)
			s.writeResponse(conn, req.SessionID, req.Code, StatusPollTimeout, req.Sequence, nil)
			return false
		}

		// Se o worker está adiantado em relação à esteira contígua (> 255 frames à frente):
		// Retorna StatusPollTimeout (2) para que o worker reconsulte sem abortar o túnel
		if req.Sequence > sess.deliveredSeq && req.Sequence-sess.deliveredSeq > 255 {
			sess.mu.Unlock()
			s.logger.Debug("poll_seq_ahead_timeout", "sess", shortID(req.SessionID), "req_seq", req.Sequence, "delivered_seq", sess.deliveredSeq)
			s.writeResponse(conn, req.SessionID, req.Code, StatusPollTimeout, req.Sequence, nil)
			return false
		}

		// Long-polling sequencial estrito (hcr.c linha 341103):
		// Enquanto req.Sequence > deliveredSeq (worker adiantado em relação à esteira contígua)
		// ou não há frames disponíveis a partir de req.Sequence, aguarda notificação em broadcast
		pollTimer := time.NewTimer(s.cfg.DownloadPollTimeout)
		defer pollTimer.Stop()

		for (req.Sequence > sess.deliveredSeq || !sess.hasFramesFrom(req.Sequence)) && !sess.targetClosed {
			notifyCh := sess.dataNotify
			sess.mu.Unlock()
			select {
			case <-pollTimer.C:
				sess.mu.Lock()
				goto finishPoll
			case <-notifyCh:
				sess.mu.Lock()
			case <-ctx.Done():
				sess.mu.Lock()
				goto finishPoll
			}
		}

	finishPoll:
		var matching []*DownloadFrame
		if req.Sequence <= sess.deliveredSeq {
			matching = sess.getFramesFrom(req.Sequence, maxChunks, int(MaxPayloadLimit))
		}

		if len(matching) == 0 {
			status := StatusPollTimeout // 2: Timeout / sem dados no intervalo (FUN_00664300 linha 345408)
			if sess.targetClosed {
				status = StatusClosed // 3: Conexão com o alvo encerrou
			}
			sess.mu.Unlock()
			s.writeResponse(conn, req.SessionID, req.Code, status, req.Sequence, nil)
			return false
		}

		// Cada chunk no payload retornado deve ser precedido por seu tamanho uint32 BigEndian
		var framed []byte
		var highestSeq uint64
		for _, f := range matching {
			chunkHdr := make([]byte, 4)
			binary.BigEndian.PutUint32(chunkHdr, uint32(len(f.Data)))
			framed = append(framed, chunkHdr...)
			framed = append(framed, f.Data...)
			highestSeq = f.Seq
		}
		if highestSeq+1 > sess.deliveredSeq {
			sess.deliveredSeq = highestSeq + 1
		}
		sess.notifyDataLocked()
		sess.touch()
		sess.mu.Unlock()

		s.logger.Debug("POLL_DATA",
			"sess", shortID(req.SessionID),
			"chunks", len(matching),
			"bytes", len(framed),
			"req_seq", req.Sequence,
			"delivered_seq", sess.deliveredSeq,
		)
		s.stats.downloadBytes.Add(uint64(len(framed)))
		// Conforme FUN_00664300 em hcr.c (linha 345282), resposta com dados usa StatusPollData (1)
		s.writeResponse(conn, req.SessionID, req.Code, StatusPollData, req.Sequence, framed)
		return false

	case ReqAck: // 4: Confirmação de recebimento (ACK)
		sess, ok := s.sessions.GetSession(req.SessionID)
		if !ok {
			s.logger.Warn("ack_session_not_found", "sess", shortID(req.SessionID))
			s.writeResponse(conn, req.SessionID, req.Code, StatusError, req.Sequence, []byte(ErrAuthFailed.Error()))
			return true
		}

		sess.mu.Lock()
		var remaining []*DownloadFrame
		var ackedBytes int
		for _, f := range sess.downBuffer {
			if f.Seq <= req.Sequence {
				ackedBytes += len(f.Data)
			} else {
				remaining = append(remaining, f)
			}
		}
		sess.downBuffer = remaining
		sess.pendingBytes -= ackedBytes
		if sess.pendingBytes < 0 {
			sess.pendingBytes = 0
		}
		sess.ackSeq = req.Sequence
		sess.hasAcked = true
		sess.notifyDataLocked()
		sess.touch()
		sess.mu.Unlock()

		s.logger.Debug("ACK_OK", "sess", shortID(req.SessionID), "seq", req.Sequence, "freed", ackedBytes, "pending", sess.pendingBytes)
		s.writeResponse(conn, req.SessionID, req.Code, StatusOk, req.Sequence, nil)
		return false

	case ReqClose: // 5: Fechar sessão
		s.logger.Info("session_closed_by_request", "sess", shortID(req.SessionID))
		s.sessions.CloseSession(req.SessionID)
		s.writeResponse(conn, req.SessionID, req.Code, StatusClosed, req.Sequence, nil)
		return true

	case ReqPing: // 6: Keepalive / Ping
		sess, ok := s.sessions.GetSession(req.SessionID)
		if !ok {
			s.logger.Warn("ping_session_not_found", "sess", shortID(req.SessionID))
			s.writeResponse(conn, req.SessionID, req.Code, StatusClosed, req.Sequence, nil)
			return true
		}
		sess.mu.Lock()
		closed := sess.targetClosed
		sess.touch()
		sess.mu.Unlock()
		if closed {
			s.writeResponse(conn, req.SessionID, req.Code, StatusClosed, req.Sequence, nil)
		} else {
			s.writeResponse(conn, req.SessionID, req.Code, StatusOk, req.Sequence, nil)
		}
		return false

	default:
		s.logger.Warn("unknown_request_code", "code", req.Code, "sess", shortID(req.SessionID))
		s.writeResponse(conn, req.SessionID, req.Code, StatusError, req.Sequence, []byte(ErrInvalidRequest.Error()))
		return true
	}
}

// writeResponse envia os 14 bytes do ResponseHeader seguidos do payload mascarado
func (s *Server) writeResponse(conn net.Conn, sessionID [16]byte, code uint8, status uint8, seq uint64, payload []byte) {
	pLen := uint32(len(payload))
	hdr := MarshalResponseHeader(status, seq, pLen)

	s.logger.Debug("RESP",
		"code", reqCodeNameShort(code),
		"status", statusCodeNameShort(status),
		"seq", seq,
		"len", pLen,
	)

	if len(payload) == 0 {
		conn.Write(hdr)
		return
	}

	// Mascara o payload de saída (Server -> Client: direction = 1)
	outPayload := make([]byte, len(payload))
	copy(outPayload, payload)
	maskPayload(outPayload, sessionID, code, seq, DirResponse)

	buf := append(hdr, outPayload...)
	conn.Write(buf)
}

func (s *Server) sessionStatsLoop() {
	defer s.wait.Done()
	ticker := time.NewTicker(s.cfg.SessionStatsInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.logger.Info("session_stats", "sessions", s.sessions.Len(), "active_connections", s.stats.activeConns.Load())
		case <-s.closed:
			return
		}
	}
}

func (s *Server) idleReaperLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reaped := s.sessions.ReapIdleSessions()
			if reaped > 0 {
				s.logger.Info("idle_sessions_reaped", "count", reaped)
			}
		}
	}
}
