package main

import (
	"container/heap"
	"context"
	"crypto/tls"
	"encoding/base64"
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

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

const (
	nativeXHTTPMaxSessionIDBytes             = 256
	nativeXHTTPMaxSequenceBytes              = 20
	nativeXHTTPHardMaxHeaderBytes            = 256 * 1024
	nativeXHTTPHardMaxPostBytes        int64 = 16 * 1024 * 1024
	nativeXHTTPMaxBufferedPosts              = 512
	nativeXHTTPMaxBufferedSessionBytes       = 16 * 1024 * 1024
	nativeXHTTPMaxBufferedGlobalBytes        = 128 * 1024 * 1024
	// Tiny/empty packet-up requests still retain queue metadata. Charge a minimum
	// amount against the byte budgets so the reassembly queue can be count-unlimited
	// without allowing zero-byte packets to grow the heap without bound.
	nativeXHTTPMinPacketAccountingBytes int64 = 256
)

var (
	nativeXHTTPBufferedBytes       atomic.Int64
	nativeXHTTPBufferRejected      atomic.Int64
	errNativeXHTTPUploadBufferFull = errors.New("xhttp upload buffer limit reached")
	nativeXHTTPMemoryWait          = struct {
		sync.Mutex
		waiters []*nativeXHTTPMemoryWaiter
		head    int
		queued  int
	}{}
)

type nativeXHTTPMemoryWaiter struct {
	bytes   int64
	ready   chan struct{}
	granted bool
}

const (
	xhttpPlacementPath   = "path"
	xhttpPlacementQuery  = "query"
	xhttpPlacementHeader = "header"
	xhttpPlacementCookie = "cookie"
	xhttpPlacementBody   = "body"
	xhttpPlacementAuto   = "auto"
)

// isXHTTP reports whether this inbound uses XHTTP/SplitHTTP. Xray historically
// uses both names; the panel uses "xhttp" while upstream registers "splithttp".
func (ib *nativeInbound) isXHTTP() bool {
	switch strings.ToLower(ib.transport) {
	case "xhttp", "splithttp":
		return true
	default:
		return false
	}
}

func normalizeXHTTPPath(path string) string {
	path = strings.TrimSpace(path)
	if i := strings.Index(path, "?"); i >= 0 {
		path = path[:i]
	}
	if path == "" || path[0] != '/' {
		path = "/" + path
	}
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
	return path
}

func mergeNativeXHTTPSettings(primary, fallback nativeXHTTPSettingsJSON) nativeXHTTPSettingsJSON {
	out := primary
	if out.Host == "" {
		out.Host = fallback.Host
	}
	if out.Path == "" {
		out.Path = fallback.Path
	}
	if out.Mode == "" {
		out.Mode = fallback.Mode
	}
	if !out.NoSSEHeader {
		out.NoSSEHeader = fallback.NoSSEHeader
	}
	if out.SessionIDPlacement == "" {
		out.SessionIDPlacement = fallback.SessionIDPlacement
	}
	if out.SessionIDKey == "" {
		out.SessionIDKey = fallback.SessionIDKey
	}
	if out.SeqPlacement == "" {
		out.SeqPlacement = fallback.SeqPlacement
	}
	if out.SeqKey == "" {
		out.SeqKey = fallback.SeqKey
	}
	if out.UplinkDataPlacement == "" {
		out.UplinkDataPlacement = fallback.UplinkDataPlacement
	}
	if out.UplinkDataKey == "" {
		out.UplinkDataKey = fallback.UplinkDataKey
	}
	if out.ScMaxEachPostBytes == nil {
		out.ScMaxEachPostBytes = fallback.ScMaxEachPostBytes
	}
	if out.ScMaxBufferedPosts == 0 {
		out.ScMaxBufferedPosts = fallback.ScMaxBufferedPosts
	}
	if out.ServerMaxHeaderBytes == 0 {
		out.ServerMaxHeaderBytes = fallback.ServerMaxHeaderBytes
	}
	return out
}

func newNativeXHTTPListener(addr string, inbounds []*nativeInbound) (*nativeXHTTPListener, error) {
	if len(inbounds) == 0 {
		return nil, fmt.Errorf("native xray: shared XHTTP listener %s has no inbounds", addr)
	}
	group := &nativeXHTTPListener{addr: addr, inbounds: append([]*nativeInbound(nil), inbounds...)}
	paths := make(map[string]string, len(inbounds))
	for i, ib := range group.inbounds {
		if ib == nil || !ib.isXHTTP() {
			return nil, fmt.Errorf("native xray: shared XHTTP listener %s contains a non-XHTTP inbound", addr)
		}
		ib.path = normalizeXHTTPPath(ib.path)
		if previous, exists := paths[ib.path]; exists {
			return nil, fmt.Errorf("native xray: XHTTP inbounds %q and %q use the same path %s on %s", previous, ib.tag, ib.path, addr)
		}
		paths[ib.path] = ib.tag
		if size := ib.xhttpServerMaxHeaderBytes(); size > group.headerSize {
			group.headerSize = size
		}
		if i == 0 {
			group.security = ib.security
			group.tlsConfig = ib.tlsConfig
			continue
		}
		if ib.security != group.security {
			return nil, fmt.Errorf("native xray: XHTTP inbounds sharing %s must use the same TLS setting", addr)
		}
		if group.security == "tls" && !sameNativeTLSCertificate(group.tlsConfig, ib.tlsConfig) {
			return nil, fmt.Errorf("native xray: XHTTP inbounds sharing %s must use the same TLS certificate", addr)
		}
	}
	if group.security == "tls" && group.tlsConfig == nil {
		return nil, fmt.Errorf("native xray: shared XHTTP listener %s has no TLS configuration", addr)
	}
	return group, nil
}

func sameNativeTLSCertificate(a, b *tls.Config) bool {
	if a == nil || b == nil || len(a.Certificates) == 0 || len(b.Certificates) == 0 {
		return a == b
	}
	ac := a.Certificates[0].Certificate
	bc := b.Certificates[0].Certificate
	if len(ac) == 0 || len(bc) == 0 || len(ac[0]) != len(bc[0]) {
		return false
	}
	return string(ac[0]) == string(bc[0])
}

func (ib *nativeInbound) serveXHTTPListener(ln net.Listener) {
	group, err := newNativeXHTTPListener(ln.Addr().String(), []*nativeInbound{ib})
	if err != nil {
		xrayLogf("native xray: XHTTP listener %q rejected: %v", ib.tag, err)
		return
	}
	group.serve(ln)
}

func (g *nativeXHTTPListener) serve(ln net.Listener) {
	defer xrayRecover(fmt.Sprintf("native xray shared XHTTP listener addr=%s", ln.Addr()))
	h2s := &http2.Server{
		MaxConcurrentStreams: nativeHTTP2MaxConcurrentStreams(),
	}
	handler := http.Handler(g)
	// Official Xray accepts plaintext HTTP/1.1 and h2c on non-TLS XHTTP
	// listeners, and negotiates h2/http1 through ALPN on TLS listeners. Without
	// h2c, some clients/CDNs can reach the port but the request never reaches the
	// XHTTP handler, which makes the proxy look dead with no useful target logs.
	if g.security != "tls" {
		handler = h2c.NewHandler(g, h2s)
	}
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 4 * time.Second,
		MaxHeaderBytes:    g.headerSize,
	}
	if g.security == "tls" && g.tlsConfig != nil {
		srv.TLSConfig = g.tlsConfig
		_ = http2.ConfigureServer(srv, h2s)
	}
	// Each path has its own session namespace and idle sweeper.
	stopSweep := make(chan struct{})
	defer close(stopSweep)
	for _, ib := range g.inbounds {
		ib := ib
		xrayGo(fmt.Sprintf("native xray XHTTP idle sweeper inbound=%q", ib.tag), func() { ib.sweepXHTTPSessions(stopSweep) })
	}
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) && !isListenerClosed(err) {
		xrayLogf("native xray: shared XHTTP server on %s stopped: %v", g.addr, err)
	}
}

// ServeHTTP picks the longest configured path. This makes a root XHTTP inbound
// coexist with more specific services such as /ssh without allowing the root
// handler to steal the SSH session path.
func (g *nativeXHTTPListener) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var selected *nativeInbound
	selectedLen := -1
	for _, ib := range g.inbounds {
		if _, ok := ib.matchXHTTPPath(r.URL.Path); ok && len(ib.path) > selectedLen {
			selected = ib
			selectedLen = len(ib.path)
		}
	}
	if selected == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	selected.ServeHTTP(w, r)
}

// sweepXHTTPSessions periodically evicts connected XHTTP sessions that have seen
// no traffic (in either direction) within the idle timeout. This is the safety
// net behind the per-request context watch in handleXHTTPDownload; it only ever
// touches sessions whose lastSeen has genuinely gone stale, so an active tunnel
// (which refreshes lastSeen via nativeXHTTPConn.onActivity) is never reaped.
func (ib *nativeInbound) sweepXHTTPSessions(stop <-chan struct{}) {
	defer xrayRecover(fmt.Sprintf("native xray XHTTP idle sweeper inbound=%q", ib.tag))
	idle := nativeXHTTPIdleTimeout()
	if idle <= 0 {
		return
	}
	interval := idle / 4
	if interval < 15*time.Second {
		interval = 15 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			ib.reapStaleXHTTPSessions(idle)
		}
	}
}

func (ib *nativeInbound) reapStaleXHTTPSessions(idle time.Duration) {
	now := time.Now()
	var stale []*nativeXHTTPSession
	ib.xhttpMu.Lock()
	for id, s := range ib.xhttpSessions {
		s.mu.Lock()
		connected := s.connected
		last := s.lastSeen
		s.mu.Unlock()
		// Unconnected sessions have their own 30s reaper; only reap connected
		// ones that have gone idle past the timeout.
		if connected && now.Sub(last) >= idle {
			delete(ib.xhttpSessions, id)
			stale = append(stale, s)
		}
	}
	ib.xhttpMu.Unlock()
	for _, s := range stale {
		xrayTracef("native xray: xhttp idle sweep closing session=%q inbound=%q", s.id, ib.tag)
		s.close()
	}
}

func (ib *nativeInbound) xhttpServerMaxHeaderBytes() int {
	if ib.xhttpMaxHeaderBytes > 0 {
		if ib.xhttpMaxHeaderBytes > nativeXHTTPHardMaxHeaderBytes {
			return nativeXHTTPHardMaxHeaderBytes
		}
		return ib.xhttpMaxHeaderBytes
	}
	// Xray defaults to 8192. Keep a little room for custom headers/cookies used
	// by packet-up mode while still preventing unbounded memory use.
	return 64 * 1024
}

// ServeHTTP terminates the XHTTP/SplitHTTP transport and exposes the decoded
// byte stream to the VLESS/VMess handlers as a net.Conn.
func (ib *nativeInbound) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer xrayRecover(fmt.Sprintf("native xray XHTTP request inbound=%q method=%s path=%q remote=%s", ib.tag, r.Method, r.URL.RequestURI(), r.RemoteAddr))
	// XHTTP is a VPN transport, not a web API. A single connected user keeps a
	// long-lived download handler and can generate many short packet-up handlers.
	// Rejecting handlers at an application request ceiling turns normal tunnel
	// bursts into 429s and, through CDNs/reverse proxies, intermittent 502s.
	// HTTP/2 flow control plus the bounded, cancelable upload queues below provide
	// backpressure without applying website rate-limit semantics to tunnel traffic.
	if !ib.isXHTTP() {
		logNativePreAuthRejection("native xray: xhttp reject inbound=%q reason=not-xhttp method=%s path=%q host=%q remote=%s", ib.tag, r.Method, r.URL.RequestURI(), r.Host, r.RemoteAddr)
		xhttpBadRequest(w)
		return
	}
	if !ib.xhttpHostAllowed(r.Host) {
		logNativePreAuthRejection("native xray: xhttp reject inbound=%q reason=host method=%s path=%q host=%q want=%q remote=%s", ib.tag, r.Method, r.URL.RequestURI(), r.Host, ib.xhttpHost, r.RemoteAddr)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	base, ok := ib.matchXHTTPPath(r.URL.Path)
	if !ok {
		logNativePreAuthRejection("native xray: xhttp reject inbound=%q reason=path method=%s path=%q want=%q host=%q remote=%s", ib.tag, r.Method, r.URL.RequestURI(), ib.path, r.Host, r.RemoteAddr)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	ib.writeXHTTPCommonHeaders(w, r)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	releaseRequest, ok := acquireNativeXHTTPRequest()
	if !ok {
		logNativeLimitRejection("simultaneous XHTTP handlers", &nativeXHTTPRejected, nativeXHTTPRequestLimit())
		w.Header().Set("Retry-After", "1")
		http.Error(w, "xhttp transport temporarily busy", http.StatusServiceUnavailable)
		return
	}
	defer releaseRequest()

	sessionID, seqStr := ib.extractXHTTPMeta(r, base)
	if len(sessionID) > nativeXHTTPMaxSessionIDBytes || len(seqStr) > nativeXHTTPMaxSequenceBytes {
		logNativePreAuthRejection("native xray: xhttp reject inbound=%q reason=metadata-size remote=%s", ib.tag, r.RemoteAddr)
		xhttpBadRequest(w)
		return
	}
	mode := ib.normalizedXHTTPMode()
	xrayTracef("native xray: xhttp request inbound=%q method=%s proto=%s path=%q host=%q session=%q seq=%q len=%d mode=%s remote=%s", ib.tag, r.Method, r.Proto, r.URL.RequestURI(), r.Host, sessionID, seqStr, r.ContentLength, mode, r.RemoteAddr)

	if sessionID == "" && mode != "" && mode != "auto" && mode != "stream-one" && mode != "stream-up" {
		http.Error(w, "stream-one mode is not allowed", http.StatusBadRequest)
		return
	}

	isUplinkRequest := true
	if r.Method == http.MethodGet {
		isUplinkRequest = seqStr != ""
	}

	if isUplinkRequest && sessionID != "" { // stream-up, packet-up
		sess := ib.upsertXHTTPSession(w, sessionID)
		if sess == nil {
			return
		}
		if seqStr == "" {
			ib.handleXHTTPStreamUpload(w, r, sess)
			return
		}
		ib.handleXHTTPPacketUpload(w, r, sess, seqStr)
		return
	}

	if r.Method == http.MethodGet || sessionID == "" { // stream-down, stream-one
		if sessionID != "" {
			sess := ib.upsertXHTTPSession(w, sessionID)
			if sess == nil {
				return
			}
			ib.handleXHTTPDownload(w, r, sess, sessionID)
			return
		}
		if r.Body == nil || (r.ContentLength == 0 && len(r.TransferEncoding) == 0) {
			xhttpBadRequest(w)
			return
		}
		ib.handleXHTTPStreamOne(w, r)
		return
	}

	w.Header().Set("Allow", "GET, POST, PUT, PATCH, OPTIONS")
	w.WriteHeader(http.StatusMethodNotAllowed)
}

func xhttpBadRequest(w http.ResponseWriter) {
	http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
}

func (ib *nativeInbound) normalizedXHTTPMode() string {
	mode := strings.ToLower(strings.TrimSpace(ib.xhttpMode))
	if mode == "" {
		return "auto"
	}
	return mode
}

func isXHTTPUploadMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		return true
	default:
		return false
	}
}

func (ib *nativeInbound) xhttpHostAllowed(reqHost string) bool {
	want := strings.TrimSpace(ib.xhttpHost)
	if want == "" {
		return true
	}
	for _, h := range strings.Split(want, ",") {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if strings.EqualFold(reqHost, h) {
			return true
		}
		reqBare := stripHostPort(reqHost)
		wantBare := stripHostPort(h)
		if strings.EqualFold(reqBare, wantBare) {
			return true
		}
	}
	return false
}

func stripHostPort(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return ""
	}
	if strings.HasPrefix(h, "[") {
		if end := strings.Index(h, "]"); end >= 0 {
			return strings.Trim(h[1:end], "[]")
		}
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		return strings.Trim(host, "[]")
	}
	if i := strings.LastIndex(h, ":"); i > -1 && strings.Count(h, ":") == 1 {
		return h[:i]
	}
	return strings.Trim(h, "[]")
}

func (ib *nativeInbound) matchXHTTPPath(reqPath string) (base string, ok bool) {
	base = ib.path
	if base == "" {
		base = "/"
	}
	base = normalizeXHTTPPath(base)
	if strings.HasPrefix(reqPath, base) {
		return base, true
	}
	trimmed := strings.TrimSuffix(base, "/")
	if trimmed == "" {
		trimmed = "/"
	}
	if reqPath == trimmed {
		return base, true
	}
	return base, false
}

func (ib *nativeInbound) writeXHTTPCommonHeaders(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin == "" {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	} else {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
	if r.Method == http.MethodOptions {
		if m := r.Header.Get("Access-Control-Request-Method"); m != "" {
			w.Header().Set("Access-Control-Allow-Methods", m)
		} else {
			w.Header().Set("Access-Control-Allow-Methods", "*")
		}
		if h := r.Header.Get("Access-Control-Request-Headers"); h != "" {
			w.Header().Set("Access-Control-Allow-Headers", h)
		} else {
			w.Header().Set("Access-Control-Allow-Headers", "*")
		}
	}
}

func (ib *nativeInbound) extractXHTTPMeta(r *http.Request, base string) (sessionID, seqStr string) {
	sessionPlacement := firstNonEmpty(ib.xhttpSessionPlacement, xhttpPlacementPath)
	seqPlacement := firstNonEmpty(ib.xhttpSeqPlacement, xhttpPlacementPath)
	sessionKey := firstNonEmpty(ib.xhttpSessionKey, defaultXHTTPMetaKey(sessionPlacement, true))
	seqKey := firstNonEmpty(ib.xhttpSeqKey, defaultXHTTPMetaKey(seqPlacement, false))

	var parts []string
	pathPart := 0
	if sessionPlacement == xhttpPlacementPath || seqPlacement == xhttpPlacementPath {
		if strings.HasPrefix(r.URL.Path, base) {
			parts = strings.Split(r.URL.Path[len(base):], "/")
		}
	}

	if sessionPlacement == xhttpPlacementPath {
		if len(parts) > pathPart {
			sessionID = parts[pathPart]
			pathPart++
		}
	} else {
		sessionID = extractXHTTPValue(r, sessionPlacement, sessionKey)
	}

	if seqPlacement == xhttpPlacementPath {
		if len(parts) > pathPart {
			seqStr = parts[pathPart]
		}
	} else {
		seqStr = extractXHTTPValue(r, seqPlacement, seqKey)
	}
	return sessionID, seqStr
}

func defaultXHTTPMetaKey(placement string, session bool) string {
	switch placement {
	case xhttpPlacementHeader:
		if session {
			return "X-Session"
		}
		return "X-Seq"
	case xhttpPlacementCookie, xhttpPlacementQuery:
		if session {
			return "x_session"
		}
		return "x_seq"
	default:
		return ""
	}
}

func extractXHTTPValue(r *http.Request, placement, key string) string {
	if key == "" {
		return ""
	}
	switch placement {
	case xhttpPlacementQuery:
		return r.URL.Query().Get(key)
	case xhttpPlacementHeader:
		return r.Header.Get(key)
	case xhttpPlacementCookie:
		if c, err := r.Cookie(key); err == nil {
			return c.Value
		}
	}
	return ""
}

func (ib *nativeInbound) upsertXHTTPSession(w http.ResponseWriter, id string) *nativeXHTTPSession {
	ib.xhttpMu.Lock()
	defer ib.xhttpMu.Unlock()
	if ib.xhttpSessions == nil {
		ib.xhttpSessions = make(map[string]*nativeXHTTPSession)
	}
	if s := ib.xhttpSessions[id]; s != nil {
		s.touch()
		return s
	}
	releaseSlot, ok := acquireNativeXHTTPSession()
	if !ok {
		logNativeLimitRejection("simultaneous XHTTP sessions", &nativeXHTTPRejected, nativeXHTTPSessionLimit())
		w.Header().Set("Retry-After", "1")
		http.Error(w, "xhttp session capacity temporarily busy", http.StatusServiceUnavailable)
		return nil
	}
	s := &nativeXHTTPSession{
		id:          id,
		queue:       newNativeXHTTPUploadQueue(ib.xhttpMaxBufferedPosts, nativeXHTTPMaxBufferedSessionBytes),
		done:        make(chan struct{}),
		connectedCh: make(chan struct{}),
		lastSeen:    time.Now(),
		releaseSlot: releaseSlot,
	}
	ib.xhttpSessions[id] = s
	xrayTracef("native xray: xhttp session created inbound=%q session=%q active=%d", ib.tag, id, len(ib.xhttpSessions))
	xrayGo(fmt.Sprintf("native xray XHTTP session reaper inbound=%q session=%q", ib.tag, id), func() { ib.reapUnconnectedXHTTPSession(id, s) })
	return s
}

func (ib *nativeInbound) xhttpMaxActiveSessions() int {
	return nativeXHTTPSessionLimit()
}

func (ib *nativeInbound) reapUnconnectedXHTTPSession(id string, s *nativeXHTTPSession) {
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	select {
	case <-timer.C:
		s.mu.Lock()
		connected := s.connected
		s.mu.Unlock()
		if !connected {
			ib.deleteXHTTPSession(id, s)
			s.close()
		}
	case <-s.connectedCh:
	case <-s.done:
	}
}

func (ib *nativeInbound) deleteXHTTPSession(id string, s *nativeXHTTPSession) {
	ib.xhttpMu.Lock()
	defer ib.xhttpMu.Unlock()
	if ib.xhttpSessions[id] == s {
		delete(ib.xhttpSessions, id)
	}
}

func (ib *nativeInbound) closeAllXHTTPSessions() {
	ib.xhttpMu.Lock()
	sessions := make([]*nativeXHTTPSession, 0, len(ib.xhttpSessions))
	for id, session := range ib.xhttpSessions {
		delete(ib.xhttpSessions, id)
		sessions = append(sessions, session)
	}
	ib.xhttpMu.Unlock()
	for _, session := range sessions {
		session.close()
	}
}

func (ib *nativeInbound) handleXHTTPStreamUpload(w http.ResponseWriter, r *http.Request, sess *nativeXHTTPSession) {
	sess.touch()
	xrayTracef("native xray: xhttp stream-up inbound=%q session=%q len=%d remote=%s", ib.tag, sess.id, r.ContentLength, r.RemoteAddr)
	if ib.xhttpMode != "" && ib.xhttpMode != "auto" && ib.xhttpMode != "stream-up" && ib.xhttpMode != "stream-down" {
		http.Error(w, "xhttp stream-up mode is not allowed", http.StatusBadRequest)
		return
	}
	if err := sess.queue.push(r.Context(), nativeXHTTPPacket{Reader: r.Body}, nil); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return
		}
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	flushHTTP(w)
	select {
	case <-r.Context().Done():
	case <-sess.done:
	}
}

func (ib *nativeInbound) handleXHTTPPacketUpload(w http.ResponseWriter, r *http.Request, sess *nativeXHTTPSession, seqStr string) {
	sess.touch()
	if ib.xhttpMode != "" && ib.xhttpMode != "auto" && ib.xhttpMode != "packet-up" && ib.xhttpMode != "stream-down" {
		http.Error(w, "xhttp packet-up mode is not allowed", http.StatusBadRequest)
		return
	}
	seq, err := strconv.ParseUint(seqStr, 10, 64)
	if err != nil {
		http.Error(w, "bad xhttp sequence", http.StatusBadRequest)
		return
	}
	// Reserve the expected payload rather than the configured maximum. Normal
	// XHTTP body uploads have a Content-Length, so small packets no longer each
	// consume a full 1 MB reservation. Unknown/chunked or metadata-carried uploads
	// still reserve the maximum before decoding to preserve the hard memory bound.
	memory, err := acquireNativeXHTTPMemoryContext(r.Context(), ib.xhttpUploadReservationBytes(r))
	if err != nil {
		// If the client/CDN canceled while waiting for backpressure, there is no
		// useful HTTP error to send. Returning also releases every reservation.
		return
	}
	defer memory.release()
	payload, err := ib.readXHTTPPayload(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	memory.shrink(nativeXHTTPAccountedPacketBytes(int64(len(payload))))
	xrayTracef("native xray: xhttp packet-up inbound=%q session=%q seq=%d payload=%d remote=%s", ib.tag, sess.id, seq, len(payload), r.RemoteAddr)
	if err := sess.queue.push(r.Context(), nativeXHTTPPacket{Payload: payload, Seq: seq}, memory); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return
		}
		if errors.Is(err, io.ErrClosedPipe) {
			// A packet can race the stream-down request closing. Acknowledge the late
			// upload instead of leaking an origin 500/502 into the reconnect path.
			w.WriteHeader(http.StatusOK)
			return
		}
		if errors.Is(err, errNativeXHTTPUploadBufferFull) {
			http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
			return
		}
		xrayTracef("native xray: xhttp packet-up push failed inbound=%q session=%q seq=%d: %v", ib.tag, sess.id, seq, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(payload) == 0 {
		w.Header().Set("Cache-Control", "no-store")
	}
	w.WriteHeader(http.StatusOK)
}

func (ib *nativeInbound) readXHTTPPayload(r *http.Request) ([]byte, error) {
	placement := firstNonEmpty(ib.xhttpUplinkDataPlacement, xhttpPlacementBody)
	key := firstNonEmpty(ib.xhttpUplinkDataKey, "X-Data")

	var headerPayload, cookiePayload, bodyPayload []byte
	var err error
	if placement == xhttpPlacementAuto || placement == xhttpPlacementHeader {
		headerPayload, err = readXHTTPHeaderPayload(r, key)
		if err != nil {
			return nil, err
		}
	}
	if placement == xhttpPlacementAuto || placement == xhttpPlacementCookie {
		cookiePayload, err = readXHTTPCookiePayload(r, key)
		if err != nil {
			return nil, err
		}
	}
	if placement == xhttpPlacementAuto || placement == xhttpPlacementBody {
		bodyPayload, err = ib.readXHTTPBodyPayload(r)
		if err != nil {
			return nil, err
		}
	}

	var payload []byte
	switch placement {
	case xhttpPlacementHeader:
		payload = headerPayload
	case xhttpPlacementCookie:
		payload = cookiePayload
	case xhttpPlacementBody:
		payload = bodyPayload
	case xhttpPlacementAuto:
		payload = append(payload, headerPayload...)
		payload = append(payload, cookiePayload...)
		payload = append(payload, bodyPayload...)
	default:
		return nil, fmt.Errorf("unsupported xhttp uplink data placement %q", placement)
	}
	if int64(len(payload)) > ib.xhttpMaxPostBytes() {
		return nil, fmt.Errorf("xhttp upload too large")
	}
	return payload, nil
}

func readXHTTPHeaderPayload(r *http.Request, key string) ([]byte, error) {
	chunks := make([]string, 0, 4)
	for i := 0; ; i++ {
		chunk := r.Header.Get(fmt.Sprintf("%s-%d", key, i))
		if chunk == "" {
			break
		}
		chunks = append(chunks, chunk)
	}
	if len(chunks) == 0 {
		return nil, nil
	}
	return base64.RawURLEncoding.DecodeString(strings.Join(chunks, ""))
}

func readXHTTPCookiePayload(r *http.Request, key string) ([]byte, error) {
	chunks := make([]string, 0, 4)
	for i := 0; ; i++ {
		cookieName := fmt.Sprintf("%s_%d", key, i)
		c, err := r.Cookie(cookieName)
		if err != nil {
			break
		}
		chunks = append(chunks, c.Value)
	}
	if len(chunks) == 0 {
		return nil, nil
	}
	return base64.RawURLEncoding.DecodeString(strings.Join(chunks, ""))
}

func (ib *nativeInbound) readXHTTPBodyPayload(r *http.Request) ([]byte, error) {
	maxBytes := ib.xhttpMaxPostBytes()
	if r.ContentLength > maxBytes {
		return nil, fmt.Errorf("xhttp upload too large")
	}
	payload, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > maxBytes {
		return nil, fmt.Errorf("xhttp upload too large")
	}
	return payload, nil
}

func (ib *nativeInbound) xhttpMaxPostBytes() int64 {
	if ib.xhttpMaxEachPostBytes > 0 {
		if ib.xhttpMaxEachPostBytes > nativeXHTTPHardMaxPostBytes {
			return nativeXHTTPHardMaxPostBytes
		}
		return ib.xhttpMaxEachPostBytes
	}
	return 1_000_000
}

// xhttpUploadReservationBytes returns a safe pre-read reservation. Body-mode
// clients normally send Content-Length, which lets thousands of small packets
// share the global budget. Header/cookie/auto and chunked bodies reserve the
// configured maximum because their decoded size is not known until parsed.
func (ib *nativeInbound) xhttpUploadReservationBytes(r *http.Request) int64 {
	maxBytes := ib.xhttpMaxPostBytes()
	placement := firstNonEmpty(ib.xhttpUplinkDataPlacement, xhttpPlacementBody)
	if placement == xhttpPlacementBody && r.ContentLength >= 0 {
		if r.ContentLength > maxBytes {
			return nativeXHTTPAccountedPacketBytes(maxBytes)
		}
		return nativeXHTTPAccountedPacketBytes(r.ContentLength)
	}
	return nativeXHTTPAccountedPacketBytes(maxBytes)
}

func nativeXHTTPAccountedPacketBytes(payloadBytes int64) int64 {
	if payloadBytes < nativeXHTTPMinPacketAccountingBytes {
		return nativeXHTTPMinPacketAccountingBytes
	}
	return payloadBytes
}

func (ib *nativeInbound) handleXHTTPStreamOne(w http.ResponseWriter, r *http.Request) {
	defer xrayRecover(fmt.Sprintf("native xray XHTTP stream-one inbound=%q remote=%s", ib.tag, r.RemoteAddr))
	xrayTracef("native xray: xhttp stream-one inbound=%q len=%d remote=%s", ib.tag, r.ContentLength, r.RemoteAddr)
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Cache-Control", "no-store")
	if !ib.xhttpNoSSEHeader {
		w.Header().Set("Content-Type", "text/event-stream")
	}
	w.WriteHeader(http.StatusOK)
	flushHTTP(w)

	remote := remoteAddrFromHTTPRequest(r)
	resp := newNativeXHTTPResponseWriter(w)
	xc := &nativeXHTTPConn{
		reader: r.Body,
		writer: resp,
		remote: remote,
		local:  dummyLocalAddr(r),
		onClose: func() {
			resp.close()
			_ = r.Body.Close()
		},
	}
	ib.dispatchXHTTPConn(xc, remote)
	_ = xc.Close()
}

func (ib *nativeInbound) handleXHTTPDownload(w http.ResponseWriter, r *http.Request, sess *nativeXHTTPSession, sessionID string) {
	sess.touch()
	defer xrayRecover(fmt.Sprintf("native xray XHTTP download inbound=%q session=%q remote=%s", ib.tag, sessionID, r.RemoteAddr))
	xrayTracef("native xray: xhttp stream-down inbound=%q session=%q proto=%s remote=%s", ib.tag, sessionID, r.Proto, r.RemoteAddr)
	sess.markConnected()
	defer ib.deleteXHTTPSession(sessionID, sess)

	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Cache-Control", "no-store")
	if !ib.xhttpNoSSEHeader {
		w.Header().Set("Content-Type", "text/event-stream")
	}
	w.WriteHeader(http.StatusOK)
	flushHTTP(w)

	remote := remoteAddrFromHTTPRequest(r)
	var reader io.Reader = sess.queue
	resp := newNativeXHTTPResponseWriter(w)
	xc := &nativeXHTTPConn{
		reader:     reader,
		writer:     resp,
		remote:     remote,
		local:      dummyLocalAddr(r),
		onActivity: sess.touch,
	}
	xc.onClose = func() {
		resp.close()
		sess.close()
	}

	// When the download GET is cancelled (client gone, or a CDN closes the
	// origin stream after its own idle timeout) the HTTP request context fires.
	// Closing xc unblocks the tunnel's uplink reader (via sess.close -> queue
	// close) and closes the backend, so handleXHTTPDownload returns and its
	// deferred deleteXHTTPSession runs. Without this watch an idle tunnel whose
	// client vanished silently would never be torn down. The goroutine exits on
	// sess.done once the session closes for any reason.
	go func() {
		select {
		case <-r.Context().Done():
			// The stream-down HTTP request is the lifetime owner of an XHTTP
			// session. Log the actual transport cancellation so a CDN/proxy
			// timeout can be distinguished from a server idle policy.
			xrayTracef("native xray: xhttp stream-down ended inbound=%q session=%q remote=%s err=%v",
				ib.tag, sessionID, r.RemoteAddr, r.Context().Err())
			_ = xc.Close()
		case <-sess.done:
		}
	}()

	ib.dispatchXHTTPConn(xc, remote)
	_ = xc.Close()
}

func (ib *nativeInbound) dispatchXHTTPConn(xc net.Conn, remote net.Addr) {
	xrayTracef("native xray: xhttp dispatch inbound=%q protocol=%s remote=%s", ib.tag, ib.protocol, remote)
	switch ib.protocol {
	case "vless":
		ib.handleVLESS(xc, remote)
	case "vmess":
		ib.handleVMess(xc, remote)
	case "ssh":
		// XHTTP->SSH tunnel: the decoded stream is a raw SSH transport. Hand it to
		// the same SSH handler the TLS/DNSTT listeners use so tunneled clients
		// authenticate with ordinary SSH accounts. getSSHConfig() is the live,
		// hot-reloadable config; it can be nil only before the SSH server is set up.
		cfg := getSSHConfig()
		if cfg == nil {
			xrayLogf("native xray: inbound %q XHTTP->SSH has no SSH config available yet", ib.tag)
			return
		}
		handleConn(xc, cfg)
	default:
		xrayLogf("native xray: inbound %q XHTTP protocol %q not supported", ib.tag, ib.protocol)
	}
}

func remoteAddrFromHTTPRequest(r *http.Request) net.Addr {
	addr, err := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	if err == nil {
		return addr
	}
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

func dummyLocalAddr(r *http.Request) net.Addr {
	if r.TLS != nil && r.Host != "" {
		return &net.TCPAddr{IP: net.IPv4zero, Port: 443}
	}
	return &net.TCPAddr{IP: net.IPv4zero, Port: 80}
}

func flushHTTP(w http.ResponseWriter) {
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

type nativeXHTTPSession struct {
	id          string
	queue       *nativeXHTTPUploadQueue
	done        chan struct{}
	closeOnce   sync.Once
	connectedCh chan struct{} // closed once the download GET attaches
	connectOnce sync.Once
	mu          sync.Mutex
	connected   bool
	lastSeen    time.Time
	releaseSlot func()
}

func (s *nativeXHTTPSession) touch() {
	s.mu.Lock()
	s.lastSeen = time.Now()
	s.mu.Unlock()
}

func (s *nativeXHTTPSession) markConnected() {
	s.mu.Lock()
	s.connected = true
	s.lastSeen = time.Now()
	s.mu.Unlock()
	s.connectOnce.Do(func() { close(s.connectedCh) })
}

func (s *nativeXHTTPSession) close() {
	s.closeOnce.Do(func() {
		close(s.done)
		s.queue.close()
		if s.releaseSlot != nil {
			s.releaseSlot()
		}
	})
}

type nativeXHTTPConn struct {
	reader io.Reader
	writer io.Writer
	remote net.Addr
	local  net.Addr

	deadlineMu   sync.Mutex
	readDeadline time.Time

	closeOnce sync.Once
	onClose   func()
	// onActivity, when set, is called after any successful read or write so the
	// owning session's lastSeen reflects real bidirectional traffic (not just
	// HTTP request arrivals). The idle sweeper relies on this to avoid reaping a
	// tunnel that is actively streaming in only one direction.
	onActivity func()
}

func (c *nativeXHTTPConn) Read(p []byte) (int, error) {
	if dr, ok := c.reader.(interface{ SetReadDeadline(time.Time) error }); ok {
		c.deadlineMu.Lock()
		d := c.readDeadline
		c.deadlineMu.Unlock()
		_ = dr.SetReadDeadline(d)
	}
	n, err := c.reader.Read(p)
	if n > 0 && c.onActivity != nil {
		c.onActivity()
	}
	return n, err
}

func (c *nativeXHTTPConn) Write(p []byte) (int, error) {
	n, err := c.writer.Write(p)
	if n > 0 && c.onActivity != nil {
		c.onActivity()
	}
	return n, err
}

func (c *nativeXHTTPConn) Close() error {
	c.closeOnce.Do(func() {
		if c.onClose != nil {
			c.onClose()
		}
	})
	return nil
}

func (c *nativeXHTTPConn) LocalAddr() net.Addr  { return c.local }
func (c *nativeXHTTPConn) RemoteAddr() net.Addr { return c.remote }

func (c *nativeXHTTPConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *nativeXHTTPConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = t
	c.deadlineMu.Unlock()
	if dr, ok := c.reader.(interface{ SetReadDeadline(time.Time) error }); ok {
		return dr.SetReadDeadline(t)
	}
	return nil
}

func (c *nativeXHTTPConn) SetWriteDeadline(t time.Time) error {
	if dw, ok := c.writer.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return dw.SetWriteDeadline(t)
	}
	return nil
}

type nativeXHTTPResponseWriter struct {
	writeMu  sync.Mutex
	stateMu  sync.Mutex
	w        http.ResponseWriter
	closed   bool
	deadline time.Time
}

func newNativeXHTTPResponseWriter(w http.ResponseWriter) *nativeXHTTPResponseWriter {
	return &nativeXHTTPResponseWriter{w: w}
}

func (w *nativeXHTTPResponseWriter) Write(p []byte) (int, error) {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()

	w.stateMu.Lock()
	closed := w.closed
	deadline := w.deadline
	w.stateMu.Unlock()
	if closed {
		return 0, io.ErrClosedPipe
	}

	safetyDeadline := time.Now().Add(nativeXHTTPWriteTimeout())
	if deadline.IsZero() || deadline.After(safetyDeadline) {
		deadline = safetyDeadline
	}
	controller := http.NewResponseController(w.w)
	if err := controller.SetWriteDeadline(deadline); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return 0, err
	}
	n, err := w.w.Write(p)
	if err == nil {
		if flushErr := controller.Flush(); flushErr != nil && !errors.Is(flushErr, http.ErrNotSupported) {
			err = flushErr
		}
	}
	return n, err
}

func (w *nativeXHTTPResponseWriter) close() {
	// Do not wait for writeMu: Close is commonly called by the request-context
	// watcher specifically because a CDN write is stalled. Mark the writer closed
	// and force the active net/http write deadline to expire so Write returns.
	w.stateMu.Lock()
	w.closed = true
	w.stateMu.Unlock()
	_ = http.NewResponseController(w.w).SetWriteDeadline(time.Now())
}

func (w *nativeXHTTPResponseWriter) SetWriteDeadline(t time.Time) error {
	w.stateMu.Lock()
	w.deadline = t
	w.stateMu.Unlock()
	err := http.NewResponseController(w.w).SetWriteDeadline(t)
	if errors.Is(err, http.ErrNotSupported) {
		return nil
	}
	return err
}

// nativeXHTTPMemoryLease reserves from a process-wide byte budget before a
// packet-up handler allocates its payload. The same lease is transferred to the
// session queue, so active request bodies and queued reassembly data share one
// hard ceiling instead of each having an independent amplification window.
type nativeXHTTPMemoryLease struct {
	bytes int64
}

func acquireNativeXHTTPMemory(n int64) (*nativeXHTTPMemoryLease, bool) {
	if n <= 0 {
		return &nativeXHTTPMemoryLease{}, true
	}
	nativeXHTTPMemoryWait.Lock()
	defer nativeXHTTPMemoryWait.Unlock()
	current := nativeXHTTPBufferedBytes.Load()
	if nativeXHTTPMemoryWait.queued != 0 || current > nativeXHTTPMaxBufferedGlobalBytes-n {
		logNativeLimitRejection("XHTTP buffered upload bytes", &nativeXHTTPBufferRejected, nativeXHTTPMaxBufferedGlobalBytes)
		return nil, false
	}
	nativeXHTTPBufferedBytes.Store(current + n)
	return &nativeXHTTPMemoryLease{bytes: n}, true
}

// acquireNativeXHTTPMemoryContext applies process-wide memory backpressure.
// Unlike the old fail-fast admission path, a legitimate tunnel burst waits for
// queued bytes to be consumed and remains cancelable if its HTTP request ends.
func acquireNativeXHTTPMemoryContext(ctx context.Context, n int64) (*nativeXHTTPMemoryLease, error) {
	if n <= 0 {
		return &nativeXHTTPMemoryLease{}, nil
	}
	if n > nativeXHTTPMaxBufferedGlobalBytes {
		return nil, errNativeXHTTPUploadBufferFull
	}
	waiter := &nativeXHTTPMemoryWaiter{bytes: n, ready: make(chan struct{})}
	nativeXHTTPMemoryWait.Lock()
	current := nativeXHTTPBufferedBytes.Load()
	if nativeXHTTPMemoryWait.queued == 0 && current <= nativeXHTTPMaxBufferedGlobalBytes-n {
		nativeXHTTPBufferedBytes.Store(current + n)
		nativeXHTTPMemoryWait.Unlock()
		return &nativeXHTTPMemoryLease{bytes: n}, nil
	}
	nativeXHTTPMemoryWait.waiters = append(nativeXHTTPMemoryWait.waiters, waiter)
	nativeXHTTPMemoryWait.queued++
	nativeXHTTPMemoryWait.Unlock()

	select {
	case <-waiter.ready:
		return &nativeXHTTPMemoryLease{bytes: n}, nil
	case <-ctx.Done():
		nativeXHTTPMemoryWait.Lock()
		if waiter.granted {
			current := nativeXHTTPBufferedBytes.Load() - n
			if current < 0 {
				current = 0
			}
			nativeXHTTPBufferedBytes.Store(current)
		} else {
			for i := nativeXHTTPMemoryWait.head; i < len(nativeXHTTPMemoryWait.waiters); i++ {
				candidate := nativeXHTTPMemoryWait.waiters[i]
				if candidate == waiter {
					nativeXHTTPMemoryWait.waiters[i] = nil
					nativeXHTTPMemoryWait.queued--
					break
				}
			}
		}
		grantNativeXHTTPMemoryWaitersLocked()
		nativeXHTTPMemoryWait.Unlock()
		return nil, ctx.Err()
	}
}

func releaseNativeXHTTPMemory(n int64) {
	if n <= 0 {
		return
	}
	nativeXHTTPMemoryWait.Lock()
	current := nativeXHTTPBufferedBytes.Load()
	next := current - n
	if next < 0 {
		next = 0
	}
	nativeXHTTPBufferedBytes.Store(next)
	grantNativeXHTTPMemoryWaitersLocked()
	nativeXHTTPMemoryWait.Unlock()
}

// grantNativeXHTTPMemoryWaitersLocked wakes only the FIFO waiters whose exact
// reservations now fit. The former broadcast channel woke every blocked HTTP
// handler after every tiny release, creating a thundering herd and sustained
// multi-core CPU usage while the 128 MB budget was full.
func grantNativeXHTTPMemoryWaitersLocked() {
	for nativeXHTTPMemoryWait.queued > 0 {
		for nativeXHTTPMemoryWait.head < len(nativeXHTTPMemoryWait.waiters) &&
			nativeXHTTPMemoryWait.waiters[nativeXHTTPMemoryWait.head] == nil {
			nativeXHTTPMemoryWait.head++
		}
		if nativeXHTTPMemoryWait.head >= len(nativeXHTTPMemoryWait.waiters) {
			nativeXHTTPMemoryWait.waiters = nil
			nativeXHTTPMemoryWait.head = 0
			nativeXHTTPMemoryWait.queued = 0
			return
		}

		waiter := nativeXHTTPMemoryWait.waiters[nativeXHTTPMemoryWait.head]
		current := nativeXHTTPBufferedBytes.Load()
		if current > nativeXHTTPMaxBufferedGlobalBytes-waiter.bytes {
			compactNativeXHTTPMemoryWaitersLocked()
			return
		}
		nativeXHTTPMemoryWait.waiters[nativeXHTTPMemoryWait.head] = nil
		nativeXHTTPMemoryWait.head++
		nativeXHTTPMemoryWait.queued--
		nativeXHTTPBufferedBytes.Store(current + waiter.bytes)
		waiter.granted = true
		close(waiter.ready)
	}
	compactNativeXHTTPMemoryWaitersLocked()
}

func compactNativeXHTTPMemoryWaitersLocked() {
	head := nativeXHTTPMemoryWait.head
	if head == 0 {
		return
	}
	if nativeXHTTPMemoryWait.queued == 0 {
		nativeXHTTPMemoryWait.waiters = nil
		nativeXHTTPMemoryWait.head = 0
		return
	}
	if head < 1024 && head*2 < len(nativeXHTTPMemoryWait.waiters) {
		return
	}
	remaining := copy(nativeXHTTPMemoryWait.waiters, nativeXHTTPMemoryWait.waiters[head:])
	for i := remaining; i < len(nativeXHTTPMemoryWait.waiters); i++ {
		nativeXHTTPMemoryWait.waiters[i] = nil
	}
	nativeXHTTPMemoryWait.waiters = nativeXHTTPMemoryWait.waiters[:remaining]
	nativeXHTTPMemoryWait.head = 0
}

func (l *nativeXHTTPMemoryLease) shrink(n int64) {
	if l == nil {
		return
	}
	if n < 0 {
		n = 0
	}
	if n >= l.bytes {
		return
	}
	release := l.bytes - n
	l.bytes = n
	releaseNativeXHTTPMemory(release)
}

func (l *nativeXHTTPMemoryLease) release() {
	if l == nil || l.bytes <= 0 {
		return
	}
	n := l.bytes
	l.bytes = 0
	releaseNativeXHTTPMemory(n)
}

type nativeXHTTPPacket struct {
	Reader         io.ReadCloser
	Payload        []byte
	Seq            uint64
	accountedBytes int64
}

type nativeXHTTPUploadQueue struct {
	pushedPackets chan nativeXHTTPPacket
	maxBytes      int64

	// readMu serializes the single decoded stream reader with close-time queue
	// cleanup. pushWG lets close wait until every producer that started before
	// closedFlag was set has either transferred or released its memory lease.
	readMu        sync.Mutex
	pushWG        sync.WaitGroup
	mu            sync.Mutex
	reader        io.ReadCloser
	readerQueued  bool
	heap          nativeXHTTPHeap
	nextSeq       uint64
	readDeadline  time.Time
	bufferedBytes int64
	closedFlag    bool
	spaceChanged  chan struct{}

	closed    chan struct{}
	closeOnce sync.Once
}

func newNativeXHTTPUploadQueue(maxPackets int, maxBytes int64) *nativeXHTTPUploadQueue {
	if maxPackets <= 0 {
		maxPackets = defaultNativeXHTTPBufferedPosts
	}
	if maxPackets > nativeXHTTPMaxBufferedPosts {
		maxPackets = nativeXHTTPMaxBufferedPosts
	}
	if maxBytes <= 0 || maxBytes > nativeXHTTPMaxBufferedSessionBytes {
		maxBytes = nativeXHTTPMaxBufferedSessionBytes
	}
	return &nativeXHTTPUploadQueue{
		pushedPackets: make(chan nativeXHTTPPacket, maxPackets),
		maxBytes:      maxBytes,
		closed:        make(chan struct{}),
		spaceChanged:  make(chan struct{}),
	}
}

func (q *nativeXHTTPUploadQueue) beginPush() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closedFlag {
		return false
	}
	q.pushWG.Add(1)
	return true
}

func (q *nativeXHTTPUploadQueue) adoptPayloadMemory(ctx context.Context, memory *nativeXHTTPMemoryLease, n int64) error {
	if n <= 0 {
		return nil
	}
	if memory == nil || memory.bytes != n {
		return errNativeXHTTPUploadBufferFull
	}
	if n > q.maxBytes {
		return errNativeXHTTPUploadBufferFull
	}
	for {
		q.mu.Lock()
		if q.closedFlag {
			q.mu.Unlock()
			return io.ErrClosedPipe
		}
		if q.bufferedBytes <= q.maxBytes-n {
			q.bufferedBytes += n
			memory.bytes = 0
			q.mu.Unlock()
			return nil
		}
		changed := q.spaceChanged
		q.mu.Unlock()
		select {
		case <-changed:
		case <-q.closed:
			return io.ErrClosedPipe
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (q *nativeXHTTPUploadQueue) releasePayloadMemory(n int64) {
	if n <= 0 {
		return
	}
	q.mu.Lock()
	release := n
	if release > q.bufferedBytes {
		release = q.bufferedBytes
	}
	q.bufferedBytes -= release
	close(q.spaceChanged)
	q.spaceChanged = make(chan struct{})
	q.mu.Unlock()
	releaseNativeXHTTPMemory(release)
}

func (q *nativeXHTTPUploadQueue) push(ctx context.Context, p nativeXHTTPPacket, memory *nativeXHTTPMemoryLease) error {
	if !q.beginPush() {
		return io.ErrClosedPipe
	}
	defer q.pushWG.Done()

	readerReserved := false
	if p.Reader != nil {
		q.mu.Lock()
		if q.reader != nil || q.readerQueued || q.closedFlag {
			q.mu.Unlock()
			return errors.New("xhttp upload reader already exists")
		}
		q.readerQueued = true
		readerReserved = true
		q.mu.Unlock()
		defer func() {
			if readerReserved {
				q.mu.Lock()
				q.readerQueued = false
				q.mu.Unlock()
			}
		}()
	}
	accountedBytes := int64(0)
	if p.Reader == nil {
		accountedBytes = nativeXHTTPAccountedPacketBytes(int64(len(p.Payload)))
	}
	if err := q.adoptPayloadMemory(ctx, memory, accountedBytes); err != nil {
		return err
	}
	p.accountedBytes = accountedBytes
	if accountedBytes > 0 {
		defer func() {
			if accountedBytes > 0 {
				q.releasePayloadMemory(accountedBytes)
			}
		}()
	}
	select {
	case q.pushedPackets <- p:
		// Ownership has moved to the queue. close() waits for this producer and
		// then drains/releases anything not consumed by the stream reader.
		accountedBytes = 0
		readerReserved = false
		return nil
	case <-q.closed:
		return io.ErrClosedPipe
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (q *nativeXHTTPUploadQueue) close() {
	q.closeOnce.Do(func() {
		q.mu.Lock()
		q.closedFlag = true
		reader := q.reader
		close(q.closed)
		q.mu.Unlock()
		if reader != nil {
			_ = reader.Close()
		}

		q.pushWG.Wait()
		q.readMu.Lock()
		// No producers or readers can now change the queue. Drop references to
		// buffered payloads promptly and return their exact byte reservation.
		for {
			select {
			case p := <-q.pushedPackets:
				if p.Reader != nil {
					_ = p.Reader.Close()
				}
				p.Payload = nil
			default:
				goto drained
			}
		}
	drained:
		q.mu.Lock()
		remaining := q.bufferedBytes
		q.bufferedBytes = 0
		for i := range q.heap {
			q.heap[i].Payload = nil
		}
		q.heap = nil
		q.mu.Unlock()
		q.readMu.Unlock()
		releaseNativeXHTTPMemory(remaining)
	})
}

func (q *nativeXHTTPUploadQueue) SetReadDeadline(t time.Time) error {
	q.mu.Lock()
	q.readDeadline = t
	q.mu.Unlock()
	return nil
}

func (q *nativeXHTTPUploadQueue) recv() (nativeXHTTPPacket, error) {
	q.mu.Lock()
	d := q.readDeadline
	q.mu.Unlock()

	if d.IsZero() {
		select {
		case p := <-q.pushedPackets:
			return p, nil
		case <-q.closed:
			return nativeXHTTPPacket{}, io.EOF
		}
	}

	wait := time.Until(d)
	if wait <= 0 {
		return nativeXHTTPPacket{}, os.ErrDeadlineExceeded
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case p := <-q.pushedPackets:
		return p, nil
	case <-q.closed:
		return nativeXHTTPPacket{}, io.EOF
	case <-timer.C:
		return nativeXHTTPPacket{}, os.ErrDeadlineExceeded
	}
}

func (q *nativeXHTTPUploadQueue) Read(b []byte) (int, error) {
	q.readMu.Lock()
	defer q.readMu.Unlock()

	if reader := q.loadReader(); reader != nil {
		return reader.Read(b)
	}

	for {
		select {
		case <-q.closed:
			return 0, io.EOF
		default:
		}

		if len(q.heap) == 0 {
			p, err := q.recv()
			if err != nil {
				return 0, err
			}
			if p.Reader != nil {
				if !q.setReader(p.Reader) {
					_ = p.Reader.Close()
					return 0, io.EOF
				}
				return p.Reader.Read(b)
			}
			select {
			case <-q.closed:
				q.releasePayloadMemory(p.accountedBytes)
				return 0, io.EOF
			default:
			}
			heap.Push(&q.heap, p)
		}

		for len(q.heap) > 0 {
			packet := heap.Pop(&q.heap).(nativeXHTTPPacket)

			if packet.Seq == q.nextSeq {
				if len(packet.Payload) == 0 {
					q.releasePayloadMemory(packet.accountedBytes)
					q.nextSeq = packet.Seq + 1
					continue
				}
				n := copy(b, packet.Payload)
				if n < len(packet.Payload) {
					q.releasePayloadMemory(int64(n))
					packet.accountedBytes -= int64(n)
					packet.Payload = packet.Payload[n:]
					heap.Push(&q.heap, packet)
				} else {
					q.releasePayloadMemory(packet.accountedBytes)
					q.nextSeq = packet.Seq + 1
				}
				return n, nil
			}

			if packet.Seq > q.nextSeq {
				heap.Push(&q.heap, packet)
				p, err := q.recv()
				if err != nil {
					return 0, err
				}
				if p.Reader != nil {
					_ = p.Reader.Close()
					return 0, errors.New("xhttp mixed stream-up and packet-up upload")
				}
				heap.Push(&q.heap, p)
				continue
			}

			// A duplicate/late packet is discarded; release the bytes it owned.
			q.releasePayloadMemory(packet.accountedBytes)
		}
	}
}

func (q *nativeXHTTPUploadQueue) loadReader() io.ReadCloser {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.reader
}

func (q *nativeXHTTPUploadQueue) setReader(r io.ReadCloser) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closedFlag {
		return false
	}
	q.reader = r
	return true
}

type nativeXHTTPHeap []nativeXHTTPPacket

func (h nativeXHTTPHeap) Len() int           { return len(h) }
func (h nativeXHTTPHeap) Less(i, j int) bool { return h[i].Seq < h[j].Seq }
func (h nativeXHTTPHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *nativeXHTTPHeap) Push(x any)        { *h = append(*h, x.(nativeXHTTPPacket)) }
func (h *nativeXHTTPHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}
