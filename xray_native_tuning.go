package main

import (
	"runtime"
	"sync/atomic"
	"time"
)

type XrayNativeTuning struct {
	RuntimeGOMAXPROCS          int  `json:"runtime_gomaxprocs,omitempty"`
	MuxGlobalSessions          int  `json:"mux_global_sessions,omitempty"`
	MaxConcurrentConnections   int  `json:"max_concurrent_connections,omitempty"`
	MaxConcurrentXHTTPRequests int  `json:"max_concurrent_xhttp_requests,omitempty"`
	XHTTPMaxSessions           int  `json:"xhttp_max_sessions,omitempty"`
	TracePackets               bool `json:"trace_packets,omitempty"`
}

const (
	defaultNativeRuntimeGOMAXPROCS = 0
	defaultNativeMuxGlobalSessions = 32768
	// Transport sockets, XHTTP requests, and XHTTP sessions are VPN traffic, not
	// website requests. Keep the legacy JSON fields for config compatibility, but
	// always normalize them to unlimited. Actual resource protection is provided by
	// socket/HTTP flow control and the bounded byte queues in xray_xhttp.go.
	defaultNativeMaxConnections   = -1
	defaultNativeMaxXHTTPRequests = -1

	fixedNativeMuxMaxSessions    = 64
	fixedNativeMuxUDPIdleMS      = 120000
	fixedNativeMuxUDPReadBuffer  = 256 * 1024
	fixedNativeMuxUDPWriteBuffer = 256 * 1024

	defaultNativeXHTTPMaxSessions = -1
	// Packet-up posts are also protected by byte budgets in xray_xhttp.go. Keep
	// the default reorder queue modest so thousands of unauthenticated sessions
	// cannot consume large amounts of memory merely by allocating empty channel
	// buffers. Operators may request more, up to the hard cap enforced there.
	defaultNativeXHTTPBufferedPosts = 64

	// These are simultaneous resource-safety windows, not request-rate limits.
	// They are deliberately far above the expected 6-8K connected-user load, but
	// finite so a reconnect storm, broken CDN, or hostile client cannot retain an
	// unbounded number of sockets, HTTP handlers, sessions, and goroutine stacks.
	// Transport Accept waits at capacity (kernel backpressure); XHTTP overloads
	// receive 503 rather than the web-rate-limit semantics of 429.
	fixedNativeMaxTransportConnections = 65536
	fixedNativeMaxXHTTPRequests        = 65536
	fixedNativeMaxXHTTPSessions        = 65536
	fixedNativeHTTP2ConcurrentStreams  = 4096
	fixedNativeXHTTPWriteTimeoutMS     = 60 * 1000

	// Backstop reaper for connected XHTTP VPN sessions. The stream-down GET's
	// request context is the primary lifetime owner, but behind a CDN that context
	// frequently never fires when a client silently drops (mobile networks, CDN
	// connection pooling, half-open TCP). When it doesn't, an idle SSH backend
	// never errors either, so the session, its goroutines, socket/fd, and SSH
	// connection leak until the whole process restarts. That accumulation is what
	// drove the recurring XHTTP 502s that only a reboot cleared: the origin slowly
	// ran out of fds/memory and could no longer serve new stream-down GETs.
	//
	// This sweeper only ever reaps sessions with genuinely stale lastSeen. lastSeen
	// is refreshed on every successful read OR write via nativeXHTTPConn.onActivity,
	// so any tunnel still passing data or keepalives is never touched -- only a
	// session with zero bytes in BOTH directions for the full window (i.e. one that
	// looks dead) is closed. 20 minutes is generous enough not to disturb a
	// genuinely idle-but-alive tunnel while still bounding resource growth under
	// heavy 6-8K-user churn. Zero disables the connected-session sweeper.
	fixedNativeXHTTPIdleMS = 20 * 60 * 1000
)

var (
	nativeTuneRuntimeGOMAXPROCS atomic.Int64
	nativeTuneMuxGlobalSessions atomic.Int64
	nativeTuneTracePackets      atomic.Bool
)

func init() {
	applyNativeXrayTuning(nil)
}

func normalizeNativeXrayTuning(t *XrayNativeTuning) XrayNativeTuning {
	if t == nil {
		t = &XrayNativeTuning{}
	}
	out := *t
	if out.RuntimeGOMAXPROCS < 0 {
		out.RuntimeGOMAXPROCS = defaultNativeRuntimeGOMAXPROCS
	}
	if out.MuxGlobalSessions <= 0 {
		out.MuxGlobalSessions = defaultNativeMuxGlobalSessions
	}
	// Ignore every old positive/zero admission ceiling. This migration is
	// deliberately unconditional so upgrading an existing server immediately
	// removes the old 4K/8K/32K web-style caps without requiring a panel save.
	out.MaxConcurrentConnections = defaultNativeMaxConnections
	out.MaxConcurrentXHTTPRequests = defaultNativeMaxXHTTPRequests
	out.XHTTPMaxSessions = defaultNativeXHTTPMaxSessions
	return out
}

func applyNativeXrayTuning(t *XrayNativeTuning) XrayNativeTuning {
	out := normalizeNativeXrayTuning(t)
	gomax := out.RuntimeGOMAXPROCS
	if gomax <= 0 {
		gomax = runtime.NumCPU()
	}
	if gomax < 1 {
		gomax = 1
	}
	runtime.GOMAXPROCS(gomax)
	nativeTuneRuntimeGOMAXPROCS.Store(int64(gomax))
	nativeTuneMuxGlobalSessions.Store(int64(out.MuxGlobalSessions))
	nativeTuneTracePackets.Store(out.TracePackets)
	return out
}

func nativeRuntimeGOMAXPROCS() int     { return int(nativeTuneRuntimeGOMAXPROCS.Load()) }
func nativeMuxGlobalSessionLimit() int { return int(nativeTuneMuxGlobalSessions.Load()) }
func nativeTracePacketsEnabled() bool  { return nativeTuneTracePackets.Load() }

func nativeMuxMaxSessionLimit() int     { return fixedNativeMuxMaxSessions }
func nativeMuxUDPReadBufferSize() int   { return fixedNativeMuxUDPReadBuffer }
func nativeMuxUDPWriteBufferSize() int  { return fixedNativeMuxUDPWriteBuffer }
func nativeXHTTPBufferedPostLimit() int { return defaultNativeXHTTPBufferedPosts }
func nativeHTTP2MaxConcurrentStreams() uint32 {
	return fixedNativeHTTP2ConcurrentStreams
}
func nativeTransportConnectionLimit() int { return fixedNativeMaxTransportConnections }
func nativeXHTTPRequestLimit() int        { return fixedNativeMaxXHTTPRequests }
func nativeXHTTPSessionLimit() int        { return fixedNativeMaxXHTTPSessions }
func nativeXHTTPWriteTimeout() time.Duration {
	return fixedNativeXHTTPWriteTimeoutMS * time.Millisecond
}
func nativeMuxUDPIdleTimeout() time.Duration {
	return fixedNativeMuxUDPIdleMS * time.Millisecond
}
func nativeXHTTPIdleTimeout() time.Duration {
	return fixedNativeXHTTPIdleMS * time.Millisecond
}
