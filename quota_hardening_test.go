package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestNativeClientMaxConnectionsAndBatchedActiveDelta(t *testing.T) {
	oldStore := statsStore
	statsStore = &Store{}
	defer func() { statsStore = oldStore }()

	const uuid = "11111111-1111-1111-1111-111111111111"
	m := &XrayManager{
		nativeQuotaByUUID: map[string]*xrayNativeQuotaState{
			uuid: {maxConns: 1, generation: 1},
		},
	}
	state := m.nativeQuotaState(uuid)

	release, acquiredState, ok := m.acquireNativeClientConnection(uuid, "user@example")
	if !ok || release == nil {
		t.Fatal("first native connection was rejected")
	}
	if acquiredState != state {
		t.Fatal("connection lease did not retain the authenticated policy state")
	}
	if _, _, ok := m.acquireNativeClientConnection(uuid, "user@example"); ok {
		t.Fatal("connection above max_conns was accepted")
	}

	m.nativeDBMu.Lock()
	pending := m.nativeActivePending[uuid]
	m.nativeDBMu.Unlock()
	if pending.Delta != 1 || !pending.Connected || pending.State != state {
		t.Fatalf("connect was not queued for batch persistence: %+v", pending)
	}

	release()
	release() // idempotent release must not underflow counters.

	m.nativeDBMu.Lock()
	pending = m.nativeActivePending[uuid]
	m.nativeDBMu.Unlock()
	if pending.Delta != 0 || !pending.Connected {
		t.Fatalf("connect/disconnect batch should net to zero and retain last-active: %+v", pending)
	}

	state.mu.Lock()
	active := state.activeConns
	state.mu.Unlock()
	if active != 0 {
		t.Fatalf("active connection count = %d, want 0", active)
	}

	release2, _, ok := m.acquireNativeClientConnection(uuid, "user@example")
	if !ok {
		t.Fatal("slot was not reusable after release")
	}
	release2()
}

func TestNativeOnlineUsersAreKeyedByUUID(t *testing.T) {
	oldStore := statsStore
	statsStore = nil
	defer func() { statsStore = oldStore }()

	m := &XrayManager{}
	m.recordNativeConnect("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "shared@example", nil)
	m.recordNativeConnect("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "shared@example", nil)
	if got := m.CountOnlineUsers(); got != 2 {
		t.Fatalf("online UUID count = %d, want 2 for two UUIDs sharing one email", got)
	}
	m.statsMu.RLock()
	_, first := m.statsByEmail["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"]
	_, second := m.statsByEmail["bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"]
	m.statsMu.RUnlock()
	if !first || !second {
		t.Fatal("native runtime stats were not stored under canonical UUID keys")
	}
}

func TestNativeExpiryRejectsAndDisconnectsClient(t *testing.T) {
	const uuid = "cccccccc-cccc-cccc-cccc-cccccccccccc"
	state := &xrayNativeQuotaState{hasExpiry: true, expiresAt: time.Now().Add(time.Hour), generation: 1}
	m := &XrayManager{nativeQuotaByUUID: map[string]*xrayNativeQuotaState{uuid: state}}
	closer := &closeTrackingReader{}
	release, _, ok := m.acquireNativeClientConnection(uuid, "expiry@example", closer)
	if !ok {
		t.Fatal("unexpired client was rejected")
	}
	m.disconnectNativeClient(uuid)
	if !closer.closed.Load() {
		t.Fatal("active native client was not closed during revocation")
	}
	release()

	state.mu.Lock()
	state.expiresAt = time.Now().Add(-time.Second)
	state.mu.Unlock()
	if reason := m.nativeClientAccessDenied(uuid); reason != "expired" {
		t.Fatalf("expired client denial = %q, want expired", reason)
	}
	if _, _, ok := m.acquireNativeClientConnection(uuid, "expiry@example"); ok {
		t.Fatal("expired client acquired a new connection")
	}
}

func TestQuotaAndExpiryValidationRejectsUnsafeInput(t *testing.T) {
	if err := validateQuotaConfig(1, "typo", 1); err == nil {
		t.Fatal("unknown quota action was accepted")
	}
	if err := validateQuotaConfig(1, quotaActionBlock, -1); err == nil {
		t.Fatal("negative throttle setting was accepted")
	}
	if _, err := parseOptionalXrayExpiry("not-a-date"); err == nil {
		t.Fatal("invalid Xray expiry was accepted")
	}
	if exp, err := parseOptionalXrayExpiry(""); err != nil || exp != nil {
		t.Fatalf("empty Xray expiry = (%v, %v), want nil, nil", exp, err)
	}
}

func TestRemoveNativeQuotaPolicyPrunesPendingMaps(t *testing.T) {
	m := &XrayManager{
		nativeQuotaByUUID: map[string]*xrayNativeQuotaState{
			"gone": {generation: 1},
		},
		nativeTrafficPending: map[string]xrayPendingTraffic{
			"gone": {Uplink: 10},
		},
		nativeActivePending: map[string]xrayPendingActive{
			"gone": {Delta: 1},
		},
	}
	m.removeNativeQuotaPolicy("gone")
	if m.nativeQuotaState("gone") != nil {
		t.Fatal("quota policy was not removed")
	}
	m.nativeDBMu.Lock()
	_, trafficExists := m.nativeTrafficPending["gone"]
	_, activeExists := m.nativeActivePending["gone"]
	m.nativeDBMu.Unlock()
	if trafficExists || activeExists {
		t.Fatal("deleted UUID remained in a pending persistence map")
	}
}

func TestNativeCounterIsBoundedAndReleaseIsIdempotent(t *testing.T) {
	var active atomicInt64ForTest
	release1, ok := acquireNativeCounter(&active.Int64, 2)
	if !ok {
		t.Fatal("first slot rejected")
	}
	release2, ok := acquireNativeCounter(&active.Int64, 2)
	if !ok {
		t.Fatal("second slot rejected")
	}
	if _, ok := acquireNativeCounter(&active.Int64, 2); ok {
		t.Fatal("slot above limit accepted")
	}
	release1()
	release1()
	if got := active.Load(); got != 1 {
		t.Fatalf("active after double release = %d, want 1", got)
	}
	release2()
	if got := active.Load(); got != 0 {
		t.Fatalf("active after releases = %d, want 0", got)
	}
}

// Embedding keeps the test declaration readable while still passing the exact
// atomic.Int64 type required by acquireNativeCounter.
type atomicInt64ForTest struct{ Int64 atomic.Int64 }

func (a *atomicInt64ForTest) Load() int64 { return a.Int64.Load() }

func TestTrackedNativeConnectionsAreClosedOnShutdown(t *testing.T) {
	oldAccepting := nativeTransportAccepting.Load()
	defer nativeTransportAccepting.Store(oldAccepting)

	beginNativeTransportAccepting()
	before := nativeTransportConnections.Load()
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()
	wrapped, ok := wrapTrackedNativeTransportConn(serverSide)
	if !ok {
		t.Fatal("tracked connection was rejected")
	}
	if got := nativeTransportConnections.Load(); got != before+1 {
		t.Fatalf("transport count = %d, want %d", got, before+1)
	}

	stopNativeTransportAccepting()
	closeAllNativeTransportConnections()
	_ = clientSide.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := clientSide.Read(make([]byte, 1)); err == nil {
		t.Fatal("peer remained open after native shutdown")
	}
	if err := wrapped.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("second close returned unexpected error: %v", err)
	}
	if got := nativeTransportConnections.Load(); got != before {
		t.Fatalf("transport count after shutdown = %d, want %d", got, before)
	}
}

func TestXHTTPSessionsIgnoreLegacyGlobalCapAndReleaseCounters(t *testing.T) {
	before := nativeXHTTPSessions.Load()
	ib := &nativeInbound{xhttpMaxBufferedPosts: 2}
	for _, id := range []string{"one", "two"} {
		if sess := ib.upsertXHTTPSession(httptest.NewRecorder(), id); sess == nil {
			t.Fatalf("session %q was rejected", id)
		}
	}
	if got := nativeXHTTPSessions.Load(); got != before+2 {
		t.Fatalf("global XHTTP sessions = %d, want %d", got, before+2)
	}
	ib.closeAllXHTTPSessions()
	if got := nativeXHTTPSessions.Load(); got != before {
		t.Fatalf("global XHTTP sessions after close = %d, want %d", got, before)
	}
	ib.xhttpMu.Lock()
	remaining := len(ib.xhttpSessions)
	ib.xhttpMu.Unlock()
	if remaining != 0 {
		t.Fatalf("inbound retained %d XHTTP sessions", remaining)
	}
}

func TestXHTTPSessionSafetyWindowIsAboveProductionScale(t *testing.T) {
	if got := (&nativeInbound{}).xhttpMaxActiveSessions(); got != fixedNativeMaxXHTTPSessions {
		t.Fatalf("XHTTP session safety window = %d, want %d", got, fixedNativeMaxXHTTPSessions)
	}
	if got := nativeXHTTPSessionLimit(); got < 8_000 {
		t.Fatalf("XHTTP session safety window = %d, want room for at least 8K users", got)
	}
}

func TestNativeHTTP2StreamsUseFiniteTransportBackpressure(t *testing.T) {
	if got := nativeHTTP2MaxConcurrentStreams(); got != fixedNativeHTTP2ConcurrentStreams {
		t.Fatalf("HTTP/2 stream setting = %d, want %d", got, fixedNativeHTTP2ConcurrentStreams)
	}
	if got := nativeHTTP2MaxConcurrentStreams(); got < 1024 {
		t.Fatalf("HTTP/2 stream setting = %d, too small for XHTTP packet bursts", got)
	}
	if got := nativeMuxMaxSessionLimit(); got != 64 {
		t.Fatalf("per-transport Mux session guard = %d, want 64", got)
	}
}

func TestXHTTPHandlerDoesNotApplyWebRequestCeiling(t *testing.T) {
	ib := &nativeInbound{transport: "xhttp", path: "/"}
	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	rec := httptest.NewRecorder()
	ib.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("XHTTP OPTIONS at legacy request ceiling = %d, want 200", rec.Code)
	}
}

func TestXHTTPHandlerSafetySlotIsReleased(t *testing.T) {
	before := nativeXHTTPRequests.Load()
	ib := &nativeInbound{transport: "xhttp", path: "/"}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	ib.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty XHTTP request status = %d, want 400", rec.Code)
	}
	if got := nativeXHTTPRequests.Load(); got != before {
		t.Fatalf("XHTTP handler counter after return = %d, want %d", got, before)
	}
}

func TestPersistedXHTTPAdmissionTuningIsAlwaysUnlimited(t *testing.T) {
	got := normalizeNativeXrayTuning(&XrayNativeTuning{
		MuxGlobalSessions:          8192,
		MaxConcurrentConnections:   4096,
		MaxConcurrentXHTTPRequests: 8192,
		XHTTPMaxSessions:           4096,
	})
	if got.MuxGlobalSessions != 8192 ||
		got.MaxConcurrentConnections != -1 ||
		got.MaxConcurrentXHTTPRequests != defaultNativeMaxXHTTPRequests ||
		got.XHTTPMaxSessions != -1 {
		t.Fatalf("persisted admission limits were not removed: %+v", got)
	}
}

func TestXHTTPMetadataLengthIsBoundedBeforeSessionAllocation(t *testing.T) {
	ib := &nativeInbound{transport: "xhttp", path: "/"}
	req := httptest.NewRequest("GET", "/"+strings.Repeat("a", nativeXHTTPMaxSessionIDBytes+1), nil)
	rec := httptest.NewRecorder()
	ib.ServeHTTP(rec, req)
	if rec.Code != 400 {
		t.Fatalf("oversized XHTTP session id status = %d, want 400", rec.Code)
	}
	ib.xhttpMu.Lock()
	sessions := len(ib.xhttpSessions)
	ib.xhttpMu.Unlock()
	if sessions != 0 {
		t.Fatalf("oversized metadata allocated %d sessions", sessions)
	}
}

func TestXHTTPUploadMemoryIsReleasedOnReadAndClose(t *testing.T) {
	before := nativeXHTTPBufferedBytes.Load()
	q := newNativeXHTTPUploadQueue(4, 512)

	accounted := nativeXHTTPAccountedPacketBytes(4)
	lease, ok := acquireNativeXHTTPMemory(accounted)
	if !ok {
		t.Fatal("failed to reserve XHTTP test memory")
	}
	if err := q.push(context.Background(), nativeXHTTPPacket{Payload: []byte("test"), Seq: 0}, lease); err != nil {
		lease.release()
		t.Fatalf("queue push failed: %v", err)
	}
	lease.release() // transferred leases are a no-op for the producer.
	if got := nativeXHTTPBufferedBytes.Load(); got != before+accounted {
		t.Fatalf("buffered bytes after push = %d, want %d", got, before+accounted)
	}

	buf := make([]byte, 4)
	if n, err := q.Read(buf); err != nil || n != 4 || string(buf) != "test" {
		t.Fatalf("queue read = (%d, %v, %q), want (4, nil, test)", n, err, string(buf))
	}
	if got := nativeXHTTPBufferedBytes.Load(); got != before {
		t.Fatalf("buffered bytes after read = %d, want %d", got, before)
	}

	lease, ok = acquireNativeXHTTPMemory(nativeXHTTPAccountedPacketBytes(3))
	if !ok {
		t.Fatal("failed to reserve second XHTTP test memory")
	}
	if err := q.push(context.Background(), nativeXHTTPPacket{Payload: []byte("xyz"), Seq: 2}, lease); err != nil {
		lease.release()
		t.Fatalf("second queue push failed: %v", err)
	}
	lease.release()
	q.close()
	if got := nativeXHTTPBufferedBytes.Load(); got != before {
		t.Fatalf("buffered bytes after close = %d, want %d", got, before)
	}
}

func TestXHTTPUploadQueueEnforcesPerSessionByteBudget(t *testing.T) {
	before := nativeXHTTPBufferedBytes.Load()
	q := newNativeXHTTPUploadQueue(4, nativeXHTTPMinPacketAccountingBytes-1)
	defer q.close()

	lease, ok := acquireNativeXHTTPMemory(nativeXHTTPAccountedPacketBytes(5))
	if !ok {
		t.Fatal("failed to reserve XHTTP test memory")
	}
	defer lease.release()
	err := q.push(context.Background(), nativeXHTTPPacket{Payload: make([]byte, 5)}, lease)
	if !errors.Is(err, errNativeXHTTPUploadBufferFull) {
		t.Fatalf("oversized queue push error = %v, want buffer limit", err)
	}
	lease.release()
	if got := nativeXHTTPBufferedBytes.Load(); got != before {
		t.Fatalf("rejected payload retained %d bytes, baseline %d", got, before)
	}
}

func TestXHTTPUploadQueueBackpressuresInsteadOfRejectingBurst(t *testing.T) {
	before := nativeXHTTPBufferedBytes.Load()
	q := newNativeXHTTPUploadQueue(2, nativeXHTTPMinPacketAccountingBytes)
	defer q.close()

	first, ok := acquireNativeXHTTPMemory(nativeXHTTPAccountedPacketBytes(4))
	if !ok {
		t.Fatal("failed to reserve first XHTTP payload")
	}
	if err := q.push(context.Background(), nativeXHTTPPacket{Payload: []byte("one!"), Seq: 0}, first); err != nil {
		first.release()
		t.Fatalf("first queue push failed: %v", err)
	}
	first.release()

	second, ok := acquireNativeXHTTPMemory(nativeXHTTPAccountedPacketBytes(4))
	if !ok {
		t.Fatal("failed to reserve second XHTTP payload")
	}
	done := make(chan error, 1)
	go func() {
		done <- q.push(context.Background(), nativeXHTTPPacket{Payload: []byte("two!"), Seq: 1}, second)
	}()

	select {
	case err := <-done:
		second.release()
		t.Fatalf("second burst packet did not backpressure: %v", err)
	case <-time.After(25 * time.Millisecond):
	}

	buf := make([]byte, 4)
	if n, err := q.Read(buf); err != nil || n != 4 || string(buf) != "one!" {
		second.release()
		t.Fatalf("first queue read = (%d, %v, %q)", n, err, string(buf))
	}
	select {
	case err := <-done:
		if err != nil {
			second.release()
			t.Fatalf("backpressured packet failed after space released: %v", err)
		}
		second.release()
	case <-time.After(time.Second):
		second.release()
		t.Fatal("backpressured packet did not resume")
	}

	q.close()
	if got := nativeXHTTPBufferedBytes.Load(); got != before {
		t.Fatalf("backpressure test leaked %d buffered bytes (baseline %d)", got, before)
	}
}

func TestXHTTPGlobalMemoryBackpressureWakesWaitersFIFO(t *testing.T) {
	before := nativeXHTTPBufferedBytes.Load()
	fillBytes := nativeXHTTPMaxBufferedGlobalBytes - before
	filler, ok := acquireNativeXHTTPMemory(fillBytes)
	if !ok {
		t.Fatal("failed to fill XHTTP memory budget for waiter test")
	}
	defer filler.release()

	type result struct {
		lease *nativeXHTTPMemoryLease
		err   error
	}
	startWaiter := func() <-chan result {
		done := make(chan result, 1)
		go func() {
			lease, err := acquireNativeXHTTPMemoryContext(context.Background(), nativeXHTTPMinPacketAccountingBytes)
			done <- result{lease: lease, err: err}
		}()
		return done
	}
	waitForWaiters := func(want int) {
		t.Helper()
		deadline := time.Now().Add(time.Second)
		for {
			nativeXHTTPMemoryWait.Lock()
			got := nativeXHTTPMemoryWait.queued
			nativeXHTTPMemoryWait.Unlock()
			if got == want {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("memory waiters = %d, want %d", got, want)
			}
			time.Sleep(time.Millisecond)
		}
	}

	firstDone := startWaiter()
	waitForWaiters(1)
	secondDone := startWaiter()
	waitForWaiters(2)

	filler.shrink(fillBytes - nativeXHTTPMinPacketAccountingBytes)
	first := <-firstDone
	if first.err != nil || first.lease == nil {
		t.Fatalf("first memory waiter = (%v, %v)", first.lease, first.err)
	}
	select {
	case second := <-secondDone:
		if second.lease != nil {
			second.lease.release()
		}
		t.Fatalf("second waiter woke before FIFO capacity was released: %v", second.err)
	case <-time.After(25 * time.Millisecond):
	}

	first.lease.release()
	select {
	case second := <-secondDone:
		if second.err != nil || second.lease == nil {
			t.Fatalf("second memory waiter = (%v, %v)", second.lease, second.err)
		}
		second.lease.release()
	case <-time.After(time.Second):
		t.Fatal("second memory waiter did not wake after first released")
	}

	filler.release()
	if got := nativeXHTTPBufferedBytes.Load(); got != before {
		t.Fatalf("FIFO waiter test leaked %d buffered bytes (baseline %d)", got, before)
	}
}

func TestXHTTPReassemblyHasNoPacketRequestCountCeiling(t *testing.T) {
	before := nativeXHTTPBufferedBytes.Load()
	q := newNativeXHTTPUploadQueue(1, 4*nativeXHTTPMinPacketAccountingBytes)
	defer q.close()

	done := make(chan error, 1)
	go func() {
		for _, seq := range []uint64{3, 2, 1, 0} {
			lease, ok := acquireNativeXHTTPMemory(nativeXHTTPAccountedPacketBytes(1))
			if !ok {
				done <- errors.New("could not reserve packet memory")
				return
			}
			err := q.push(context.Background(), nativeXHTTPPacket{Payload: []byte{byte('a' + seq)}, Seq: seq}, lease)
			lease.release()
			if err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()

	buf := make([]byte, 1)
	for want := byte('a'); want <= byte('d'); want++ {
		n, err := q.Read(buf)
		if err != nil || n != 1 || buf[0] != want {
			t.Fatalf("reassembled packet = (%d, %v, %q), want %q", n, err, buf[:n], []byte{want})
		}
	}
	if err := <-done; err != nil {
		t.Fatalf("out-of-order burst was rejected: %v", err)
	}
	q.close()
	if got := nativeXHTTPBufferedBytes.Load(); got != before {
		t.Fatalf("reassembly test leaked %d buffered bytes (baseline %d)", got, before)
	}
}

func TestXHTTPBodyReservationUsesActualContentLength(t *testing.T) {
	ib := &nativeInbound{xhttpMaxEachPostBytes: 1_000_000}
	req := httptest.NewRequest(http.MethodPost, "/session/0", strings.NewReader("small"))
	if got := ib.xhttpUploadReservationBytes(req); got != nativeXHTTPMinPacketAccountingBytes {
		t.Fatalf("body reservation = %d, want minimum accounted packet size", got)
	}
	req.ContentLength = -1
	if got := ib.xhttpUploadReservationBytes(req); got != 1_000_000 {
		t.Fatalf("chunked body reservation = %d, want configured maximum", got)
	}
}

func TestNativeQuotaResetWaitsForInFlightTraffic(t *testing.T) {
	const uuid = "22222222-2222-2222-2222-222222222222"
	state := &xrayNativeQuotaState{usedBytes: 123, generation: 1}
	m := &XrayManager{nativeQuotaByUUID: map[string]*xrayNativeQuotaState{uuid: state}}

	state.trafficMu.RLock()
	done := make(chan struct{})
	go func() {
		m.resetNativeQuotaUsage(uuid)
		close(done)
	}()
	select {
	case <-done:
		state.trafficMu.RUnlock()
		t.Fatal("traffic reset crossed an in-flight writer boundary")
	case <-time.After(25 * time.Millisecond):
	}
	state.trafficMu.RUnlock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("traffic reset did not complete after writer released")
	}
	state.mu.Lock()
	used, generation := state.usedBytes, state.generation
	state.mu.Unlock()
	if used != 0 || generation != 2 {
		t.Fatalf("reset state = used %d generation %d, want 0/2", used, generation)
	}
}

func TestNativeRateWaitCanBeCanceled(t *testing.T) {
	lim := rate.NewLimiter(1, 1)
	if !lim.AllowN(time.Now(), 1) {
		t.Fatal("failed to consume initial limiter token")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitNativeRate(ctx, lim, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("waitNativeRate error = %v, want context.Canceled", err)
	}
}

func TestSSHDirtyQueueDoesNotScanInactiveUsers(t *testing.T) {
	sshTrafficDirtyMu.Lock()
	old := sshTrafficDirty
	sshTrafficDirty = make(map[string]*UserState)
	sshTrafficDirtyMu.Unlock()
	defer func() {
		sshTrafficDirtyMu.Lock()
		sshTrafficDirty = old
		sshTrafficDirtyMu.Unlock()
	}()

	active := &UserState{Cfg: UserConfig{Username: "active"}}
	inactive := &UserState{Cfg: UserConfig{Username: "inactive"}}
	markSSHUserTrafficDirty(active)
	dirty := takeSSHUserTrafficDirty()
	if len(dirty) != 1 || dirty["active"] != active {
		t.Fatalf("dirty queue = %#v", dirty)
	}
	if _, found := dirty[inactive.Cfg.Username]; found {
		t.Fatal("inactive user appeared in dirty queue")
	}
	if next := takeSSHUserTrafficDirty(); len(next) != 0 {
		t.Fatalf("dirty queue was not drained: %#v", next)
	}
}

func TestOldNativeConnectionCannotDecrementReplacementAccount(t *testing.T) {
	oldStore := statsStore
	statsStore = &Store{}
	defer func() { statsStore = oldStore }()

	const uuid = "replacement-active-user"
	oldState := &xrayNativeQuotaState{maxConns: 1, generation: 1}
	m := &XrayManager{nativeQuotaByUUID: map[string]*xrayNativeQuotaState{uuid: oldState}}

	release, acquiredState, ok := m.acquireNativeClientConnection(uuid, "old@example")
	if !ok || acquiredState != oldState {
		t.Fatal("failed to acquire old account connection")
	}
	// Discard the old account's successful connect delta so this assertion only
	// measures what happens when that old connection later disconnects.
	m.nativeDBMu.Lock()
	m.nativeActivePending = nil
	m.nativeDBMu.Unlock()

	newState := &xrayNativeQuotaState{maxConns: 1, generation: 1}
	m.nativeQuotaMu.Lock()
	m.nativeQuotaByUUID[uuid] = newState
	m.nativeQuotaMu.Unlock()

	release()

	m.nativeDBMu.Lock()
	pending := m.nativeActivePending[uuid]
	m.nativeDBMu.Unlock()
	if pending.Delta != 0 || pending.State != nil {
		t.Fatalf("old disconnect was queued against replacement account: %+v", pending)
	}
	newState.mu.Lock()
	active := newState.activeConns
	newState.mu.Unlock()
	if active != 0 {
		t.Fatalf("replacement account active count changed to %d", active)
	}
}

func TestOldNativeTrafficCannotAttachToReplacementAccount(t *testing.T) {
	oldStore := statsStore
	statsStore = &Store{}
	defer func() { statsStore = oldStore }()

	const uuid = "replacement-traffic-user"
	oldState := &xrayNativeQuotaState{generation: 1}
	newState := &xrayNativeQuotaState{generation: 1}
	m := &XrayManager{nativeQuotaByUUID: map[string]*xrayNativeQuotaState{uuid: oldState}}

	meter := newTrafficMeter(uuid, "old@example", true, oldState)
	meter.n = 1234

	m.nativeQuotaMu.Lock()
	m.nativeQuotaByUUID[uuid] = newState
	m.nativeQuotaMu.Unlock()

	oldMgr := xrayMgr
	xrayMgr = m
	defer func() { xrayMgr = oldMgr }()
	meter.flush()

	m.nativeDBMu.Lock()
	pending := m.nativeTrafficPending[uuid]
	m.nativeDBMu.Unlock()
	if pending.Uplink != 0 || pending.Downlink != 0 || pending.State != nil {
		t.Fatalf("old traffic was queued against replacement account: %+v", pending)
	}
	m.statsMu.RLock()
	stat := m.statsByEmail["old@example"]
	m.statsMu.RUnlock()
	if stat.Uplink != 0 || stat.Downlink != 0 {
		t.Fatalf("old traffic resurfaced in runtime stats: %+v", stat)
	}
}

func TestNativeFlusherDropsMismatchedPolicyIdentity(t *testing.T) {
	oldStore := statsStore
	statsStore = &Store{}
	defer func() { statsStore = oldStore }()

	const uuid = "identity-prune-user"
	oldState := &xrayNativeQuotaState{generation: 1}
	newState := &xrayNativeQuotaState{generation: 1}
	m := &XrayManager{
		nativeQuotaByUUID: map[string]*xrayNativeQuotaState{uuid: newState},
		nativeTrafficPending: map[string]xrayPendingTraffic{
			uuid: {Email: "old@example", Uplink: 99, State: oldState},
		},
		nativeActivePending: map[string]xrayPendingActive{
			uuid: {Email: "old@example", Delta: -1, State: oldState},
		},
	}
	m.flushNativeStatsToDB()

	m.nativeDBMu.Lock()
	defer m.nativeDBMu.Unlock()
	if len(m.nativeTrafficPending) != 0 || len(m.nativeActivePending) != 0 {
		t.Fatalf("mismatched pending deltas survived prune: traffic=%v active=%v", m.nativeTrafficPending, m.nativeActivePending)
	}
}

func TestNativeMuxFinishRunsOnce(t *testing.T) {
	var calls atomic.Int32
	s := &nativeMuxSession{
		closed: make(chan struct{}),
		uplink: make(chan nativeMuxUplinkItem),
		onClose: func(*nativeMuxSession) {
			calls.Add(1)
		},
	}

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.finish()
		}()
	}
	wg.Wait()
	if got := calls.Load(); got != 1 {
		t.Fatalf("mux onClose called %d times, want 1", got)
	}
}

type closeTrackingReader struct {
	closed atomic.Bool
}

func (r *closeTrackingReader) Read([]byte) (int, error) { return 0, io.EOF }
func (r *closeTrackingReader) Close() error {
	r.closed.Store(true)
	return nil
}

func TestNativeXHTTPQueueCloseClosesQueuedStreamReader(t *testing.T) {
	q := newNativeXHTTPUploadQueue(1, 1024)
	r := &closeTrackingReader{}
	if err := q.push(context.Background(), nativeXHTTPPacket{Reader: r}, nil); err != nil {
		t.Fatalf("queue stream reader: %v", err)
	}
	q.close()
	if !r.closed.Load() {
		t.Fatal("queued stream reader was not closed during queue shutdown")
	}
}

func TestNativeXHTTPQueueSkipsEmptyPacketsWithoutZeroProgressRead(t *testing.T) {
	before := nativeXHTTPBufferedBytes.Load()
	q := newNativeXHTTPUploadQueue(2, 2*nativeXHTTPMinPacketAccountingBytes)
	defer q.close()

	for seq, payload := range [][]byte{nil, []byte("x")} {
		accounted := nativeXHTTPAccountedPacketBytes(int64(len(payload)))
		lease, ok := acquireNativeXHTTPMemory(accounted)
		if !ok {
			t.Fatal("failed to reserve packet memory")
		}
		if err := q.push(context.Background(), nativeXHTTPPacket{Payload: payload, Seq: uint64(seq)}, lease); err != nil {
			lease.release()
			t.Fatalf("queue packet %d: %v", seq, err)
		}
		lease.release()
	}

	buf := make([]byte, 1)
	n, err := q.Read(buf)
	if err != nil || n != 1 || string(buf[:n]) != "x" {
		t.Fatalf("queue read after empty packet = (%d, %v, %q), want (1, nil, x)", n, err, buf[:n])
	}
	q.close()
	if got := nativeXHTTPBufferedBytes.Load(); got != before {
		t.Fatalf("empty-packet test leaked %d buffered bytes (baseline %d)", got, before)
	}
}

type deadlineUnblockingResponseWriter struct {
	header      http.Header
	writeStart  chan struct{}
	unblock     chan struct{}
	startOnce   sync.Once
	unblockOnce sync.Once
}

func newDeadlineUnblockingResponseWriter() *deadlineUnblockingResponseWriter {
	return &deadlineUnblockingResponseWriter{
		header:     make(http.Header),
		writeStart: make(chan struct{}),
		unblock:    make(chan struct{}),
	}
}

func (w *deadlineUnblockingResponseWriter) Header() http.Header { return w.header }
func (w *deadlineUnblockingResponseWriter) WriteHeader(int)     {}
func (w *deadlineUnblockingResponseWriter) Flush()              {}
func (w *deadlineUnblockingResponseWriter) Write([]byte) (int, error) {
	w.startOnce.Do(func() { close(w.writeStart) })
	<-w.unblock
	return 0, os.ErrDeadlineExceeded
}
func (w *deadlineUnblockingResponseWriter) SetWriteDeadline(deadline time.Time) error {
	if !deadline.IsZero() && !deadline.After(time.Now().Add(10*time.Millisecond)) {
		w.unblockOnce.Do(func() { close(w.unblock) })
	}
	return nil
}

func TestNativeXHTTPResponseCloseInterruptsStalledWrite(t *testing.T) {
	underlying := newDeadlineUnblockingResponseWriter()
	writer := newNativeXHTTPResponseWriter(underlying)
	writeDone := make(chan error, 1)
	go func() {
		_, err := writer.Write([]byte("blocked"))
		writeDone <- err
	}()

	select {
	case <-underlying.writeStart:
	case <-time.After(time.Second):
		t.Fatal("response write did not start")
	}

	closeDone := make(chan struct{})
	go func() {
		writer.close()
		close(closeDone)
	}()
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("response close blocked behind stalled write")
	}
	select {
	case err := <-writeDone:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("stalled write error = %v, want deadline exceeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("stalled response write was not interrupted")
	}
}
