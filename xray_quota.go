package main

import (
	"context"
	"io"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type xrayNativeQuotaState struct {
	// trafficMu establishes a clean reset boundary. Native stream and packet
	// writers hold a read lock from quota reservation through the actual write
	// and metering; traffic resets take the write lock. This prevents an
	// in-flight pre-reset reservation from being accounted in the new period or
	// subtracting from freshly reset usage.
	trafficMu    sync.RWMutex
	mu           sync.Mutex
	usedBytes    int64
	quotaBytes   int64
	action       string
	throttleMbps int
	limiter      *rate.Limiter
	generation   uint64
	maxConns     int
	activeConns  int
	owner        string
	expiresAt    time.Time
	hasExpiry    bool
	connections  map[io.Closer]struct{}
}

func (m *XrayManager) reloadNativeQuotaPolicies() {
	if statsStore == nil {
		return
	}
	metas, err := statsStore.ListAllXrayClients(context.Background())
	if err != nil {
		xrayLogf("xray native quota: load policies failed: %v", err)
		return
	}
	next := make(map[string]*xrayNativeQuotaState, len(metas))
	for _, meta := range metas {
		if meta == nil || strings.TrimSpace(meta.UUID) == "" {
			continue
		}
		next[meta.UUID] = newXrayNativeQuotaState(meta)
	}
	m.nativeQuotaMu.Lock()
	m.nativeQuotaByUUID = next
	m.nativeQuotaMu.Unlock()
}

func newXrayNativeQuotaState(meta *XrayClientMeta) *xrayNativeQuotaState {
	used := meta.TotalUplinkBytes + meta.TotalDownlinkBytes
	if used < 0 {
		used = 0
	}
	return &xrayNativeQuotaState{
		usedBytes:    used,
		quotaBytes:   meta.DataQuotaBytes,
		action:       normalizeQuotaAction(meta.QuotaAction),
		throttleMbps: quotaThrottleMbpsOrDefault(meta.QuotaThrottleMbps),
		generation:   1,
		maxConns:     normalizeXrayMaxConns(meta.MaxConns),
		owner:        strings.TrimSpace(meta.OwnerUsername),
		hasExpiry:    meta.ExpiresAt != nil,
		expiresAt:    xrayExpiryValue(meta.ExpiresAt),
	}
}

func xrayExpiryValue(expiry *time.Time) time.Time {
	if expiry == nil {
		return time.Time{}
	}
	return *expiry
}

func normalizeXrayMaxConns(v int) int {
	if v < 0 {
		return 0
	}
	return v
}

func (m *XrayManager) setNativeQuotaPolicy(meta *XrayClientMeta) {
	if meta == nil || strings.TrimSpace(meta.UUID) == "" {
		return
	}
	uuid := strings.TrimSpace(meta.UUID)
	m.nativeQuotaMu.Lock()
	if m.nativeQuotaByUUID == nil {
		m.nativeQuotaByUUID = make(map[string]*xrayNativeQuotaState)
	}
	existing := m.nativeQuotaByUUID[uuid]
	if existing == nil {
		m.nativeQuotaByUUID[uuid] = newXrayNativeQuotaState(meta)
		m.nativeQuotaMu.Unlock()
		return
	}
	m.nativeQuotaMu.Unlock()

	existing.mu.Lock()
	existing.quotaBytes = meta.DataQuotaBytes
	existing.action = normalizeQuotaAction(meta.QuotaAction)
	existing.throttleMbps = quotaThrottleMbpsOrDefault(meta.QuotaThrottleMbps)
	existing.maxConns = normalizeXrayMaxConns(meta.MaxConns)
	existing.owner = strings.TrimSpace(meta.OwnerUsername)
	existing.hasExpiry = meta.ExpiresAt != nil
	existing.expiresAt = xrayExpiryValue(meta.ExpiresAt)
	existing.limiter = nil
	existing.mu.Unlock()
}

func (m *XrayManager) removeNativeQuotaPolicy(uuid string) {
	uuid = strings.TrimSpace(uuid)
	if uuid == "" {
		return
	}
	m.nativeQuotaMu.Lock()
	state := m.nativeQuotaByUUID[uuid]
	delete(m.nativeQuotaByUUID, uuid)
	m.nativeQuotaMu.Unlock()
	closeNativeClientConnections(state)

	// Do not retain failed traffic/active deltas for a client that no longer
	// exists. This also bounds the pending maps during a prolonged DB outage.
	m.nativeDBMu.Lock()
	delete(m.nativeTrafficPending, uuid)
	delete(m.nativeActivePending, uuid)
	m.nativeDBMu.Unlock()
}

func (m *XrayManager) resetNativeQuotaUsage(uuid string) {
	uuid = strings.TrimSpace(uuid)
	m.nativeQuotaMu.RLock()
	state := m.nativeQuotaByUUID[uuid]
	m.nativeQuotaMu.RUnlock()
	if state == nil {
		return
	}
	state.trafficMu.Lock()
	defer state.trafficMu.Unlock()
	state.mu.Lock()
	state.usedBytes = 0
	state.limiter = nil
	state.generation++
	if state.generation == 0 {
		state.generation = 1
	}
	state.mu.Unlock()
}

func (m *XrayManager) resetNativeTrafficAccounting(ctx context.Context, store *Store, uuid, email string) error {
	state := m.nativeQuotaState(uuid)
	if state != nil {
		state.trafficMu.Lock()
		defer state.trafficMu.Unlock()
		state.mu.Lock()
		defer state.mu.Unlock()
	}

	m.nativeTrafficPersistMu.Lock()
	defer m.nativeTrafficPersistMu.Unlock()

	// Remove this client's queued pre-reset delta while holding only the short
	// map mutex. The database call may take seconds during an outage; keeping
	// nativeDBMu locked across it would stall traffic/accounting updates for
	// every other native user and could amplify a slow database into a goroutine
	// pile-up.
	m.nativeDBMu.Lock()
	key := strings.TrimSpace(uuid)
	var pending xrayPendingTraffic
	hadPending := false
	if m.nativeTrafficPending != nil {
		pending, hadPending = m.nativeTrafficPending[key]
		delete(m.nativeTrafficPending, key)
	}
	m.nativeDBMu.Unlock()

	err := store.ResetXrayClientTraffic(ctx, uuid)
	if err != nil && hadPending && pending.State == state {
		m.nativeDBMu.Lock()
		if m.nativeTrafficPending == nil {
			m.nativeTrafficPending = make(map[string]xrayPendingTraffic)
		}
		current := m.nativeTrafficPending[key]
		if current.State != nil && current.State != state {
			current = xrayPendingTraffic{}
		}
		if current.Email == "" {
			current.Email = pending.Email
		}
		current.Uplink += pending.Uplink
		current.Downlink += pending.Downlink
		current.State = state
		m.nativeTrafficPending[key] = current
		m.nativeDBMu.Unlock()
	}
	if err != nil {
		return err
	}
	if state != nil {
		state.usedBytes = 0
		state.limiter = nil
		state.generation++
		if state.generation == 0 {
			state.generation = 1
		}
	}

	m.statsMu.Lock()
	for _, key := range []string{strings.TrimSpace(email), strings.TrimSpace(uuid)} {
		if key == "" {
			continue
		}
		if runtime, ok := m.statsByEmail[key]; ok {
			runtime.Uplink = 0
			runtime.Downlink = 0
			m.statsByEmail[key] = runtime
		}
	}
	m.statsMu.Unlock()
	return nil
}

func (m *XrayManager) nativeQuotaState(uuid string) *xrayNativeQuotaState {
	m.nativeQuotaMu.RLock()
	state := m.nativeQuotaByUUID[strings.TrimSpace(uuid)]
	m.nativeQuotaMu.RUnlock()
	return state
}

// acquireNativeClientConnection enforces the DB-backed max_conns policy across
// every native inbound and transport. The returned release function is safe to
// call more than once and keeps runtime/DB online counters in sync.
func (m *XrayManager) acquireNativeClientConnection(uuid, email string, closers ...io.Closer) (func(), *xrayNativeQuotaState, bool) {
	state := m.nativeQuotaState(uuid)
	var closer io.Closer
	if len(closers) > 0 {
		closer = closers[0]
	}
	if state != nil {
		state.mu.Lock()
		if reason := nativeClientAccessDeniedLocked(state); reason != "" {
			state.mu.Unlock()
			xrayLogf("native xray: rejected user %s: %s", email, reason)
			return nil, state, false
		}
		if state.maxConns > 0 && state.activeConns >= state.maxConns {
			limit := state.maxConns
			state.mu.Unlock()
			logNativeClientLimitRejection(email, limit)
			return nil, state, false
		}
		state.activeConns++
		if closer != nil {
			if state.connections == nil {
				state.connections = make(map[io.Closer]struct{})
			}
			state.connections[closer] = struct{}{}
		}
		state.mu.Unlock()
	}

	m.recordNativeConnect(uuid, email, state)
	var once sync.Once
	return func() {
		once.Do(func() {
			if state != nil {
				state.mu.Lock()
				if closer != nil {
					delete(state.connections, closer)
				}
				if state.activeConns > 0 {
					state.activeConns--
				}
				state.mu.Unlock()
			}
			m.recordNativeDisconnect(uuid, email, state)
		})
	}, state, true
}

func closeNativeClientConnections(state *xrayNativeQuotaState) {
	if state == nil {
		return
	}
	state.mu.Lock()
	closers := make([]io.Closer, 0, len(state.connections))
	for closer := range state.connections {
		closers = append(closers, closer)
	}
	state.mu.Unlock()
	for _, closer := range closers {
		_ = closer.Close()
	}
}

func (m *XrayManager) disconnectNativeClient(uuid string) {
	closeNativeClientConnections(m.nativeQuotaState(uuid))
}

func (m *XrayManager) nativeClientAccessDenied(uuid string) string {
	state := m.nativeQuotaState(uuid)
	if state == nil {
		return ""
	}
	state.mu.Lock()
	reason := nativeClientAccessDeniedLocked(state)
	state.mu.Unlock()
	return reason
}

func nativeClientAccessDeniedLocked(state *xrayNativeQuotaState) string {
	if state.hasExpiry && !state.expiresAt.After(time.Now()) {
		return "expired"
	}
	if state.owner != "" {
		if err := ownerIsActive(state.owner); err != nil {
			return "owner suspended or expired"
		}
	}
	if state.quotaBytes > 0 && normalizeQuotaAction(state.action) == quotaActionBlock && state.usedBytes >= state.quotaBytes {
		return "data quota exceeded"
	}
	return ""
}

func (m *XrayManager) nativeQuotaBlocked(uuid string) bool {
	return nativeQuotaStateBlocked(m.nativeQuotaState(uuid))
}

func nativeQuotaStateBlocked(state *xrayNativeQuotaState) bool {
	if state == nil {
		return false
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.quotaBytes > 0 && normalizeQuotaAction(state.action) == quotaActionBlock && state.usedBytes >= state.quotaBytes
}

func (m *XrayManager) reserveNativeQuota(state *xrayNativeQuotaState, requested int) (allowed int, limiter *rate.Limiter, stopAfter bool) {
	if requested <= 0 {
		return 0, nil, false
	}
	if state == nil {
		return requested, nil, false
	}
	state.mu.Lock()
	defer state.mu.Unlock()

	n := int64(requested)
	if state.quotaBytes <= 0 {
		state.usedBytes += n
		return requested, nil, false
	}
	if normalizeQuotaAction(state.action) == quotaActionThrottle {
		previous := state.usedBytes
		state.usedBytes += n
		if previous+n > state.quotaBytes {
			if state.limiter == nil {
				bps := mbpsToBytesPerSec(quotaThrottleMbpsOrDefault(state.throttleMbps))
				burst := int(bps)
				if burst < copyBufSize {
					burst = copyBufSize
				}
				state.limiter = rate.NewLimiter(rate.Limit(bps), burst)
			}
			return requested, state.limiter, false
		}
		return requested, nil, false
	}

	remaining := state.quotaBytes - state.usedBytes
	if remaining <= 0 {
		return 0, nil, true
	}
	take := n
	if take > remaining {
		take = remaining
	}
	state.usedBytes += take
	return int(take), nil, take < n
}

func (m *XrayManager) finishNativeQuotaReservation(state *xrayNativeQuotaState, reserved, written int) {
	if reserved <= 0 || written >= reserved {
		return
	}
	if written < 0 {
		written = 0
	}
	if state == nil {
		return
	}
	state.mu.Lock()
	state.usedBytes -= int64(reserved - written)
	if state.usedBytes < 0 {
		state.usedBytes = 0
	}
	state.mu.Unlock()
}

type xrayQuotaMeteredWriter struct {
	w     io.Writer
	meter *trafficMeter
	ctx   context.Context
}

func (mw xrayQuotaMeteredWriter) Write(p []byte) (int, error) {
	if mw.meter == nil {
		return mw.w.Write(p)
	}
	state := mw.meter.state
	if state != nil {
		state.trafficMu.RLock()
		defer state.trafficMu.RUnlock()
	}
	allowed, limiter, stopAfter := xrayMgr.reserveNativeQuota(state, len(p))
	if allowed <= 0 {
		return 0, errDataQuotaExceeded
	}
	if limiter != nil {
		ctx := mw.ctx
		if ctx == nil {
			ctx = context.Background()
		}
		if err := limiter.WaitN(ctx, allowed); err != nil {
			xrayMgr.finishNativeQuotaReservation(state, allowed, 0)
			return 0, err
		}
	}
	n, err := mw.w.Write(p[:allowed])
	xrayMgr.finishNativeQuotaReservation(state, allowed, n)
	if n > 0 {
		mw.meter.add(n)
	}
	if err != nil {
		return n, err
	}
	if stopAfter || allowed < len(p) || nativeQuotaStateBlocked(state) {
		return n, errDataQuotaExceeded
	}
	return n, nil
}

type nativePacketQuotaReservation struct {
	meter    *trafficMeter
	state    *xrayNativeQuotaState
	limiter  *rate.Limiter
	reserved int
	finished bool
}

func reserveNativePacketQuota(meter *trafficMeter, n int) (nativePacketQuotaReservation, error) {
	if meter == nil || n <= 0 {
		return nativePacketQuotaReservation{}, nil
	}
	state := meter.state
	if state != nil {
		state.trafficMu.RLock()
	}
	allowed, limiter, stopAfter := xrayMgr.reserveNativeQuota(state, n)
	if allowed != n || stopAfter {
		if allowed > 0 {
			xrayMgr.finishNativeQuotaReservation(state, allowed, 0)
		}
		if state != nil {
			state.trafficMu.RUnlock()
		}
		return nativePacketQuotaReservation{}, errDataQuotaExceeded
	}
	return nativePacketQuotaReservation{
		meter:    meter,
		state:    state,
		limiter:  limiter,
		reserved: n,
	}, nil
}

func (r *nativePacketQuotaReservation) wait(ctx context.Context) error {
	if r == nil || r.finished || r.limiter == nil || r.reserved <= 0 {
		return nil
	}
	if err := waitNativeRate(ctx, r.limiter, r.reserved); err != nil {
		r.finish(0)
		return err
	}
	return nil
}

func (r *nativePacketQuotaReservation) finish(written int) {
	if r == nil || r.finished {
		return
	}
	r.finished = true
	if r.meter == nil || r.reserved <= 0 {
		if r.state != nil {
			r.state.trafficMu.RUnlock()
		}
		return
	}
	xrayMgr.finishNativeQuotaReservation(r.state, r.reserved, written)
	if written > 0 {
		r.meter.add(written)
	}
	if r.state != nil {
		r.state.trafficMu.RUnlock()
	}
}
