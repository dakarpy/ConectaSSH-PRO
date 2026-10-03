package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

const (
	quotaActionBlock    = "block"
	quotaActionThrottle = "throttle"
)

var errDataQuotaExceeded = errors.New("data quota exceeded")

func normalizeQuotaAction(v string) string {
	if strings.EqualFold(strings.TrimSpace(v), quotaActionThrottle) {
		return quotaActionThrottle
	}
	return quotaActionBlock
}

func quotaThrottleMbpsOrDefault(v int) int {
	if v <= 0 {
		return 1
	}
	return v
}

type sshTrafficDelta struct {
	Uplink   int64
	Downlink int64
}

var (
	sshTrafficPersistenceMu sync.Mutex
	sshTrafficDirtyMu       sync.Mutex
	sshTrafficDirty         = make(map[string]*UserState)
)

func markSSHUserTrafficDirty(u *UserState) {
	if u == nil || strings.TrimSpace(u.Cfg.Username) == "" {
		return
	}
	sshTrafficDirtyMu.Lock()
	sshTrafficDirty[u.Cfg.Username] = u
	sshTrafficDirtyMu.Unlock()
}

func takeSSHUserTrafficDirty() map[string]*UserState {
	sshTrafficDirtyMu.Lock()
	dirty := sshTrafficDirty
	sshTrafficDirty = make(map[string]*UserState)
	sshTrafficDirtyMu.Unlock()
	return dirty
}

func clearSSHUserTrafficDirty(username string, u *UserState) {
	sshTrafficDirtyMu.Lock()
	if current := sshTrafficDirty[username]; u == nil || current == u {
		delete(sshTrafficDirty, username)
	}
	sshTrafficDirtyMu.Unlock()
}

func (s *Store) AddSSHUserTrafficBatch(ctx context.Context, deltas map[string]sshTrafficDelta) error {
	if s == nil || len(deltas) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `
        UPDATE ssh_users SET
            total_uplink_bytes   = GREATEST(total_uplink_bytes + GREATEST($2::BIGINT, 0), 0),
            total_downlink_bytes = GREATEST(total_downlink_bytes + GREATEST($3::BIGINT, 0), 0)
        WHERE username = $1`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for username, d := range deltas {
		if strings.TrimSpace(username) == "" || (d.Uplink == 0 && d.Downlink == 0) {
			continue
		}
		if _, err := stmt.ExecContext(ctx, username, d.Uplink, d.Downlink); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ResetSSHUserTraffic(ctx context.Context, username string) error {
	if s == nil || strings.TrimSpace(username) == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE ssh_users
		SET total_uplink_bytes = 0, total_downlink_bytes = 0
		WHERE username = $1`, username)
	return err
}

func initSSHRuntimeUsage(u *UserState, uplink, downlink int64) {
	if u == nil {
		return
	}
	if uplink < 0 {
		uplink = 0
	}
	if downlink < 0 {
		downlink = 0
	}
	atomic.StoreInt64(&u.TotalUplinkBytes, uplink)
	atomic.StoreInt64(&u.TotalDownlinkBytes, downlink)
	atomic.StoreInt64(&u.totalBytes, uplink+downlink)
	atomic.StoreInt64(&u.pendingUplinkBytes, 0)
	atomic.StoreInt64(&u.pendingDownlinkBytes, 0)
}

func resetSSHRuntimeUsageLocked(u *UserState) {
	if u == nil {
		return
	}
	initSSHRuntimeUsage(u, 0, 0)
	u.mu.Lock()
	u.quotaLimiter = nil
	u.quotaLimiterMbps = 0
	u.mu.Unlock()
}

func resetSSHRuntimeUsage(username string) {
	u, ok := userMgr.Get(username)
	if !ok || u == nil {
		return
	}
	u.trafficMu.Lock()
	resetSSHRuntimeUsageLocked(u)
	clearSSHUserTrafficDirty(username, u)
	u.trafficMu.Unlock()
}

func resetSSHUserTrafficAccounting(ctx context.Context, store *Store, username string) error {
	u, _ := userMgr.Get(username)
	if u != nil {
		u.trafficMu.Lock()
		defer u.trafficMu.Unlock()
	}
	sshTrafficPersistenceMu.Lock()
	defer sshTrafficPersistenceMu.Unlock()
	if err := store.ResetSSHUserTraffic(ctx, username); err != nil {
		return err
	}
	if u != nil {
		resetSSHRuntimeUsageLocked(u)
		clearSSHUserTrafficDirty(username, u)
	}
	return nil
}

func sshUserQuotaBlocked(u *UserState) bool {
	if u == nil {
		return false
	}
	u.mu.Lock()
	quota := u.Cfg.DataQuotaBytes
	action := normalizeQuotaAction(u.Cfg.QuotaAction)
	u.mu.Unlock()
	return quota > 0 && action == quotaActionBlock && atomic.LoadInt64(&u.totalBytes) >= quota
}

func sshQuotaLimiter(u *UserState, mbps int) *rate.Limiter {
	mbps = quotaThrottleMbpsOrDefault(mbps)
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.quotaLimiter == nil || u.quotaLimiterMbps != mbps {
		bps := mbpsToBytesPerSec(mbps)
		burst := int(bps)
		if burst < copyBufSize {
			burst = copyBufSize
		}
		u.quotaLimiter = rate.NewLimiter(rate.Limit(bps), burst)
		u.quotaLimiterMbps = mbps
	}
	return u.quotaLimiter
}

func reserveSSHUserBytes(u *UserState, requested int) (allowed int, throttle *rate.Limiter, stopAfter bool) {
	if u == nil || requested <= 0 {
		return 0, nil, false
	}
	u.mu.Lock()
	quota := u.Cfg.DataQuotaBytes
	action := normalizeQuotaAction(u.Cfg.QuotaAction)
	throttleMbps := u.Cfg.QuotaThrottleMbps
	u.mu.Unlock()

	n := int64(requested)
	if quota <= 0 {
		atomic.AddInt64(&u.totalBytes, n)
		return requested, nil, false
	}

	if action == quotaActionThrottle {
		previous := atomic.AddInt64(&u.totalBytes, n) - n
		if previous+n > quota {
			return requested, sshQuotaLimiter(u, throttleMbps), false
		}
		return requested, nil, false
	}

	for {
		used := atomic.LoadInt64(&u.totalBytes)
		remaining := quota - used
		if remaining <= 0 {
			return 0, nil, true
		}
		take := n
		if take > remaining {
			take = remaining
		}
		if atomic.CompareAndSwapInt64(&u.totalBytes, used, used+take) {
			return int(take), nil, take < n || used+take >= quota
		}
	}
}

func finishSSHUserReservation(u *UserState, uplink bool, reserved, written int) {
	if u == nil || reserved <= 0 {
		return
	}
	if written < 0 {
		written = 0
	}
	if written > reserved {
		written = reserved
	}
	if written < reserved {
		atomic.AddInt64(&u.totalBytes, -int64(reserved-written))
	}
	if written == 0 {
		return
	}
	if uplink {
		atomic.AddInt64(&u.TotalUplinkBytes, int64(written))
		atomic.AddInt64(&u.pendingUplinkBytes, int64(written))
	} else {
		atomic.AddInt64(&u.TotalDownlinkBytes, int64(written))
		atomic.AddInt64(&u.pendingDownlinkBytes, int64(written))
	}
	markSSHUserTrafficDirty(u)
}

type sshQuotaWriter struct {
	w      io.Writer
	user   *UserState
	uplink bool
	ctx    context.Context
}

func (qw sshQuotaWriter) Write(p []byte) (int, error) {
	if qw.user != nil {
		qw.user.trafficMu.RLock()
		defer qw.user.trafficMu.RUnlock()
	}
	allowed, quotaLimiter, stopAfter := reserveSSHUserBytes(qw.user, len(p))
	if allowed <= 0 {
		return 0, errDataQuotaExceeded
	}
	if quotaLimiter != nil {
		ctx := qw.ctx
		if ctx == nil {
			ctx = context.Background()
		}
		if err := quotaLimiter.WaitN(ctx, allowed); err != nil {
			finishSSHUserReservation(qw.user, qw.uplink, allowed, 0)
			return 0, err
		}
	}
	n, err := qw.w.Write(p[:allowed])
	finishSSHUserReservation(qw.user, qw.uplink, allowed, n)
	if err != nil {
		return n, err
	}
	if stopAfter || allowed < len(p) {
		return n, errDataQuotaExceeded
	}
	return n, nil
}

func startSSHUserTrafficFlusher(store *Store) {
	if store == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			flushSSHUserTraffic(store)
		}
	}()
}

func flushSSHUserTraffic(store *Store) {
	if store == nil {
		return
	}
	sshTrafficPersistenceMu.Lock()
	defer sshTrafficPersistenceMu.Unlock()
	deltas := make(map[string]sshTrafficDelta)
	states := make(map[string]*UserState)
	for username, u := range takeSSHUserTrafficDirty() {
		if u == nil || strings.TrimSpace(username) == "" {
			continue
		}
		up := atomic.SwapInt64(&u.pendingUplinkBytes, 0)
		down := atomic.SwapInt64(&u.pendingDownlinkBytes, 0)
		if up == 0 && down == 0 {
			continue
		}
		deltas[username] = sshTrafficDelta{Uplink: up, Downlink: down}
		states[username] = u
	}
	if len(deltas) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := store.AddSSHUserTrafficBatch(ctx, deltas); err != nil {
		log.Printf("ssh traffic flush failed: %v", err)
		for username, d := range deltas {
			if u := states[username]; u != nil {
				atomic.AddInt64(&u.pendingUplinkBytes, d.Uplink)
				atomic.AddInt64(&u.pendingDownlinkBytes, d.Downlink)
				markSSHUserTrafficDirty(u)
			}
		}
	}
}

func validateQuotaConfig(quotaBytes int64, action string, throttleMbps int) error {
	if quotaBytes < 0 {
		return fmt.Errorf("data_quota_bytes must be non-negative")
	}
	rawAction := strings.ToLower(strings.TrimSpace(action))
	if rawAction != "" && rawAction != quotaActionBlock && rawAction != quotaActionThrottle {
		return fmt.Errorf("quota_action must be block or throttle")
	}
	if throttleMbps < 0 {
		return fmt.Errorf("quota_throttle_mbps must be non-negative")
	}
	if throttleMbps > 1000000 {
		return fmt.Errorf("quota_throttle_mbps must not exceed 1000000")
	}
	return nil
}
