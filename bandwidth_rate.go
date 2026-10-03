package main

// Live per-account bandwidth. The panel already keeps cumulative uploaded and
// downloaded byte counters for every SSH user and Xray client; this file turns
// those counters into a current speed so the UI can show "↑ 12 Mbps ↓ 40 Mbps"
// for the whole account instead of only lifetime totals. Speeds are always the
// sum of every connection the account has open, because the counters they are
// derived from are per account, not per connection.

import (
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// bandwidthRate is a smoothed instantaneous speed in bytes per second.
type bandwidthRate struct {
	UpBytesPerSec   float64
	DownBytesPerSec float64
}

func (r bandwidthRate) isZero() bool {
	return r.UpBytesPerSec == 0 && r.DownBytesPerSec == 0
}

type bandwidthSample struct {
	up   int64
	down int64
	at   time.Time
	rate bandwidthRate
}

// bandwidthSampler converts monotonically increasing byte counters into a
// speed. Deltas smaller than minSampleInterval are ignored so a double sample
// cannot divide by an almost-zero interval, and a counter that moves backwards
// (traffic reset, account recreated) re-baselines instead of reporting a
// nonsensical negative or huge rate.
type bandwidthSampler struct {
	mu      sync.Mutex
	samples map[string]bandwidthSample

	// tau is the exponential smoothing time constant. Larger values give a
	// calmer number; zero disables smoothing.
	tau time.Duration
	// staleAfter makes Rate report zero for accounts that stopped being
	// sampled (idle Xray clients dropped by the stats poller, for example),
	// instead of freezing the last speed on screen forever.
	staleAfter time.Duration
}

const minBandwidthSampleInterval = 250 * time.Millisecond

func newBandwidthSampler(tau, staleAfter time.Duration) *bandwidthSampler {
	return &bandwidthSampler{
		samples:    make(map[string]bandwidthSample),
		tau:        tau,
		staleAfter: staleAfter,
	}
}

// Observe records the current cumulative counters for key. The first
// observation only establishes a baseline; the rate stays zero until a second
// one arrives.
func (s *bandwidthSampler) Observe(key string, up, down int64, now time.Time) {
	if s == nil {
		return
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return
	}
	if up < 0 {
		up = 0
	}
	if down < 0 {
		down = 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, ok := s.samples[key]
	if !ok {
		s.samples[key] = bandwidthSample{up: up, down: down, at: now}
		return
	}
	// Counters went backwards: the account's traffic was reset or the entry was
	// recycled. Start over from this value.
	if up < prev.up || down < prev.down {
		s.samples[key] = bandwidthSample{up: up, down: down, at: now}
		return
	}
	dt := now.Sub(prev.at)
	if dt < minBandwidthSampleInterval {
		return
	}
	seconds := dt.Seconds()
	instant := bandwidthRate{
		UpBytesPerSec:   float64(up-prev.up) / seconds,
		DownBytesPerSec: float64(down-prev.down) / seconds,
	}
	next := instant
	if s.tau > 0 && !prev.rate.isZero() {
		// alpha derived from the real interval so an irregular sampling
		// cadence still converges on the true average.
		alpha := 1 - math.Exp(-seconds/s.tau.Seconds())
		if alpha > 1 {
			alpha = 1
		}
		next = bandwidthRate{
			UpBytesPerSec:   prev.rate.UpBytesPerSec + alpha*(instant.UpBytesPerSec-prev.rate.UpBytesPerSec),
			DownBytesPerSec: prev.rate.DownBytesPerSec + alpha*(instant.DownBytesPerSec-prev.rate.DownBytesPerSec),
		}
	}
	if next.UpBytesPerSec < 0 {
		next.UpBytesPerSec = 0
	}
	if next.DownBytesPerSec < 0 {
		next.DownBytesPerSec = 0
	}
	s.samples[key] = bandwidthSample{up: up, down: down, at: now, rate: next}
}

// Rate returns the last known speed for key. Stale entries report zero.
func (s *bandwidthSampler) Rate(key string) (bandwidthRate, bool) {
	if s == nil {
		return bandwidthRate{}, false
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return bandwidthRate{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rateLocked(key)
}

// RateForKeys returns the first known speed among keys. Xray clients are
// tracked under their UUID in native mode and under their email in external
// mode, so callers pass every identifier the client may be stored under.
func (s *bandwidthSampler) RateForKeys(keys ...string) (bandwidthRate, bool) {
	if s == nil {
		return bandwidthRate{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if rate, ok := s.rateLocked(key); ok {
			return rate, true
		}
	}
	return bandwidthRate{}, false
}

func (s *bandwidthSampler) rateLocked(key string) (bandwidthRate, bool) {
	sample, ok := s.samples[key]
	if !ok {
		return bandwidthRate{}, false
	}
	if s.staleAfter > 0 && !sample.at.IsZero() && time.Since(sample.at) > s.staleAfter {
		return bandwidthRate{}, true
	}
	return sample.rate, true
}

// Retain drops every tracked key that is not in keep, so the map cannot grow
// forever as accounts are deleted or recreated.
func (s *bandwidthSampler) Retain(keep map[string]struct{}) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for key := range s.samples {
		if _, ok := keep[key]; !ok {
			delete(s.samples, key)
		}
	}
}

// ---- SSH accounts ----

const sshBandwidthSampleInterval = 2 * time.Second

var sshBandwidth = newBandwidthSampler(5*time.Second, 20*time.Second)

func startSSHUserRateSampler() {
	go func() {
		ticker := time.NewTicker(sshBandwidthSampleInterval)
		defer ticker.Stop()
		for range ticker.C {
			sampleSSHUserRates(time.Now())
		}
	}()
}

func sampleSSHUserRates(now time.Time) {
	if userMgr == nil {
		return
	}
	states := userMgr.List()
	active := make(map[string]struct{}, len(states))
	for _, u := range states {
		if u == nil {
			continue
		}
		u.mu.Lock()
		username := strings.TrimSpace(u.Cfg.Username)
		u.mu.Unlock()
		if username == "" {
			continue
		}
		sshBandwidth.Observe(
			username,
			atomic.LoadInt64(&u.TotalUplinkBytes),
			atomic.LoadInt64(&u.TotalDownlinkBytes),
			now,
		)
		active[username] = struct{}{}
	}
	sshBandwidth.Retain(active)
}

func sshUserRate(username string) bandwidthRate {
	rate, _ := sshBandwidth.Rate(username)
	return rate
}
