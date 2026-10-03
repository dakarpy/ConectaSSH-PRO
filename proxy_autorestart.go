package main

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"
)

var (
	proxyAutoMu     sync.Mutex
	proxyAutoCancel context.CancelFunc
)

// startProxyAutoRestart starts a watchdog that periodically hard-restarts the
// public SSH/HTTP proxy layer. Unlike a normal hot reload, this intentionally
// closes active SSH sessions so the behavior is close to a service reboot.
func startProxyAutoRestart(cfg *Config) {
	interval := proxyAutoRestartInterval(cfg)
	if interval <= 0 {
		return
	}
	grace := proxyAutoRestartGrace(cfg)
	cfgCopy := cloneProxyRestartConfig(cfg)
	ctx, cancel := context.WithCancel(context.Background())

	proxyAutoMu.Lock()
	if proxyAutoCancel != nil {
		proxyAutoCancel()
	}
	proxyAutoCancel = cancel
	proxyAutoMu.Unlock()

	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		log.Printf("proxy auto restart enabled: interval=%s grace=%s mode=hard", interval, grace)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				restartProxyHard(ctx, cfgCopy, grace)
			}
		}
	}()
}

func stopProxyAutoRestart() {
	proxyAutoMu.Lock()
	defer proxyAutoMu.Unlock()
	if proxyAutoCancel != nil {
		proxyAutoCancel()
		proxyAutoCancel = nil
	}
}

func cloneProxyRestartConfig(cfg *Config) *Config {
	if cfg == nil {
		return nil
	}
	out := &Config{
		Listen:                   cfg.Listen,
		ProxyAutoRestartInterval: cfg.ProxyAutoRestartInterval,
		ProxyAutoRestartGrace:    cfg.ProxyAutoRestartGrace,
	}
	out.ExtraListen = append([]string(nil), cfg.ExtraListen...)
	out.TLSForwarders = append([]TLSForwarderConfig(nil), cfg.TLSForwarders...)
	return out
}

func restartProxyHard(ctx context.Context, cfg *Config, grace time.Duration) {
	if cfg == nil {
		return
	}
	log.Printf("proxy auto restart: stopping public proxy listeners and active SSH sessions")
	if publicPool != nil {
		publicPool.StopAll("proxy auto restart")
	}
	if tlsPool != nil {
		tlsPool.StopAll("proxy auto restart")
	}
	closed := userMgr.DisconnectAll()
	if closed > 0 {
		log.Printf("proxy auto restart: closed %d active SSH session(s)", closed)
	}
	if !sleepOrContextDone(ctx, grace) {
		return
	}

	publicAddrs := append([]string{cfg.Listen}, cfg.ExtraListen...)
	for attempt := 1; ; attempt++ {
		errs := []error{}
		if publicPool != nil {
			errs = append(errs, publicPool.Sync(publicAddrs)...)
		}
		if tlsPool != nil {
			errs = append(errs, tlsPool.Sync(cfg.TLSForwarders)...)
		}

		ok := len(errs) == 0
		if publicPool != nil && !publicPool.HasAll(publicAddrs) {
			ok = false
		}
		if tlsPool != nil && !tlsPool.HasAll(cfg.TLSForwarders) {
			ok = false
		}
		if ok {
			log.Printf("proxy auto restart: public proxy restarted")
			return
		}

		for _, err := range errs {
			log.Printf("proxy auto restart: start attempt %d failed: %v", attempt, err)
		}
		if len(errs) == 0 {
			log.Printf("proxy auto restart: start attempt %d incomplete; one or more listeners are still down", attempt)
		}
		if !sleepOrContextDone(ctx, 10*time.Second) {
			return
		}
	}
}

func proxyAutoRestartInterval(cfg *Config) time.Duration {
	if cfg == nil {
		return 0
	}
	raw := strings.TrimSpace(cfg.ProxyAutoRestartInterval)
	if raw == "" || raw == "0" || raw == "0s" || strings.EqualFold(raw, "off") || strings.EqualFold(raw, "disabled") {
		return 0
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		log.Printf("proxy auto restart disabled: invalid interval %q: %v", raw, err)
		return 0
	}
	if d < time.Minute {
		log.Printf("proxy auto restart disabled: interval %q is below minimum 1m", raw)
		return 0
	}
	return d
}

func proxyAutoRestartGrace(cfg *Config) time.Duration {
	if cfg == nil || strings.TrimSpace(cfg.ProxyAutoRestartGrace) == "" {
		return 2 * time.Second
	}
	d, err := time.ParseDuration(strings.TrimSpace(cfg.ProxyAutoRestartGrace))
	if err != nil || d < 0 {
		log.Printf("proxy auto restart: invalid grace %q, using 2s", cfg.ProxyAutoRestartGrace)
		return 2 * time.Second
	}
	if d > time.Minute {
		return time.Minute
	}
	return d
}

func sleepOrContextDone(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		select {
		case <-ctx.Done():
			return false
		default:
			return true
		}
	}
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}
