package main

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	defaultMainListen     = "0.0.0.0:80"
	defaultExtraListen    = "0.0.0.0:8080"
	defaultLocalSSHListen = "127.0.0.1:2222"
	defaultDNSTTListen    = "0.0.0.0:5300"
	defaultUDPGWListen    = "0.0.0.0:7300"
)

// normalizeDurationField validates one optional duration setting in place. An
// invalid value is cleared so the service falls back to its own default rather
// than starting with a nonsense timeout.
func normalizeDurationField(value *string, label string, minimum, maximum time.Duration, warn func(string, ...interface{})) {
	*value = strings.TrimSpace(*value)
	if *value == "" {
		return
	}
	d, err := time.ParseDuration(*value)
	if err != nil || d <= 0 {
		warn("%s %q is invalid; using the service default", label, *value)
		*value = ""
		return
	}
	if minimum > 0 && d < minimum {
		warn("%s %q is below the minimum %s; clamping", label, *value, minimum)
		*value = minimum.String()
		return
	}
	if maximum > 0 && d > maximum {
		warn("%s %q is above the maximum %s; clamping", label, *value, maximum)
		*value = maximum.String()
	}
}

// normalizeAutoRestartFields applies the shared auto-restart rules used by
// every embedded service: an interval below 1m disables the watchdog, and the
// grace delay is capped at 1m.
func normalizeAutoRestartFields(interval, grace *string, label string, warn func(string, ...interface{})) {
	*interval = strings.TrimSpace(*interval)
	if *interval != "" && *interval != "0" && *interval != "0s" &&
		!strings.EqualFold(*interval, "off") && !strings.EqualFold(*interval, "disabled") {
		if d, err := time.ParseDuration(*interval); err != nil {
			warn("%s auto restart interval %q is invalid; disabling auto restart", label, *interval)
			*interval = ""
		} else if d < time.Minute {
			warn("%s auto restart interval %q is below minimum 1m; disabling auto restart", label, *interval)
			*interval = ""
		}
	}
	*grace = strings.TrimSpace(*grace)
	if *grace != "" {
		if d, err := time.ParseDuration(*grace); err != nil || d < 0 {
			warn("%s auto restart grace %q is invalid; using default 2s", label, *grace)
			*grace = ""
		} else if d > time.Minute {
			warn("%s auto restart grace %q is above 1m; clamping to 1m", label, *grace)
			*grace = "1m"
		}
	}
}

func normalizeRuntimePorts(cfg *Config) []string {
	var warnings []string
	warn := func(format string, args ...interface{}) {
		msg := fmt.Sprintf(format, args...)
		warnings = append(warnings, msg)
		log.Printf("config safety: %s", msg)
	}

	cfg.Listen = strings.TrimSpace(cfg.Listen)
	if cfg.Listen == "" {
		cfg.Listen = defaultMainListen
	}
	if err := tcpAddrAvailableForPool(cfg.Listen, publicPool); err != nil {
		old := cfg.Listen
		cfg.Listen = defaultMainListen
		warn("main listener %s is unavailable (%v); using default %s", old, err, cfg.Listen)
		if err2 := tcpAddrAvailableForPool(cfg.Listen, publicPool); err2 != nil {
			warn("default main listener %s is also unavailable: %v", cfg.Listen, err2)
		}
	}

	seen := map[string]bool{cfg.Listen: true}
	extra := make([]string, 0, len(cfg.ExtraListen))
	for _, addr := range cfg.ExtraListen {
		addr = strings.TrimSpace(addr)
		if addr == "" || seen[addr] {
			continue
		}
		if err := tcpAddrAvailableForPool(addr, publicPool); err != nil {
			warn("extra listener %s is unavailable (%v)", addr, err)
			fallback := defaultExtraListen
			if !seen[fallback] {
				if err2 := tcpAddrAvailableForPool(fallback, publicPool); err2 == nil {
					extra = append(extra, fallback)
					seen[fallback] = true
					warn("extra listener fell back to default %s", fallback)
				} else {
					warn("default extra listener %s is also unavailable: %v", fallback, err2)
				}
			}
			continue
		}
		extra = append(extra, addr)
		seen[addr] = true
	}
	cfg.ExtraListen = extra

	oldLocalSSHListen := strings.TrimSpace(cfg.LocalSSHListen)
	normalizedLocalSSHListen, localSSHErr := normalizeLocalSSHListen(oldLocalSSHListen)
	cfg.LocalSSHListen = normalizedLocalSSHListen
	if localSSHErr != nil {
		warn("internal SSH listener %q is invalid (%v); using safe default %s", oldLocalSSHListen, localSSHErr, cfg.LocalSSHListen)
	}
	if err := tcpAddrAvailableForPool(cfg.LocalSSHListen, localPool); err != nil {
		old := cfg.LocalSSHListen
		cfg.LocalSSHListen = defaultLocalSSHListen
		if old != defaultLocalSSHListen {
			warn("internal SSH listener %s is unavailable (%v); using default %s", old, err, cfg.LocalSSHListen)
		}
		if err2 := tcpAddrAvailableForPool(cfg.LocalSSHListen, localPool); err2 != nil {
			warn("default internal SSH listener %s is unavailable: %v", cfg.LocalSSHListen, err2)
		}
	}

	cfg.ProxyAutoRestartInterval = strings.TrimSpace(cfg.ProxyAutoRestartInterval)
	if cfg.ProxyAutoRestartInterval != "" && cfg.ProxyAutoRestartInterval != "0" && cfg.ProxyAutoRestartInterval != "0s" && !strings.EqualFold(cfg.ProxyAutoRestartInterval, "off") && !strings.EqualFold(cfg.ProxyAutoRestartInterval, "disabled") {
		if d, err := time.ParseDuration(cfg.ProxyAutoRestartInterval); err != nil {
			warn("proxy auto restart interval %q is invalid; disabling auto restart", cfg.ProxyAutoRestartInterval)
			cfg.ProxyAutoRestartInterval = ""
		} else if d < time.Minute {
			warn("proxy auto restart interval %q is below 1m; disabling auto restart", cfg.ProxyAutoRestartInterval)
			cfg.ProxyAutoRestartInterval = ""
		}
	}
	cfg.ProxyAutoRestartGrace = strings.TrimSpace(cfg.ProxyAutoRestartGrace)
	if cfg.ProxyAutoRestartGrace != "" {
		if d, err := time.ParseDuration(cfg.ProxyAutoRestartGrace); err != nil || d < 0 {
			warn("proxy auto restart grace %q is invalid; using default 2s", cfg.ProxyAutoRestartGrace)
			cfg.ProxyAutoRestartGrace = ""
		} else if d > time.Minute {
			warn("proxy auto restart grace %q is above 1m; clamping to 1m", cfg.ProxyAutoRestartGrace)
			cfg.ProxyAutoRestartGrace = "1m"
		}
	}

	if cfg.DNSTT != nil {
		cfg.DNSTT.FakeDNSDomain = strings.TrimSpace(cfg.DNSTT.FakeDNSDomain)
		if cfg.DNSTT.FakeDNSEnabled {
			if cfg.DNSTT.FakeDNSDomain == "" {
				cfg.DNSTT.FakeDNSDomain = "t.local.lan"
			}
			// Automatically add the local/fake test zone to the accepted DNSTT
			// domains so the tunnel handler can decode traffic for it.
			cfg.DNSTT.Domains = append(cfg.DNSTT.Domains, cfg.DNSTT.FakeDNSDomain)
		}
		cfg.DNSTT.Domains = normalizeDNSTTDomainList(cfg.DNSTT.Domain, cfg.DNSTT.Domains)
		if len(cfg.DNSTT.Domains) > 0 {
			cfg.DNSTT.Domain = cfg.DNSTT.Domains[0]
		} else {
			cfg.DNSTT.Domain = strings.TrimSpace(cfg.DNSTT.Domain)
		}
		if cfg.DNSTT.FakeDNSEnabled {
			localDomains := normalizeDNSTTDomainList(cfg.DNSTT.FakeDNSDomain, nil)
			if len(localDomains) > 0 {
				cfg.DNSTT.FakeDNSDomain = localDomains[0]
			}
		}

		var migratedLegacyDNSTTWildcard bool
		cfg.DNSTT.UDPListen, migratedLegacyDNSTTWildcard = normalizeDNSTTListenDefault(cfg.DNSTT.UDPListen)
		if migratedLegacyDNSTTWildcard {
			warn("DNSTT legacy default [::]:5300 is IPv6-only; using IPv4 default %s", cfg.DNSTT.UDPListen)
		}
		if err := udpAddrAvailableForDNSTT(cfg.DNSTT.UDPListen); err != nil {
			old := cfg.DNSTT.UDPListen
			cfg.DNSTT.UDPListen = defaultDNSTTListen
			warn("DNSTT UDP listener %s is unavailable (%v); using default %s", old, err, cfg.DNSTT.UDPListen)
			if err2 := udpAddrAvailableForDNSTT(cfg.DNSTT.UDPListen); err2 != nil {
				warn("default DNSTT UDP listener %s is also unavailable: %v", cfg.DNSTT.UDPListen, err2)
			}
		}

		if cfg.DNSTT.FakeDNSEnabled {
			cfg.DNSTT.FakeDNSListen = strings.TrimSpace(cfg.DNSTT.FakeDNSListen)
			if cfg.DNSTT.FakeDNSListen == "" {
				cfg.DNSTT.FakeDNSListen = "[::]:53"
			}
			if !sameUDPListenAddress(cfg.DNSTT.FakeDNSListen, cfg.DNSTT.UDPListen) {
				if err := udpAddrAvailableForDNSTT(cfg.DNSTT.FakeDNSListen); err != nil {
					warn("built-in DNSTT local DNS listener %s is unavailable: %v", cfg.DNSTT.FakeDNSListen, err)
				}
			}
		}

		cfg.DNSTT.AutoRestartInterval = strings.TrimSpace(cfg.DNSTT.AutoRestartInterval)
		if cfg.DNSTT.AutoRestartInterval != "" && cfg.DNSTT.AutoRestartInterval != "0" && cfg.DNSTT.AutoRestartInterval != "0s" && !strings.EqualFold(cfg.DNSTT.AutoRestartInterval, "off") && !strings.EqualFold(cfg.DNSTT.AutoRestartInterval, "disabled") {
			if d, err := time.ParseDuration(cfg.DNSTT.AutoRestartInterval); err != nil {
				warn("DNSTT auto restart interval %q is invalid; disabling auto restart", cfg.DNSTT.AutoRestartInterval)
				cfg.DNSTT.AutoRestartInterval = ""
			} else if d < time.Minute {
				warn("DNSTT auto restart interval %q is below 1m; disabling auto restart", cfg.DNSTT.AutoRestartInterval)
				cfg.DNSTT.AutoRestartInterval = ""
			}
		}
		cfg.DNSTT.AutoRestartGrace = strings.TrimSpace(cfg.DNSTT.AutoRestartGrace)
		if cfg.DNSTT.AutoRestartGrace != "" {
			if d, err := time.ParseDuration(cfg.DNSTT.AutoRestartGrace); err != nil || d < 0 {
				warn("DNSTT auto restart grace %q is invalid; using default 2s", cfg.DNSTT.AutoRestartGrace)
				cfg.DNSTT.AutoRestartGrace = ""
			} else if d > time.Minute {
				warn("DNSTT auto restart grace %q is above 1m; clamping to 1m", cfg.DNSTT.AutoRestartGrace)
				cfg.DNSTT.AutoRestartGrace = "1m"
			}
		}

		if cfg.DNSTT.MaxSessions < -1 {
			warn("DNSTT max_sessions %d is invalid; using unlimited (-1)", cfg.DNSTT.MaxSessions)
			cfg.DNSTT.MaxSessions = -1
		}
		if cfg.DNSTT.MaxStreams < -1 {
			warn("DNSTT max_streams %d is invalid; using unlimited (-1)", cfg.DNSTT.MaxStreams)
			cfg.DNSTT.MaxStreams = -1
		}
		if cfg.DNSTT.PendingResponses > 0 {
			if cfg.DNSTT.PendingResponses < minDNSTTPendingResponses {
				warn("DNSTT pending_responses %d is too low; clamping to %d", cfg.DNSTT.PendingResponses, minDNSTTPendingResponses)
				cfg.DNSTT.PendingResponses = minDNSTTPendingResponses
			} else if cfg.DNSTT.PendingResponses > maxDNSTTPendingResponses {
				warn("DNSTT pending_responses %d is too high; clamping to %d", cfg.DNSTT.PendingResponses, maxDNSTTPendingResponses)
				cfg.DNSTT.PendingResponses = maxDNSTTPendingResponses
			}
		}
		if cfg.DNSTT.StreamBuffer > 0 {
			if cfg.DNSTT.StreamBuffer < minDNSTTStreamBuffer {
				warn("DNSTT stream_buffer %d is too low; clamping to %d", cfg.DNSTT.StreamBuffer, minDNSTTStreamBuffer)
				cfg.DNSTT.StreamBuffer = minDNSTTStreamBuffer
			} else if cfg.DNSTT.StreamBuffer > maxDNSTTStreamBuffer {
				warn("DNSTT stream_buffer %d is too high; clamping to %d", cfg.DNSTT.StreamBuffer, maxDNSTTStreamBuffer)
				cfg.DNSTT.StreamBuffer = maxDNSTTStreamBuffer
			}
		}
		if cfg.DNSTT.UDPReadBuffer < 0 {
			warn("DNSTT udp_read_buffer %d is invalid; using default", cfg.DNSTT.UDPReadBuffer)
			cfg.DNSTT.UDPReadBuffer = 0
		}
		if cfg.DNSTT.UDPWriteBuffer < 0 {
			warn("DNSTT udp_write_buffer %d is invalid; using default", cfg.DNSTT.UDPWriteBuffer)
			cfg.DNSTT.UDPWriteBuffer = 0
		}
		if cfg.DNSTT.FakeDNSWorkers < 0 {
			warn("DNSTT fake_dns_workers %d is invalid; using automatic default", cfg.DNSTT.FakeDNSWorkers)
			cfg.DNSTT.FakeDNSWorkers = 0
		} else if cfg.DNSTT.FakeDNSWorkers > maxDNSTTFakeDNSWorkers {
			warn("DNSTT fake_dns_workers %d is too high; clamping to %d", cfg.DNSTT.FakeDNSWorkers, maxDNSTTFakeDNSWorkers)
			cfg.DNSTT.FakeDNSWorkers = maxDNSTTFakeDNSWorkers
		}
		if cfg.DNSTT.DNSResponseWorkers < 0 {
			warn("DNSTT dns_response_workers %d is invalid; using default", cfg.DNSTT.DNSResponseWorkers)
			cfg.DNSTT.DNSResponseWorkers = 0
		} else if cfg.DNSTT.DNSResponseWorkers > maxDNSTTResponseWorkers {
			warn("DNSTT dns_response_workers %d is too high; clamping to %d", cfg.DNSTT.DNSResponseWorkers, maxDNSTTResponseWorkers)
			cfg.DNSTT.DNSResponseWorkers = maxDNSTTResponseWorkers
		}
	}

	if cfg.UDPGW != nil {
		cfg.UDPGW.Listen = strings.TrimSpace(cfg.UDPGW.Listen)
		if cfg.UDPGW.Listen == "" {
			cfg.UDPGW.Listen = defaultUDPGWListen
		}
		if err := tcpAddrAvailableForUDPGW(cfg.UDPGW.Listen); err != nil {
			old := cfg.UDPGW.Listen
			cfg.UDPGW.Listen = defaultUDPGWListen
			warn("UDPGW listener %s is unavailable (%v); using default %s", old, err, cfg.UDPGW.Listen)
			if err2 := tcpAddrAvailableForUDPGW(cfg.UDPGW.Listen); err2 != nil {
				warn("default UDPGW listener %s is also unavailable: %v", cfg.UDPGW.Listen, err2)
			}
		}

		cfg.UDPGW.AutoRestartInterval = strings.TrimSpace(cfg.UDPGW.AutoRestartInterval)
		if cfg.UDPGW.AutoRestartInterval != "" && cfg.UDPGW.AutoRestartInterval != "0" && cfg.UDPGW.AutoRestartInterval != "0s" && !strings.EqualFold(cfg.UDPGW.AutoRestartInterval, "off") && !strings.EqualFold(cfg.UDPGW.AutoRestartInterval, "disabled") {
			if d, err := time.ParseDuration(cfg.UDPGW.AutoRestartInterval); err != nil {
				warn("UDPGW auto restart interval %q is invalid; disabling auto restart", cfg.UDPGW.AutoRestartInterval)
				cfg.UDPGW.AutoRestartInterval = ""
			} else if d < time.Minute {
				warn("UDPGW auto restart interval %q is below 1m; disabling auto restart", cfg.UDPGW.AutoRestartInterval)
				cfg.UDPGW.AutoRestartInterval = ""
			}
		}
		cfg.UDPGW.AutoRestartGrace = strings.TrimSpace(cfg.UDPGW.AutoRestartGrace)
		if cfg.UDPGW.AutoRestartGrace != "" {
			if d, err := time.ParseDuration(cfg.UDPGW.AutoRestartGrace); err != nil || d < 0 {
				warn("UDPGW auto restart grace %q is invalid; using default 2s", cfg.UDPGW.AutoRestartGrace)
				cfg.UDPGW.AutoRestartGrace = ""
			} else if d > time.Minute {
				warn("UDPGW auto restart grace %q is above 1m; clamping to 1m", cfg.UDPGW.AutoRestartGrace)
				cfg.UDPGW.AutoRestartGrace = "1m"
			}
		}
	}

	if cfg.BHTTP != nil {
		addrs := normalizeBHTTPListenList(cfg.BHTTP.Listen)
		if len(addrs) == 0 && !cfg.BHTTP.SharedPorts {
			// With no dedicated listener and no shared ports nothing would
			// serve BHTTP at all, so fall back to a port of its own.
			addrs = []string{defaultBHTTPListen}
			warn("BHTTP has no listen address and shared ports are off; using default %s", defaultBHTTPListen)
		}
		kept := make([]string, 0, len(addrs))
		for _, addr := range addrs {
			if err := tcpAddrAvailableForBHTTP(addr); err != nil {
				warn("BHTTP listener %s is unavailable (%v)", addr, err)
				continue
			}
			kept = append(kept, addr)
		}
		if len(addrs) > 0 && len(kept) == 0 {
			warn("no BHTTP listener could be opened; keeping the configured addresses so the panel reports the failure")
			kept = addrs
		}
		cfg.BHTTP.Listen = kept

		normalizeDurationField(&cfg.BHTTP.SessionTimeout, "BHTTP session_timeout", 10*time.Second, time.Hour, warn)
		if cfg.BHTTP.MaxV2Lanes < 0 {
			warn("BHTTP max_v2_lanes %d is invalid; using the protocol default", cfg.BHTTP.MaxV2Lanes)
			cfg.BHTTP.MaxV2Lanes = 0
		}
		if cfg.BHTTP.MaxSessions < -1 {
			warn("BHTTP max_sessions %d is invalid; using unlimited (-1)", cfg.BHTTP.MaxSessions)
			cfg.BHTTP.MaxSessions = -1
		}
		if cfg.BHTTP.MaxConnections < -1 {
			warn("BHTTP max_connections %d is invalid; using unlimited (-1)", cfg.BHTTP.MaxConnections)
			cfg.BHTTP.MaxConnections = -1
		}
		normalizeAutoRestartFields(&cfg.BHTTP.AutoRestartInterval, &cfg.BHTTP.AutoRestartGrace, "BHTTP", warn)
	}

	if cfg.BTUN != nil {
		normalizeBTUNConfig(cfg.BTUN)
		if cfg.BTUN.TCPListen == "" && cfg.BTUN.UDPListen == "" && !cfg.BTUN.SharedPorts {
			// With no listener and no shared ports nothing would serve BTUN at
			// all, so fall back to ports of its own.
			cfg.BTUN.TCPListen = defaultBTUNTCPListen
			cfg.BTUN.UDPListen = defaultBTUNUDPListen
			warn("BTUN has no listener and shared ports are off; using defaults tcp/udp %s", defaultBTUNTCPListen)
		}
		if cfg.BTUN.TCPListen != "" {
			if err := tcpAddrAvailableForBTUN(cfg.BTUN.TCPListen); err != nil {
				warn("BTUN TCP listener %s is unavailable (%v)", cfg.BTUN.TCPListen, err)
			}
		}
		if cfg.BTUN.UDPListen != "" {
			if err := udpAddrAvailableForBTUN(cfg.BTUN.UDPListen); err != nil {
				warn("BTUN UDP listener %s is unavailable (%v)", cfg.BTUN.UDPListen, err)
			}
		}
		if _, _, err := net.ParseCIDR(cfg.BTUN.Subnet); err != nil {
			warn("BTUN subnet %q is invalid (%v); using default %s", cfg.BTUN.Subnet, err, defaultBTUNSubnet)
			cfg.BTUN.Subnet = defaultBTUNSubnet
			cfg.BTUN.Gateway = ""
		}
		if gateway, err := btunGatewayForSubnet(cfg.BTUN.Subnet); err != nil {
			warn("BTUN subnet %q cannot host clients (%v); using default %s", cfg.BTUN.Subnet, err, defaultBTUNSubnet)
			cfg.BTUN.Subnet = defaultBTUNSubnet
			cfg.BTUN.Gateway, _ = btunGatewayForSubnet(defaultBTUNSubnet)
		} else if cfg.BTUN.Gateway == "" {
			cfg.BTUN.Gateway = gateway
		} else if _, _, err := net.ParseCIDR(cfg.BTUN.Gateway); err != nil {
			warn("BTUN gateway %q is invalid (%v); deriving %s from the subnet", cfg.BTUN.Gateway, err, gateway)
			cfg.BTUN.Gateway = gateway
		}
		if cfg.BTUN.MTU < 576 || cfg.BTUN.MTU > 9000 {
			warn("BTUN mtu %d is out of the 576..9000 range; using default %d", cfg.BTUN.MTU, defaultBTUNMTU)
			cfg.BTUN.MTU = defaultBTUNMTU
		}
		normalizeDurationField(&cfg.BTUN.HandshakeTimeout, "BTUN handshake_timeout", time.Second, 5*time.Minute, warn)
		normalizeDurationField(&cfg.BTUN.IdleTimeout, "BTUN idle_timeout", 10*time.Second, time.Hour, warn)
		if cfg.BTUN.MaxPacketSize < 0 {
			warn("BTUN max_packet_size %d is invalid; using the protocol default", cfg.BTUN.MaxPacketSize)
			cfg.BTUN.MaxPacketSize = 0
		}
		if cfg.BTUN.MaxCoverBytes < 0 {
			warn("BTUN max_cover_bytes %d is invalid; using the protocol default", cfg.BTUN.MaxCoverBytes)
			cfg.BTUN.MaxCoverBytes = 0
		}
		if cfg.BTUN.MaxSessions < -1 {
			warn("BTUN max_sessions %d is invalid; using unlimited (-1)", cfg.BTUN.MaxSessions)
			cfg.BTUN.MaxSessions = -1
		}
		normalizeAutoRestartFields(&cfg.BTUN.AutoRestartInterval, &cfg.BTUN.AutoRestartGrace, "BTUN", warn)
	}

	if cfg.HCR != nil {
		addrs := normalizeHCRListenList(cfg.HCR.Listen)
		if len(addrs) == 0 && !cfg.HCR.SharedPorts {
			addrs = []string{defaultHCRListen}
			warn("HCR has no listen address and shared ports are off; using default %s", defaultHCRListen)
		}
		kept := make([]string, 0, len(addrs))
		for _, addr := range addrs {
			if err := tcpAddrAvailableForHCR(addr); err != nil {
				warn("HCR listener %s is unavailable (%v)", addr, err)
				continue
			}
			kept = append(kept, addr)
		}
		if len(addrs) > 0 && len(kept) == 0 {
			warn("no HCR listener could be opened; keeping the configured addresses so the panel reports the failure")
			kept = addrs
		}
		cfg.HCR.Listen = kept

		normalizeDurationField(&cfg.HCR.DownloadPollTimeout, "HCR download_poll_timeout", time.Second, time.Minute, warn)
		normalizeDurationField(&cfg.HCR.IdleSessionTimeout, "HCR idle_session_timeout", 10*time.Second, time.Hour, warn)
		if cfg.HCR.MaxSessions < -1 {
			warn("HCR max_sessions %d is invalid; using unlimited (-1)", cfg.HCR.MaxSessions)
			cfg.HCR.MaxSessions = -1
		}
		if cfg.HCR.MaxConnections < -1 {
			warn("HCR max_connections %d is invalid; using unlimited (-1)", cfg.HCR.MaxConnections)
			cfg.HCR.MaxConnections = -1
		}
		if cfg.HCR.MaxSourceSessions < 0 {
			warn("HCR max_source_sessions %d is invalid; using 0 (unlimited)", cfg.HCR.MaxSourceSessions)
			cfg.HCR.MaxSourceSessions = 0
		}
		if cfg.HCR.MaxDownloadFrame < 0 {
			warn("HCR max_download_frame %d is invalid; using the default", cfg.HCR.MaxDownloadFrame)
			cfg.HCR.MaxDownloadFrame = 0
		}
		normalizeAutoRestartFields(&cfg.HCR.AutoRestartInterval, &cfg.HCR.AutoRestartGrace, "HCR", warn)
	}

	return warnings
}

// tcpAddrAvailableForHCR reports whether an HCR listen address can be bound. An
// address this process already serves for HCR is treated as available.
func tcpAddrAvailableForHCR(addr string) error {
	if addr == "" {
		return nil
	}
	if hcrRunning() {
		for _, current := range strings.Split(hcrListenList(), ", ") {
			if strings.TrimSpace(current) == addr {
				return nil
			}
		}
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return ln.Close()
}

// tcpAddrAvailableForBHTTP reports whether a BHTTP listen address can be bound.
// An address this process already serves for BHTTP is treated as available, so
// saving an unchanged config does not report a false conflict.
func tcpAddrAvailableForBHTTP(addr string) error {
	if addr == "" {
		return nil
	}
	if bhttpRunning() {
		for _, current := range strings.Split(bhttpListenList(), ", ") {
			if strings.TrimSpace(current) == addr {
				return nil
			}
		}
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return ln.Close()
}

func tcpAddrAvailableForBTUN(addr string) error {
	if addr == "" {
		return nil
	}
	btunMu.Lock()
	current := btunListenTCP
	running := btunServer != nil
	btunMu.Unlock()
	if running && current == addr {
		return nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return ln.Close()
}

func udpAddrAvailableForBTUN(addr string) error {
	if addr == "" {
		return nil
	}
	btunMu.Lock()
	current := btunListenUDP
	running := btunServer != nil
	btunMu.Unlock()
	if running && current == addr {
		return nil
	}
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	return pc.Close()
}

// normalizeLocalSSHListen guarantees that the raw integration endpoint can
// only bind to this machine. Hostnames and wildcard/non-loopback addresses are
// deliberately rejected: a changed hosts file must not turn an internal SSH
// port into a remotely reachable service.
func normalizeLocalSSHListen(addr string) (string, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return defaultLocalSSHListen, nil
	}

	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return defaultLocalSSHListen, fmt.Errorf("expected loopback host:port: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return defaultLocalSSHListen, fmt.Errorf("host must be a numeric loopback IP")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return defaultLocalSSHListen, fmt.Errorf("port must be between 1 and 65535")
	}
	if ipv4 := ip.To4(); ipv4 != nil {
		ip = ipv4
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(port)), nil
}

func tcpAddrAvailableForPool(addr string, pool *listenerPool) error {
	if addr == "" {
		return nil
	}
	if pool != nil && pool.Has(addr) {
		return nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return ln.Close()
}

func tcpAddrAvailableForUDPGW(addr string) error {
	if addr == "" {
		return nil
	}
	globalCfgMu.RLock()
	current := globalCfg != nil && globalCfg.UDPGW != nil && globalCfg.UDPGW.Listen == addr && udpgwRunning()
	globalCfgMu.RUnlock()
	if current {
		return nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return ln.Close()
}

func normalizeDNSTTDomainList(primary string, domains []string) []string {
	seen := make(map[string]bool, len(domains)+1)
	out := make([]string, 0, len(domains)+1)
	add := func(v string) {
		v = strings.TrimSpace(v)
		v = strings.TrimSuffix(v, ".")
		v = strings.ToLower(v)
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
	}
	add(primary)
	for _, d := range domains {
		add(d)
	}
	return out
}

// normalizeDNSTTListenDefault keeps explicit IPv4 and concrete IPv6 listeners,
// but migrates the old wildcard IPv6 default. listenDNSTTPacket deliberately
// opens IPv6 addresses with udp6, so [::]:5300 never receives IPv4 queries.
// Existing installations commonly inherited that value from the old default;
// moving only that wildcard/default-port combination makes them work after an
// update without changing intentionally selected IPv6 interface addresses.
func normalizeDNSTTListenDefault(addr string) (string, bool) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return defaultDNSTTListen, false
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil || port != "5300" {
		return addr, false
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip != nil && ip.To4() == nil && ip.IsUnspecified() {
		return defaultDNSTTListen, true
	}
	return addr, false
}

func udpAddrAvailableForDNSTT(addr string) error {
	if addr == "" {
		return nil
	}
	globalCfgMu.RLock()
	current := false
	if globalCfg != nil && globalCfg.DNSTT != nil && dnsttRunning() {
		current = sameUDPListenAddress(globalCfg.DNSTT.UDPListen, addr) || sameUDPListenAddress(globalCfg.DNSTT.FakeDNSListen, addr)
	}
	globalCfgMu.RUnlock()
	if current {
		return nil
	}
	pc, err := listenDNSTTPacket(addr)
	if err != nil {
		return err
	}
	return pc.Close()
}
