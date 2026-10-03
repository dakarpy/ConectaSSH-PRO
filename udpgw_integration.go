package main

// This file embeds the UDP gateway (udpgw) service into the main
// application.  The original udpgw program (public domain) accepts a
// TCP connection, then forwards framed UDP datagrams to arbitrary
// destinations and demultiplexes replies back to the originating
// connection.  Here we expose the same functionality via a
// configuration key in config.json.  When enabled, the server binds
// to the provided Listen address (or the default 0.0.0.0:7400 if
// unspecified) and handles each client in its own goroutine.  The
// gateway runs entirely in‑process and behaves like the standalone
// badvpn-udpgw daemon.

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// Safe ceilings applied regardless of config, so oversized values left in an
// existing config.json cannot bloat per-client memory at scale.
const (
	udpgwSocketBufferMax   = 512 * 1024 // per-client UDP socket buffer (kernel memory)
	udpgwWriteChanMax      = 1024       // per-client reply queue slots
	udpgwDefaultMaxClients = 10000      // total concurrent client cap
)

var (
	udpgwMu      sync.Mutex
	udpgwLn      net.Listener
	udpgwClients = make(map[net.Conn]struct{})
	// udpgwClientLimit is the max concurrent clients (0 = unlimited). Set when
	// the listener starts and read on every accept, all under udpgwMu.
	udpgwClientLimit int
	// udpgwClientsRejected counts clients turned away at the cap, for logging
	// and future stats. Guarded by udpgwMu.
	udpgwClientsRejected int64

	udpgwAutoMu     sync.Mutex
	udpgwAutoCancel context.CancelFunc
)

// stopUDPGW closes the active UDPGW listener, all active UDPGW client TCP
// sockets, and the optional auto-restart watchdog. It is a no-op if UDPGW is
// not running.
func stopUDPGW() {
	stopUDPGWAutoRestart()
	stopUDPGWInstance()
}

func stopUDPGWInstance() {
	udpgwMu.Lock()
	defer udpgwMu.Unlock()
	if udpgwLn != nil {
		_ = udpgwLn.Close()
		udpgwLn = nil
	}
	for conn := range udpgwClients {
		_ = conn.Close()
		delete(udpgwClients, conn)
	}
}

func stopUDPGWAutoRestart() {
	udpgwAutoMu.Lock()
	defer udpgwAutoMu.Unlock()
	if udpgwAutoCancel != nil {
		udpgwAutoCancel()
		udpgwAutoCancel = nil
	}
}

func registerUDPGWClient(conn net.Conn) bool {
	udpgwMu.Lock()
	defer udpgwMu.Unlock()
	if udpgwLn == nil {
		_ = conn.Close()
		return false
	}
	// Reject past the hard client cap so a surge cannot exhaust memory.
	if udpgwClientLimit > 0 && len(udpgwClients) >= udpgwClientLimit {
		udpgwClientsRejected++
		rejected := udpgwClientsRejected
		_ = conn.Close()
		// Log the first rejection and then every 1000th to avoid log spam.
		if rejected == 1 || rejected%1000 == 0 {
			log.Printf("udpgw: client cap reached (%d); rejected %d client(s) so far", udpgwClientLimit, rejected)
		}
		return false
	}
	udpgwClients[conn] = struct{}{}
	return true
}

func unregisterUDPGWClient(conn net.Conn) {
	udpgwMu.Lock()
	delete(udpgwClients, conn)
	udpgwMu.Unlock()
}

func udpgwRunning() bool {
	udpgwMu.Lock()
	defer udpgwMu.Unlock()
	return udpgwLn != nil
}

// startUDPGW starts the integrated UDP gateway if cfg is non‑nil and
// cfg.Listen is non‑empty.  It applies default values to any zero
// configuration fields and converts duration strings to time.Duration.
// The server runs in a goroutine; any fatal errors are logged and
// prevent the gateway from starting, but do not terminate the main
// process.
func startUDPGW(cfg *UDPGWConfig) error {
	if cfg == nil {
		return nil
	}
	stopUDPGWAutoRestart()
	if err := startUDPGWInstance(cfg); err != nil {
		return err
	}
	startUDPGWAutoRestart(cfg)
	return nil
}

func startUDPGWInstance(cfg *UDPGWConfig) error {
	if cfg == nil {
		return nil
	}
	// Default the listen address to the standalone default (0.0.0.0:7400) if
	// unspecified.  This matches the behaviour of the original
	// badvpn-udpgw program, which listens on all interfaces by default.
	listenAddr := cfg.Listen
	if listenAddr == "" {
		listenAddr = defaultUDPGWListen
	}
	cfg.Listen = listenAddr
	// Apply defaults for numeric fields if zero.
	c := &internalUDPGWConfig{}
	c.listen = listenAddr
	if cfg.MaxFrame > 0 {
		c.maxFrame = cfg.MaxFrame
	} else {
		c.maxFrame = 64 * 1024
	}
	c.debug = cfg.Debug
	if cfg.HexdumpN > 0 {
		c.hexdumpN = cfg.HexdumpN
	} else {
		c.hexdumpN = 64
	}
	// Per-client outgoing frame queue. A large queue costs ~24 B/slot of heap
	// per client even when empty; at thousands of clients that adds up. UDP is
	// lossy by nature, so a smaller queue that drops under backpressure is fine.
	// The value is clamped to udpgwWriteChanMax so an oversized value left in an
	// old config.json is ignored; only smaller custom values are honored.
	c.writeChan = udpgwWriteChanMax
	if cfg.WriteChan > 0 && cfg.WriteChan < udpgwWriteChanMax {
		c.writeChan = cfg.WriteChan
	}
	c.udpBindIP = cfg.UDPBindIP
	// Per-client UDP socket buffers are KERNEL memory, allocated per connected
	// client. 8 MB per socket is fine for a single process-wide listener, but
	// here every tunnel user gets its own socket, so a large value multiplied by
	// thousands of clients can exhaust kernel memory (especially if
	// net.core.rmem_max was raised for DNSTT). Clamp to udpgwSocketBufferMax so
	// old large config values are ignored; only smaller custom values are used.
	c.udpRBuf = udpgwSocketBufferMax
	if cfg.UDPRBuf > 0 && cfg.UDPRBuf < udpgwSocketBufferMax {
		c.udpRBuf = cfg.UDPRBuf
	}
	c.udpWBuf = udpgwSocketBufferMax
	if cfg.UDPWBuf > 0 && cfg.UDPWBuf < udpgwSocketBufferMax {
		c.udpWBuf = cfg.UDPWBuf
	}
	// Parse durations with fallback defaults.
	if cfg.MapTTL != "" {
		if d, err := time.ParseDuration(cfg.MapTTL); err == nil {
			c.mapTTL = d
		} else {
			log.Printf("udpgw: invalid map_ttl %q: %v; using default 90s", cfg.MapTTL, err)
			c.mapTTL = 90 * time.Second
		}
	} else {
		c.mapTTL = 90 * time.Second
	}
	if cfg.ReapEvery != "" {
		if d, err := time.ParseDuration(cfg.ReapEvery); err == nil {
			c.reapEvery = d
		} else {
			log.Printf("udpgw: invalid reap_every %q: %v; using default 10s", cfg.ReapEvery, err)
			c.reapEvery = 10 * time.Second
		}
	} else {
		c.reapEvery = 10 * time.Second
	}
	// Idle timeout for TCP clients.
	if cfg.IdleTimeout != "" {
		if d, err := time.ParseDuration(cfg.IdleTimeout); err == nil {
			c.idleTimeout = d
		} else {
			log.Printf("udpgw: invalid idle_timeout %q: %v; using default 2m", cfg.IdleTimeout, err)
			c.idleTimeout = 2 * time.Minute
		}
	} else {
		c.idleTimeout = 2 * time.Minute
	}
	// Per-client logical connID cap.
	if cfg.MaxClientConns > 0 {
		c.maxClientConns = cfg.MaxClientConns
	} else {
		c.maxClientConns = 10
	}
	// Per-client destination mapping cap.
	if cfg.MaxMapEntries > 0 {
		c.maxMapEntries = cfg.MaxMapEntries
	} else {
		c.maxMapEntries = 32768
	}
	// Total concurrent client cap. New clients past this are rejected so a
	// surge (e.g. well past normal load) cannot exhaust memory and crash.
	if cfg.MaxClients > 0 {
		c.maxClients = cfg.MaxClients
	} else {
		c.maxClients = udpgwDefaultMaxClients
	}
	// Start listening.
	ln, err := net.Listen("tcp", c.listen)
	if err != nil {
		log.Printf("udpgw: listen failed on %s: %v", c.listen, err)
		return fmt.Errorf("udpgw: listen failed on %s: %w", c.listen, err)
	}

	// Register as the active listener so stopUDPGW can close it, and publish
	// the current client cap so registerUDPGWClient can enforce it.
	udpgwMu.Lock()
	if udpgwLn != nil {
		_ = udpgwLn.Close()
	}
	udpgwLn = ln
	udpgwClientLimit = c.maxClients
	udpgwMu.Unlock()

	if c.debug {
		log.Printf("udpgw: listening on %s", c.listen)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				log.Printf("udpgw: accept error: %v", err)
				continue
			}
			if !registerUDPGWClient(conn) {
				continue
			}
			go func(client net.Conn) {
				defer unregisterUDPGWClient(client)
				handleUDPGWClient(client, c)
			}(conn)
		}
	}()
	return nil
}

func startUDPGWAutoRestart(cfg *UDPGWConfig) {
	interval := udpgwAutoRestartInterval(cfg)
	if interval <= 0 {
		return
	}
	grace := udpgwAutoRestartGrace(cfg)
	cfgCopy := *cfg
	ctx, cancel := context.WithCancel(context.Background())

	udpgwAutoMu.Lock()
	if udpgwAutoCancel != nil {
		udpgwAutoCancel()
	}
	udpgwAutoCancel = cancel
	udpgwAutoMu.Unlock()

	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		log.Printf("udpgw: auto restart enabled: interval=%s grace=%s mode=hard", interval, grace)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				log.Printf("udpgw: auto restart: stopping listener and connected clients")
				stopUDPGWInstance()
				if !sleepOrContextDone(ctx, grace) {
					return
				}
				for attempt := 1; ; attempt++ {
					if err := startUDPGWInstance(&cfgCopy); err != nil {
						log.Printf("udpgw: auto restart: start attempt %d failed: %v", attempt, err)
						if !sleepOrContextDone(ctx, 10*time.Second) {
							return
						}
						continue
					}
					log.Printf("udpgw: auto restart: listener and client handler restarted")
					break
				}
			}
		}
	}()
}

func udpgwAutoRestartInterval(cfg *UDPGWConfig) time.Duration {
	if cfg == nil {
		return 0
	}
	raw := strings.TrimSpace(cfg.AutoRestartInterval)
	if raw == "" || raw == "0" || raw == "0s" || strings.EqualFold(raw, "off") || strings.EqualFold(raw, "disabled") {
		return 0
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		log.Printf("udpgw: auto restart disabled: invalid interval %q: %v", raw, err)
		return 0
	}
	if d < time.Minute {
		log.Printf("udpgw: auto restart disabled: interval %q is below minimum 1m", raw)
		return 0
	}
	return d
}

func udpgwAutoRestartGrace(cfg *UDPGWConfig) time.Duration {
	if cfg == nil || strings.TrimSpace(cfg.AutoRestartGrace) == "" {
		return 2 * time.Second
	}
	d, err := time.ParseDuration(strings.TrimSpace(cfg.AutoRestartGrace))
	if err != nil || d < 0 {
		log.Printf("udpgw: auto restart: invalid grace %q, using 2s", cfg.AutoRestartGrace)
		return 2 * time.Second
	}
	if d > time.Minute {
		return time.Minute
	}
	return d
}

// internalUDPGWConfig mirrors the exported UDPGWConfig but with
// time.Duration fields for TTL and reaper intervals.  It does not
// embed JSON tags because it is not exposed to the user.
type internalUDPGWConfig struct {
	listen         string
	maxFrame       int
	debug          bool
	hexdumpN       int
	writeChan      int
	udpBindIP      string
	udpRBuf        int
	udpWBuf        int
	mapTTL         time.Duration
	reapEvery      time.Duration
	idleTimeout    time.Duration
	maxClientConns int
	maxMapEntries  int
	maxClients     int
}

// udpDestKey identifies a destination IPv4:port for the UDP gateway.  A
// mapping of this key to a connID+x byte is kept per client so
// replies can be routed correctly.  Each client maintains its own map
// of udpDestKey->udpMapVal entries.
type udpDestKey struct {
	ip   [4]byte
	port uint16
}

// udpMapVal stores the mapping from udpDestKey to connID, the x byte and the
// expiration time.
type udpMapVal struct {
	connID uint16
	x      byte
	exp    time.Time
}

// handleUDPGWClient manages a single TCP client connection to the UDP
// gateway.  It creates a per‑client UDP socket, reads frames from the
// TCP connection, sends UDP datagrams to the requested destination,
// maintains a mapping of udpDestKey->udpMapVal for routing replies, and
// writes reply frames back over the TCP connection.  When the client
// disconnects or an error occurs, all goroutines are terminated and the
// UDP socket is closed.
func handleUDPGWClient(conn net.Conn, c *internalUDPGWConfig) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	if c.debug {
		log.Printf("udpgw: client connected: %s", remote)
	}
	// Lower latency for interactive applications by disabling Nagle.
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
	// 32 KiB is ample for reading length-prefixed UDPGW frames (which are
	// MTU-sized in practice). bufio serves reads larger than its buffer by
	// reading straight into the caller's slice, so max-frame reads still work.
	// The old 256 KiB buffer wasted ~224 KiB of heap per connected client.
	br := bufio.NewReaderSize(conn, 32*1024)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Bind a UDP socket for this client.  Use cfg.udpBindIP if provided.
	var laddr *net.UDPAddr
	if c.udpBindIP != "" {
		ip := net.ParseIP(c.udpBindIP)
		if ip != nil {
			laddr = &net.UDPAddr{IP: ip, Port: 0}
		} else {
			log.Printf("udpgw[%s]: invalid udp_bind IP %q", remote, c.udpBindIP)
			return
		}
	}
	udpConn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		log.Printf("udpgw[%s]: UDP listen failed: %v", remote, err)
		return
	}
	defer udpConn.Close()
	_ = udpConn.SetReadBuffer(c.udpRBuf)
	_ = udpConn.SetWriteBuffer(c.udpWBuf)
	// Channel to queue outgoing frames back to the client.
	writeCh := make(chan []byte, c.writeChan)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case b := <-writeCh:
				if len(b) == 0 {
					continue
				}
				// If the client stops reading, don't block forever.
				_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
				_, err := conn.Write(b)
				if err != nil {
					cancel()
					return
				}
			}
		}
	}()
	// Destination -> connID+x mapping and active connID tracking per TCP client.
	var mu sync.Mutex
	destToConn := make(map[udpDestKey]udpMapVal)
	connIDLastSeen := make(map[uint16]time.Time)
	// Start a reaper goroutine to purge expired mappings.
	// Uses ctx instead of a separate stopReaper channel so that cancellation
	// is always uniform: any exit path that calls cancel() (error, disconnect,
	// idle timeout, panic-deferred cancel) also stops the reaper.
	go func() {
		t := time.NewTicker(c.reapEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				now := time.Now()
				mu.Lock()
				for k, v := range destToConn {
					if now.After(v.exp) {
						delete(destToConn, k)
					}
				}
				for id, lastSeen := range connIDLastSeen {
					if now.Sub(lastSeen) > c.mapTTL {
						delete(connIDLastSeen, id)
					}
				}
				mu.Unlock()
			}
		}
	}()
	// Goroutine to read UDP replies and write framed responses back.
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n <= 0 {
				continue
			}
			ip4 := from.IP.To4()
			if ip4 == nil {
				// IPv6 replies are dropped because framing only supports IPv4.
				continue
			}
			k := udpDestKey{port: uint16(from.Port)}
			copy(k.ip[:], ip4)
			mu.Lock()
			v, ok := destToConn[k]
			mu.Unlock()
			if !ok || time.Now().After(v.exp) {
				if c.debug {
					log.Printf("udpgw[%s]: dropping %dB from %s (no mapping)", remote, n, from.String())
				}
				continue
			}
			// Avoid unbounded memory growth: if the client is slow and the
			// write queue is full, drop replies rather than allocating more.
			if len(writeCh) == cap(writeCh) {
				if c.debug {
					log.Printf("udpgw[%s]: drop UDP reply %dB from %s (write queue full)", remote, n, from.String())
				}
				continue
			}
			frame := udpgwBuildFrame(v.connID, v.x, k.ip, k.port, buf[:n])
			select {
			case <-ctx.Done():
				return
			case writeCh <- frame:
			default:
				// Race with another sender filling the channel.
			}
			if c.debug {
				log.Printf("udpgw[%s]: UDP<- %dB from %s -> connID=%d x=0x%02x", remote, n, from.String(), v.connID, v.x)
			}
		}
	}()
	// Main loop: read frames from TCP, update mapping and send UDP.
	for {
		// Close idle TCP clients to avoid leaking goroutines.
		if c.idleTimeout > 0 {
			_ = conn.SetReadDeadline(time.Now().Add(c.idleTimeout))
		}
		payload, err := udpgwReadPayload(br, c.maxFrame)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if c.debug {
					log.Printf("udpgw[%s]: idle timeout (%s); closing", remote, c.idleTimeout)
				}
			}
			if err == io.EOF {
				if c.debug {
					log.Printf("udpgw: client disconnected: %s", remote)
				}
			} else {
				log.Printf("udpgw[%s]: read error: %v", remote, err)
			}
			cancel()
			_ = conn.Close()
			<-done
			return
		}
		// payload: connID(2) + X(1) + dstIPv4(4) + dstPort(2) + data
		if len(payload) < 2+1+4+2 {
			if c.debug {
				log.Printf("udpgw[%s]: too short payload %dB", remote, len(payload))
			}
			continue
		}
		connID := binary.BigEndian.Uint16(payload[0:2])
		x := payload[2]
		var dstIP [4]byte
		copy(dstIP[:], payload[3:7])
		dstPort := binary.BigEndian.Uint16(payload[7:9])
		data := payload[9:]
		if c.debug {
			log.Printf("udpgw[%s]: RX connID=%d dst=%d.%d.%d.%d:%d x=0x%02x len=%d", remote, connID, dstIP[0], dstIP[1], dstIP[2], dstIP[3], dstPort, x, len(data))
		}
		// Enforce a per-client logical session cap using udpgw connID.
		k := udpDestKey{ip: dstIP, port: dstPort}
		now := time.Now()
		mu.Lock()
		// Step 1: evict TTL-expired connIDs first.
		for id, lastSeen := range connIDLastSeen {
			if now.Sub(lastSeen) > c.mapTTL {
				delete(connIDLastSeen, id)
			}
		}
		// Step 2: if the connID is new and we are still at or above the cap
		// after TTL eviction, evict the single oldest entry to make room.
		// This prevents a client rotating connIDs faster than mapTTL from
		// bypassing maxClientConns and growing the map indefinitely.
		if _, alreadyKnown := connIDLastSeen[connID]; !alreadyKnown && c.maxClientConns > 0 && len(connIDLastSeen) >= c.maxClientConns {
			// Find and remove the oldest connID seen.
			var oldestID uint16
			var oldestTime time.Time
			first := true
			for id, lastSeen := range connIDLastSeen {
				if first || lastSeen.Before(oldestTime) {
					oldestID = id
					oldestTime = lastSeen
					first = false
				}
			}
			delete(connIDLastSeen, oldestID)
			if c.debug {
				log.Printf("udpgw[%s]: connID cap reached (%d); evicted oldest connID=%d to admit connID=%d", remote, c.maxClientConns, oldestID, connID)
			}
		}
		connIDLastSeen[connID] = now
		// Update the mapping (bounded to protect memory).
		if c.maxMapEntries > 0 && len(destToConn) >= c.maxMapEntries {
			// First, purge expired entries.
			for dk, dv := range destToConn {
				if now.After(dv.exp) {
					delete(destToConn, dk)
				}
			}
			// If still too large, evict arbitrary entries until we're under the cap.
			if len(destToConn) >= c.maxMapEntries {
				evict := (len(destToConn) - c.maxMapEntries) + 1
				for dk := range destToConn {
					delete(destToConn, dk)
					evict--
					if evict <= 0 {
						break
					}
				}
				if c.debug {
					log.Printf("udpgw[%s]: mapping cap reached; evicted entries, size=%d", remote, len(destToConn))
				}
			}
		}
		destToConn[k] = udpMapVal{connID: connID, x: x, exp: now.Add(c.mapTTL)}
		mu.Unlock()
		// Send the UDP datagram.
		raddr := &net.UDPAddr{IP: net.IP(dstIP[:]), Port: int(dstPort)}
		_, err = udpConn.WriteToUDP(data, raddr)
		if err != nil {
			if c.debug {
				log.Printf("udpgw[%s]: UDP write failed to %s: %v", remote, raddr.String(), err)
			}
			continue
		}
		if c.debug {
			log.Printf("udpgw[%s]: UDP-> %dB to %s", remote, len(data), raddr.String())
		}
	}
}

// udpgwReadPayload reads a length‑prefixed payload from r.  The length
// prefix is a little‑endian uint16.  Payloads larger than max cause an
// error.
func udpgwReadPayload(r *bufio.Reader, max int) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := int(binary.LittleEndian.Uint16(lenBuf[:]))
	if n <= 0 || n > max {
		return nil, fmt.Errorf("udpgw: invalid frame length %d", n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}

// udpgwBuildFrame constructs a reply frame for the client.  The frame
// consists of a little‑endian length prefix, then connID (big endian),
// x byte, source IPv4, source port, and the data.
func udpgwBuildFrame(connID uint16, x byte, ip [4]byte, port uint16, data []byte) []byte {
	payloadLen := 2 + 1 + 4 + 2 + len(data)
	out := make([]byte, 2+payloadLen)
	binary.LittleEndian.PutUint16(out[0:2], uint16(payloadLen))
	binary.BigEndian.PutUint16(out[2:4], connID)
	out[4] = x
	copy(out[5:9], ip[:])
	binary.BigEndian.PutUint16(out[9:11], port)
	copy(out[11:], data)
	return out
}
