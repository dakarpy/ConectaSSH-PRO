package main

// This file provides the in-memory connection that carries a tunnelled session
// into this process's own SSH server.
//
// The obvious choice, net.Pipe, is unbuffered: every Write blocks until the
// peer Reads the same bytes. That couples the two sides in lock step, so a
// transport goroutine that is momentarily writing cannot also be draining, and
// each direction pays a scheduler round trip per write. A small buffer in each
// direction removes both problems and matches how a real TCP socket behaves,
// which is what the SSH server on the other end is written against.

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// tunnelPipeBuffer is the per-direction buffer, chosen to hold a full SSH
// handshake plus a couple of maximum-size packets without blocking. It bounds
// memory: two of these per tunnelled session, and nothing grows past them.
const tunnelPipeBuffer = 256 * 1024

// tunnelPipe is one direction of the connection: a bounded byte queue with
// deadline-aware blocking reads and writes.
type tunnelPipe struct {
	mu     sync.Mutex
	data   []byte
	offset int
	max    int
	// signal is closed and replaced whenever the queue changes, so waiters can
	// select on it alongside a deadline. This mirrors how the transports in
	// this codebase already signal readiness.
	signal chan struct{}
	closed bool
}

func newTunnelPipe(max int) *tunnelPipe {
	return &tunnelPipe{max: max, signal: make(chan struct{})}
}

// broadcastLocked wakes every waiter. The caller must hold mu.
func (p *tunnelPipe) broadcastLocked() {
	close(p.signal)
	p.signal = make(chan struct{})
}

func (p *tunnelPipe) availableLocked() int { return len(p.data) - p.offset }

// compactLocked reclaims the consumed prefix once it is worth the copy.
func (p *tunnelPipe) compactLocked() {
	if p.offset == 0 {
		return
	}
	if p.offset == len(p.data) {
		p.data = p.data[:0]
		p.offset = 0
		return
	}
	if p.offset >= p.max/2 {
		copy(p.data, p.data[p.offset:])
		p.data = p.data[:len(p.data)-p.offset]
		p.offset = 0
	}
}

// write copies data into the queue, blocking while it is full. It returns the
// number of bytes accepted, which is all of them unless the pipe closed or the
// deadline fired.
func (p *tunnelPipe) write(data []byte, deadline func() time.Time) (int, error) {
	written := 0
	for len(data) > 0 {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return written, io.ErrClosedPipe
		}
		p.compactLocked()
		room := p.max - p.availableLocked()
		if room > 0 {
			if room > len(data) {
				room = len(data)
			}
			p.data = append(p.data, data[:room]...)
			data = data[room:]
			written += room
			p.broadcastLocked()
			p.mu.Unlock()
			continue
		}
		wait := p.signal
		p.mu.Unlock()
		if err := waitWithDeadline(wait, deadline); err != nil {
			return written, err
		}
	}
	return written, nil
}

// read copies out whatever is queued, blocking until at least one byte is
// available, the pipe closes, or the deadline fires.
func (p *tunnelPipe) read(out []byte, deadline func() time.Time) (int, error) {
	if len(out) == 0 {
		return 0, nil
	}
	for {
		p.mu.Lock()
		if available := p.availableLocked(); available > 0 {
			n := copy(out, p.data[p.offset:])
			p.offset += n
			p.compactLocked()
			p.broadcastLocked()
			p.mu.Unlock()
			return n, nil
		}
		if p.closed {
			p.mu.Unlock()
			return 0, io.EOF
		}
		wait := p.signal
		p.mu.Unlock()
		if err := waitWithDeadline(wait, deadline); err != nil {
			return 0, err
		}
	}
}

// close marks the direction finished. Queued bytes stay readable so a peer can
// drain what was already sent, matching how a closed TCP socket behaves.
func (p *tunnelPipe) close() {
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		p.broadcastLocked()
	}
	p.mu.Unlock()
}

// waitWithDeadline blocks until the pipe signals, or the deadline passes.
func waitWithDeadline(signal <-chan struct{}, deadline func() time.Time) error {
	at := deadline()
	if at.IsZero() {
		<-signal
		return nil
	}
	delay := time.Until(at)
	if delay <= 0 {
		return os.ErrDeadlineExceeded
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-signal:
		return nil
	case <-timer.C:
		return os.ErrDeadlineExceeded
	}
}

// tunnelConn is one end of a buffered in-memory connection. It satisfies
// net.Conn, deadlines included, because the SSH server relies on
// SetReadDeadline to bound an unfinished handshake.
type tunnelConn struct {
	recv *tunnelPipe
	send *tunnelPipe
	addr transportAddr

	deadlineMu    sync.RWMutex
	readDeadline  time.Time
	writeDeadline time.Time

	closeOnce sync.Once
}

// newTunnelConnPair returns the two ends of a buffered connection. Bytes
// written to one end are readable from the other.
func newTunnelConnPair(label string, buffer int) (*tunnelConn, *tunnelConn) {
	if buffer <= 0 {
		buffer = tunnelPipeBuffer
	}
	toServer := newTunnelPipe(buffer)
	toClient := newTunnelPipe(buffer)
	addr := transportAddr(label)
	client := &tunnelConn{recv: toClient, send: toServer, addr: addr}
	server := &tunnelConn{recv: toServer, send: toClient, addr: addr}
	return client, server
}

func (c *tunnelConn) Read(p []byte) (int, error) {
	return c.recv.read(p, c.currentReadDeadline)
}

func (c *tunnelConn) Write(p []byte) (int, error) {
	n, err := c.send.write(p, c.currentWriteDeadline)
	if errors.Is(err, io.ErrClosedPipe) && n < len(p) {
		return n, io.ErrClosedPipe
	}
	return n, err
}

// Close shuts both directions. The peer's pending reads drain what was already
// queued and then see EOF.
func (c *tunnelConn) Close() error {
	c.closeOnce.Do(func() {
		c.send.close()
		c.recv.close()
	})
	return nil
}

func (c *tunnelConn) LocalAddr() net.Addr  { return c.addr }
func (c *tunnelConn) RemoteAddr() net.Addr { return c.addr }

func (c *tunnelConn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	c.deadlineMu.Unlock()
	c.wakeWaiters()
	return nil
}

func (c *tunnelConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = t
	c.deadlineMu.Unlock()
	c.wakeWaiters()
	return nil
}

func (c *tunnelConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.writeDeadline = t
	c.deadlineMu.Unlock()
	c.wakeWaiters()
	return nil
}

// wakeWaiters re-evaluates blocked readers and writers so a deadline set while
// they are parked takes effect instead of being seen only on the next wakeup.
func (c *tunnelConn) wakeWaiters() {
	c.recv.mu.Lock()
	c.recv.broadcastLocked()
	c.recv.mu.Unlock()
	c.send.mu.Lock()
	c.send.broadcastLocked()
	c.send.mu.Unlock()
}

func (c *tunnelConn) currentReadDeadline() time.Time {
	c.deadlineMu.RLock()
	defer c.deadlineMu.RUnlock()
	return c.readDeadline
}

func (c *tunnelConn) currentWriteDeadline() time.Time {
	c.deadlineMu.RLock()
	defer c.deadlineMu.RUnlock()
	return c.writeDeadline
}
