package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	nativeUDPMaxPacket  = 65535
	nativeUDPBufferSize = 64 * 1024
	nativeUDPIdle       = 2 * time.Minute
)

// nativeVLESSUDPTunnel implements VLESS UDP-over-stream framing for a normal
// VLESS CommandUDP request. Xray uses classic 2-byte length-prefixed packets
// for this command. Do not auto-detect XUDP here: real DNS queries often have
// bytes 2/3 equal to 0x01/0x00, which looked like our old loose XUDP metadata
// check and caused the server to block waiting for a fake second payload.
// XUDP belongs to VLESS CommandMux and is handled separately when Mux support
// is implemented.
func nativeVLESSUDPTunnel(client io.ReadWriteCloser, backend net.Conn, uuid, email string, quotaState *xrayNativeQuotaState, up, down *rate.Limiter) {
	defer xrayRecover(fmt.Sprintf("native xray VLESS UDP tunnel user=%s", email))

	upMeter := newTrafficMeter(uuid, email, true, quotaState)
	downMeter := newTrafficMeter(uuid, email, false, quotaState)

	var wg sync.WaitGroup
	var closeOnce sync.Once
	ctx, cancel := context.WithCancel(context.Background())
	closeAll := func() {
		closeOnce.Do(func() {
			cancel()
			_ = backend.Close()
			_ = client.Close()
		})
	}

	wg.Add(1)
	xrayGo("native xray VLESS UDP uplink", func() {
		defer wg.Done()
		defer closeAll()
		for {
			payload, err := readVLESSLengthPacket(client)
			if err != nil {
				if err != io.EOF {
					xrayLogf("native xray: VLESS UDP client read failed: %v", err)
				}
				return
			}
			if len(payload) == 0 {
				continue
			}
			if err := waitNativeRate(ctx, up, len(payload)); err != nil {
				return
			}
			quotaReservation, err := reserveNativePacketQuota(upMeter, len(payload))
			if err != nil {
				return
			}
			if err := quotaReservation.wait(ctx); err != nil {
				return
			}
			n, err := backend.Write(payload)
			quotaReservation.finish(n)
			if err != nil {
				xrayLogf("native xray: VLESS UDP backend write failed: %v", err)
				return
			}
		}
	})

	wg.Add(1)
	xrayGo("native xray VLESS UDP downlink", func() {
		defer wg.Done()
		defer closeAll()
		buf := make([]byte, nativeUDPBufferSize)
		for {
			_ = backend.SetReadDeadline(time.Now().Add(nativeUDPIdle))
			n, err := backend.Read(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					return
				}
				if err != io.EOF {
					xrayLogf("native xray: VLESS UDP backend read failed: %v", err)
				}
				return
			}
			if n <= 0 {
				continue
			}
			if err := waitNativeRate(ctx, down, n); err != nil {
				return
			}
			quotaReservation, err := reserveNativePacketQuota(downMeter, n)
			if err != nil {
				return
			}
			if err := quotaReservation.wait(ctx); err != nil {
				return
			}
			if err := writeVLESSLengthPacket(client, buf[:n]); err != nil {
				quotaReservation.finish(0)
				xrayLogf("native xray: VLESS UDP client write failed: %v", err)
				return
			}
			quotaReservation.finish(n)
		}
	})

	wg.Wait()
	upMeter.flush()
	downMeter.flush()
	closeAll()
}

type vlessUDPPacketCodec struct {
	mu      sync.RWMutex
	decided bool
	xudp    bool
}

func (c *vlessUDPPacketCodec) setXUDP(v bool) {
	c.mu.Lock()
	if !c.decided {
		c.decided = true
		c.xudp = v
	}
	c.mu.Unlock()
}

func (c *vlessUDPPacketCodec) useXUDP() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.decided && c.xudp
}

func (c *vlessUDPPacketCodec) Read(r io.Reader) ([]byte, error) {
	if c.useXUDP() {
		return readVLESSXUDPPacket(r)
	}
	return c.readAuto(r)
}

func (c *vlessUDPPacketCodec) Write(w io.Writer, payload []byte) error {
	if c.useXUDP() {
		return writeVLESSXUDPPacket(w, payload)
	}
	return writeVLESSLengthPacket(w, payload)
}

func (c *vlessUDPPacketCodec) readAuto(r io.Reader) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n == 0 {
		c.setXUDP(false)
		return []byte{}, nil
	}
	if n > nativeUDPMaxPacket {
		return nil, fmt.Errorf("udp packet too large: %d", n)
	}

	// XUDP starts with a metadata frame length, not a payload length. Metadata is
	// small and has command/option bytes at offsets 2/3 after the two-byte mux ID.
	// Read a possible metadata frame once and fall back to normal length-prefixed
	// UDP if it does not match the XUDP shape. This lets the native emulator work
	// with clients whose default packet encoding is xudp while preserving classic
	// VLESS UDP framing.
	if n >= 4 && n <= 512 {
		candidate := make([]byte, n)
		if _, err := io.ReadFull(r, candidate); err != nil {
			return nil, err
		}
		if isVLESSXUDPMetadata(candidate) {
			c.setXUDP(true)
			return readVLESSXUDPPayloadAfterMeta(r, candidate)
		}
		c.setXUDP(false)
		return candidate, nil
	}

	c.setXUDP(false)
	pkt := make([]byte, n)
	_, err := io.ReadFull(r, pkt)
	return pkt, err
}

func readVLESSLengthPacket(r io.Reader) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n == 0 {
		return []byte{}, nil
	}
	if n > nativeUDPMaxPacket {
		return nil, fmt.Errorf("udp packet too large: %d", n)
	}
	pkt := make([]byte, n)
	_, err := io.ReadFull(r, pkt)
	return pkt, err
}

func writeVLESSLengthPacket(w io.Writer, payload []byte) error {
	if len(payload) > nativeUDPMaxPacket {
		return fmt.Errorf("udp packet too large: %d", len(payload))
	}
	// One Write is important for XHTTP because the response writer flushes once per
	// Write. Two writes per UDP packet doubles flush/syscall pressure.
	frame := make([]byte, 0, 2+len(payload))
	frame = appendUint16(frame, uint16(len(payload)))
	frame = append(frame, payload...)
	_, err := w.Write(frame)
	return err
}

func isVLESSXUDPMetadata(meta []byte) bool {
	if len(meta) < 4 {
		return false
	}
	cmd := meta[2]
	opt := meta[3]
	if cmd != 1 && cmd != 2 && cmd != 4 { // New, Keep, End/discard
		return false
	}
	return opt == 0 || opt == 1
}

func readVLESSXUDPPacket(r io.Reader) ([]byte, error) {
	for {
		var lenBuf [2]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return nil, err
		}
		n := int(binary.BigEndian.Uint16(lenBuf[:]))
		if n < 4 || n > 512 {
			return nil, fmt.Errorf("bad xudp metadata length: %d", n)
		}
		meta := make([]byte, n)
		if _, err := io.ReadFull(r, meta); err != nil {
			return nil, err
		}
		if !isVLESSXUDPMetadata(meta) {
			return nil, fmt.Errorf("bad xudp metadata command/option")
		}
		payload, err := readVLESSXUDPPayloadAfterMeta(r, meta)
		if err != nil {
			return nil, err
		}
		if payload != nil {
			return payload, nil
		}
	}
}

func readVLESSXUDPPayloadAfterMeta(r io.Reader, meta []byte) ([]byte, error) {
	if len(meta) < 4 {
		return nil, io.ErrUnexpectedEOF
	}
	if meta[2] == 4 { // discard/end marker
		return nil, nil
	}
	if meta[3] != 1 { // no payload attached
		return nil, nil
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n == 0 {
		return []byte{}, nil
	}
	if n > nativeUDPMaxPacket {
		return nil, fmt.Errorf("xudp payload too large: %d", n)
	}
	pkt := make([]byte, n)
	_, err := io.ReadFull(r, pkt)
	return pkt, err
}

func writeVLESSXUDPPacket(w io.Writer, payload []byte) error {
	if len(payload) > nativeUDPMaxPacket {
		return fmt.Errorf("udp packet too large: %d", len(payload))
	}
	// Metadata length 4, mux session id 0, command Keep, option payload-present.
	// This is accepted by Xray's xudp.PacketReader for responses when the UDP
	// destination is already known from the request header.
	var header [8]byte
	binary.BigEndian.PutUint16(header[0:2], 4)
	header[2] = 0
	header[3] = 0
	header[4] = 2 // Keep
	header[5] = 1 // Opt: payload follows
	binary.BigEndian.PutUint16(header[6:8], uint16(len(payload)))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// nativeVMessUDPTunnel maps one VMess body chunk to one UDP datagram. VMess AEAD
// chunking already preserves packet boundaries, so no extra VLESS length prefix
// is added inside the encrypted body.
func nativeVMessUDPTunnel(client nativeVMessStream, backend net.Conn, uuid, email string, quotaState *xrayNativeQuotaState, up, down *rate.Limiter) {
	defer xrayRecover(fmt.Sprintf("native xray VMess UDP tunnel user=%s", email))

	upMeter := newTrafficMeter(uuid, email, true, quotaState)
	downMeter := newTrafficMeter(uuid, email, false, quotaState)

	var wg sync.WaitGroup
	var closeOnce sync.Once
	ctx, cancel := context.WithCancel(context.Background())
	closeAll := func() {
		closeOnce.Do(func() {
			cancel()
			_ = backend.Close()
			_ = client.Close()
		})
	}

	wg.Add(1)
	xrayGo("native xray VMess UDP uplink", func() {
		defer wg.Done()
		defer closeAll()
		for {
			pkt, err := client.ReadPacket()
			if err != nil {
				if err != io.EOF {
					xrayLogf("native xray: VMess UDP client read failed: %v", err)
				}
				return
			}
			if len(pkt) == 0 {
				continue
			}
			if err := waitNativeRate(ctx, up, len(pkt)); err != nil {
				return
			}
			quotaReservation, err := reserveNativePacketQuota(upMeter, len(pkt))
			if err != nil {
				return
			}
			if err := quotaReservation.wait(ctx); err != nil {
				return
			}
			n, err := backend.Write(pkt)
			quotaReservation.finish(n)
			if err != nil {
				xrayLogf("native xray: VMess UDP backend write failed: %v", err)
				return
			}
		}
	})

	wg.Add(1)
	xrayGo("native xray VMess UDP downlink", func() {
		defer wg.Done()
		defer closeAll()
		buf := make([]byte, nativeUDPBufferSize)
		for {
			_ = backend.SetReadDeadline(time.Now().Add(nativeUDPIdle))
			n, err := backend.Read(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					return
				}
				if err != io.EOF {
					xrayLogf("native xray: VMess UDP backend read failed: %v", err)
				}
				return
			}
			if n <= 0 {
				continue
			}
			if err := waitNativeRate(ctx, down, n); err != nil {
				return
			}
			quotaReservation, err := reserveNativePacketQuota(downMeter, n)
			if err != nil {
				return
			}
			if err := quotaReservation.wait(ctx); err != nil {
				return
			}
			if err := client.WritePacket(buf[:n]); err != nil {
				quotaReservation.finish(0)
				xrayLogf("native xray: VMess UDP client write failed: %v", err)
				return
			}
			quotaReservation.finish(n)
		}
	})

	wg.Wait()
	upMeter.flush()
	downMeter.flush()
	closeAll()
}

func waitNativeRate(ctx context.Context, lim *rate.Limiter, n int) error {
	if lim == nil || n <= 0 {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return lim.WaitN(ctx, n)
}
