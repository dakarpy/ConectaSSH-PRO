package main

// Pure-Go VMess (AEAD) server, part of the in-process Xray emulator.
//
// This implements the modern "VMess AEAD" protocol (alterId = 0) exactly as
// spoken by current Xray/v2ray clients: AEAD-authenticated request header,
// AES-128-GCM / ChaCha20-Poly1305 chunked body with SHAKE-masked lengths,
// optional global padding and authenticated length, and the AEAD response
// header + body. Byte offsets, KDF labels and orderings follow the v2fly/xray
// reference (proxy/vmess/{aead,encoding}). Legacy MD5-auth VMess (alterId > 0)
// is intentionally not supported.
//
// TCP and UDP commands are served. Mux is intentionally not supported in the
// native emulator yet.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"hash/fnv"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/sha3"
)

// ---------- constants ----------

const vmessCmdKeyMagic = "c48619fe-8f02-49e0-b9e9-edf763e17e21"

const (
	kdfSaltVMessAEADKDF = "VMess AEAD KDF"

	kdfLabelAuthIDEncryptionKey = "AES Auth ID Encryption"

	kdfLabelReqHeaderLenKey = "VMess Header AEAD Key_Length"
	kdfLabelReqHeaderLenIV  = "VMess Header AEAD Nonce_Length"
	kdfLabelReqHeaderKey    = "VMess Header AEAD Key"
	kdfLabelReqHeaderIV     = "VMess Header AEAD Nonce"

	kdfLabelRespHeaderLenKey = "AEAD Resp Header Len Key"
	kdfLabelRespHeaderLenIV  = "AEAD Resp Header Len IV"
	kdfLabelRespHeaderKey    = "AEAD Resp Header Key"
	kdfLabelRespHeaderIV     = "AEAD Resp Header IV"

	kdfLabelAuthLen = "auth_len"
)

// VMess request option flags (header byte 34).
const (
	vmessOptChunkStream         = 0x01
	vmessOptChunkMasking        = 0x04
	vmessOptGlobalPadding       = 0x08
	vmessOptAuthenticatedLength = 0x10
)

// VMess security types (low nibble of header byte 35).
const (
	vmessSecAES128GCM        = 3
	vmessSecChaCha20Poly1305 = 4
	vmessSecNone             = 5
)

// VMess commands (header byte 37).
const (
	vmessCmdTCP = 1
	vmessCmdUDP = 2
	vmessCmdMux = 3
)

const vmessTimeWindowSeconds = 120

// ---------- KDF ("VMess AEAD KDF", nested HMAC-SHA256) ----------

type hmacCreator struct {
	parent *hmacCreator
	value  []byte
}

func newHMAC(f func() hash.Hash, key []byte) hash.Hash {
	return hmac.New(f, key)
}

func (h *hmacCreator) create() hash.Hash {
	if h.parent == nil {
		return newHMAC(sha256.New, h.value)
	}
	return newHMAC(h.parent.create, h.value)
}

func vmessKDF(key []byte, path ...string) []byte {
	c := &hmacCreator{value: []byte(kdfSaltVMessAEADKDF)}
	for _, p := range path {
		c = &hmacCreator{value: []byte(p), parent: c}
	}
	h := c.create()
	h.Write(key)
	return h.Sum(nil)
}

func vmessKDF16(key []byte, path ...string) []byte {
	return vmessKDF(key, path...)[:16]
}

// ---------- command key / crypto helpers ----------

func vmessCmdKey(uuid [16]byte) [16]byte {
	h := md5.New()
	h.Write(uuid[:])
	h.Write([]byte(vmessCmdKeyMagic))
	var out [16]byte
	copy(out[:], h.Sum(nil))
	return out
}

func newAESGCM(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err) // only happens on wrong key length — a programmer error
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return gcm
}

// vmessChaChaKey expands a 16-byte key into the 32-byte ChaCha20 key VMess uses:
// MD5(key) || MD5(MD5(key)).
func vmessChaChaKey(key []byte) []byte {
	h1 := md5.Sum(key)
	h2 := md5.Sum(h1[:])
	out := make([]byte, 32)
	copy(out[0:16], h1[:])
	copy(out[16:32], h2[:])
	return out
}

func absInt64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

func shakeNext(s sha3.ShakeHash) uint16 {
	var b [2]byte
	_, _ = s.Read(b[:])
	return binary.BigEndian.Uint16(b[:])
}

// ---------- auth ID matching ----------

// matchVMess tries every VMess client's auth-ID cipher against the 16-byte
// auth ID, returning the client whose key decrypts to a CRC-valid, in-window
// timestamp. This is O(clients) AES blocks per connection.
func (ib *nativeInbound) matchVMess(authid [16]byte, now int64) *nativeXrayClient {
	ib.clientMu.RLock()
	defer ib.clientMu.RUnlock()
	for _, c := range ib.clientsByID {
		if c.authIDCipher == nil {
			continue
		}
		var dec [16]byte
		c.authIDCipher.Decrypt(dec[:], authid[:])
		if crc32.ChecksumIEEE(dec[0:12]) != binary.BigEndian.Uint32(dec[12:16]) {
			continue
		}
		t := int64(binary.BigEndian.Uint64(dec[0:8]))
		if t < 0 || absInt64(t-now) > vmessTimeWindowSeconds {
			continue
		}
		return c
	}
	return nil
}

// ---------- request header ----------

type vmessRequest struct {
	bodyIV   [16]byte
	bodyKey  [16]byte
	respV    byte
	option   byte
	security byte
	command  byte
	host     string
	port     uint16
}

// openVMessHeader reads and decrypts the AEAD request header from r, given the
// user's command key and the already-read 16-byte auth ID. r must be positioned
// immediately after the auth ID.
func openVMessHeader(cmdKey [16]byte, authid [16]byte, r io.Reader) ([]byte, error) {
	var lenBlock [18]byte // 2-byte length + 16-byte tag
	if _, err := io.ReadFull(r, lenBlock[:]); err != nil {
		return nil, err
	}
	var connNonce [8]byte
	if _, err := io.ReadFull(r, connNonce[:]); err != nil {
		return nil, err
	}

	aid := string(authid[:])
	cn := string(connNonce[:])

	lenGCM := newAESGCM(vmessKDF16(cmdKey[:], kdfLabelReqHeaderLenKey, aid, cn))
	lenNonce := vmessKDF(cmdKey[:], kdfLabelReqHeaderLenIV, aid, cn)[:12]
	lenPlain, err := lenGCM.Open(nil, lenNonce, lenBlock[:], authid[:])
	if err != nil {
		return nil, fmt.Errorf("vmess: header length decrypt: %w", err)
	}
	headerLen := int(binary.BigEndian.Uint16(lenPlain))
	if headerLen < 38 || headerLen > 512 {
		return nil, fmt.Errorf("vmess: implausible header length %d", headerLen)
	}

	payload := make([]byte, headerLen+16)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	payGCM := newAESGCM(vmessKDF16(cmdKey[:], kdfLabelReqHeaderKey, aid, cn))
	payNonce := vmessKDF(cmdKey[:], kdfLabelReqHeaderIV, aid, cn)[:12]
	header, err := payGCM.Open(nil, payNonce, payload, authid[:])
	if err != nil {
		return nil, fmt.Errorf("vmess: header payload decrypt: %w", err)
	}
	return header, nil
}

// parseVMessHeader parses the decrypted request header plaintext.
func parseVMessHeader(h []byte) (vmessRequest, error) {
	var req vmessRequest
	if len(h) < 40 {
		return req, errors.New("vmess: header too short")
	}
	if h[0] != 1 {
		return req, fmt.Errorf("vmess: unsupported version %d", h[0])
	}
	copy(req.bodyIV[:], h[1:17])
	copy(req.bodyKey[:], h[17:33])
	req.respV = h[33]
	req.option = h[34]
	req.security = h[35] & 0x0f
	paddingLen := int(h[35] >> 4)
	req.command = h[37]
	req.port = binary.BigEndian.Uint16(h[38:40])

	host, next, err := parseVMessAddress(h, 40)
	if err != nil {
		return req, err
	}
	req.host = host

	if next+paddingLen+4 != len(h) {
		return req, fmt.Errorf("vmess: header length mismatch (addr end %d + pad %d + 4 != %d)", next, paddingLen, len(h))
	}

	f := fnv.New32a()
	f.Write(h[:len(h)-4])
	if binary.BigEndian.Uint32(h[len(h)-4:]) != f.Sum32() {
		return req, errors.New("vmess: header checksum mismatch")
	}
	return req, nil
}

func parseVMessAddress(h []byte, off int) (host string, next int, err error) {
	if off >= len(h) {
		return "", 0, io.ErrUnexpectedEOF
	}
	atyp := h[off]
	off++
	switch atyp {
	case atypIPv4:
		if off+4 > len(h) {
			return "", 0, io.ErrUnexpectedEOF
		}
		host = net.IP(h[off : off+4]).String()
		off += 4
	case atypIPv6:
		if off+16 > len(h) {
			return "", 0, io.ErrUnexpectedEOF
		}
		host = net.IP(h[off : off+16]).String()
		off += 16
	case atypDomain:
		if off >= len(h) {
			return "", 0, io.ErrUnexpectedEOF
		}
		l := int(h[off])
		off++
		if off+l > len(h) {
			return "", 0, io.ErrUnexpectedEOF
		}
		host = string(h[off : off+l])
		off += l
	default:
		return "", 0, fmt.Errorf("vmess: unknown address type %d", atyp)
	}
	return host, off, nil
}

// ---------- response header ----------

func writeVMessResponseHeader(w io.Writer, respBodyKey, respBodyIV [16]byte, respV byte) error {
	header := []byte{respV, 0, 0, 0} // V echo, option 0, command 0, command-data-length 0

	lenGCM := newAESGCM(vmessKDF16(respBodyKey[:], kdfLabelRespHeaderLenKey))
	lenNonce := vmessKDF(respBodyIV[:], kdfLabelRespHeaderLenIV)[:12]
	var lenPlain [2]byte
	binary.BigEndian.PutUint16(lenPlain[:], uint16(len(header)))
	lenSealed := lenGCM.Seal(nil, lenNonce, lenPlain[:], nil) // AAD nil

	payGCM := newAESGCM(vmessKDF16(respBodyKey[:], kdfLabelRespHeaderKey))
	payNonce := vmessKDF(respBodyIV[:], kdfLabelRespHeaderIV)[:12]
	paySealed := payGCM.Seal(nil, payNonce, header, nil) // AAD nil

	out := make([]byte, 0, len(lenSealed)+len(paySealed))
	out = append(out, lenSealed...)
	out = append(out, paySealed...)
	_, err := w.Write(out)
	return err
}

// ---------- authenticated-length size parser ----------

// vmessAuthLen encodes/decodes the 2-byte chunk length as an AEAD-sealed field
// (option AuthenticatedLength). It always derives its key from the *request*
// body key/IV, in both directions, per the reference.
type vmessAuthLen struct {
	aead   cipher.AEAD
	count  uint16
	ivTail [10]byte
	nonce  [12]byte
}

func newVMessAuthLen(reqBodyKey, reqBodyIV [16]byte, chacha bool) *vmessAuthLen {
	keyMat := vmessKDF16(reqBodyKey[:], kdfLabelAuthLen)
	var aead cipher.AEAD
	if chacha {
		a, _ := chacha20poly1305.New(vmessChaChaKey(keyMat))
		aead = a
	} else {
		aead = newAESGCM(keyMat)
	}
	al := &vmessAuthLen{aead: aead}
	copy(al.ivTail[:], reqBodyIV[2:12])
	return al
}

func (al *vmessAuthLen) nextNonce() []byte {
	binary.BigEndian.PutUint16(al.nonce[0:2], al.count)
	copy(al.nonce[2:12], al.ivTail[:])
	al.count++
	return al.nonce[:12]
}

func (al *vmessAuthLen) decode(r io.Reader) (int, error) {
	var buf [18]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, err
	}
	plain, err := al.aead.Open(nil, al.nextNonce(), buf[:], nil)
	if err != nil {
		return 0, fmt.Errorf("vmess: auth-len decrypt: %w", err)
	}
	return int(binary.BigEndian.Uint16(plain)) + 16, nil
}

func (al *vmessAuthLen) encode(out *bytes.Buffer, size int) {
	var lenPlain [2]byte
	binary.BigEndian.PutUint16(lenPlain[:], uint16(size-16))
	out.Write(al.aead.Seal(nil, al.nextNonce(), lenPlain[:], nil))
}

// ---------- body chunk reader/writer ----------

const vmessMaxChunk = 64*1024 + 64

type vmessChunkReader struct {
	r         io.Reader
	aead      cipher.AEAD // nil for security "none"
	overhead  int
	ivTail    [10]byte
	count     uint16
	nonce     [12]byte
	shake     sha3.ShakeHash // non-nil when chunk masking is enabled
	authLen   *vmessAuthLen  // non-nil when authenticated length is enabled
	globalPad bool
	leftover  []byte
	eof       bool
}

func (cr *vmessChunkReader) nextNonce() []byte {
	binary.BigEndian.PutUint16(cr.nonce[0:2], cr.count)
	copy(cr.nonce[2:12], cr.ivTail[:])
	cr.count++
	return cr.nonce[:12]
}

func (cr *vmessChunkReader) readChunk() ([]byte, error) {
	// Padding length is always drawn from the SHAKE stream before the size.
	pad := 0
	if cr.shake != nil && cr.globalPad {
		pad = int(shakeNext(cr.shake) % 64)
	}

	var size int
	switch {
	case cr.authLen != nil:
		s, err := cr.authLen.decode(cr.r)
		if err != nil {
			return nil, err
		}
		size = s
	case cr.shake != nil:
		var b [2]byte
		if _, err := io.ReadFull(cr.r, b[:]); err != nil {
			return nil, err
		}
		size = int(shakeNext(cr.shake) ^ binary.BigEndian.Uint16(b[:]))
	default:
		var b [2]byte
		if _, err := io.ReadFull(cr.r, b[:]); err != nil {
			return nil, err
		}
		size = int(binary.BigEndian.Uint16(b[:]))
	}

	// size == overhead + pad means an empty (terminating) chunk.
	if size == cr.overhead+pad {
		return nil, io.EOF
	}
	if size < cr.overhead+pad || size > vmessMaxChunk {
		return nil, fmt.Errorf("vmess: bad chunk size %d", size)
	}

	data := make([]byte, size)
	if _, err := io.ReadFull(cr.r, data); err != nil {
		return nil, err
	}
	sealed := data[:size-pad] // trailing pad bytes are clear-text, discarded
	if cr.aead == nil {
		return sealed, nil
	}
	plain, err := cr.aead.Open(nil, cr.nextNonce(), sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("vmess: body decrypt: %w", err)
	}
	return plain, nil
}

func (cr *vmessChunkReader) Read(p []byte) (int, error) {
	for len(cr.leftover) == 0 {
		if cr.eof {
			return 0, io.EOF
		}
		chunk, err := cr.readChunk()
		if err == io.EOF {
			cr.eof = true
			return 0, io.EOF
		}
		if err != nil {
			return 0, err
		}
		cr.leftover = chunk
	}
	n := copy(p, cr.leftover)
	cr.leftover = cr.leftover[n:]
	return n, nil
}

type vmessChunkWriter struct {
	w         io.Writer
	aead      cipher.AEAD
	overhead  int
	ivTail    [10]byte
	count     uint16
	nonce     [12]byte
	shake     sha3.ShakeHash
	authLen   *vmessAuthLen
	globalPad bool
}

func (cw *vmessChunkWriter) nextNonce() []byte {
	binary.BigEndian.PutUint16(cw.nonce[0:2], cw.count)
	copy(cw.nonce[2:12], cw.ivTail[:])
	cw.count++
	return cw.nonce[:12]
}

func (cw *vmessChunkWriter) writeChunk(p []byte) error {
	var out bytes.Buffer

	pad := 0
	if cw.shake != nil && cw.globalPad {
		pad = int(shakeNext(cw.shake) % 64)
	}
	size := len(p) + cw.overhead + pad

	switch {
	case cw.authLen != nil:
		cw.authLen.encode(&out, size)
	case cw.shake != nil:
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], shakeNext(cw.shake)^uint16(size))
		out.Write(b[:])
	default:
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], uint16(size))
		out.Write(b[:])
	}

	if cw.aead != nil {
		out.Write(cw.aead.Seal(nil, cw.nextNonce(), p, nil))
	} else {
		out.Write(p)
	}
	if pad > 0 {
		padBytes := make([]byte, pad)
		_, _ = rand.Read(padBytes)
		out.Write(padBytes)
	}
	_, err := cw.w.Write(out.Bytes())
	return err
}

// ---------- vmessConn: net.Conn view of a decoded VMess session ----------

type nativeVMessStream interface {
	net.Conn
	ReadPacket() ([]byte, error)
	WritePacket([]byte) error
}

type vmessConn struct {
	net.Conn
	reader           *vmessChunkReader
	writer           *vmessChunkWriter
	terminateOnClose bool
	closeOnce        sync.Once
}

func (c *vmessConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

// ReadPacket returns exactly one decrypted VMess body chunk. UDP-over-VMess uses
// one VMess chunk per UDP datagram, so packet handling must bypass the streamy
// Read method that can merge/split chunks.
func (c *vmessConn) ReadPacket() ([]byte, error) { return c.reader.readChunk() }

func (c *vmessConn) WritePacket(p []byte) error { return c.writer.writeChunk(p) }

func (c *vmessConn) Write(p []byte) (int, error) {
	// Bound each chunk well under the uint16 length field.
	const maxChunk = 16 * 1024
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > maxChunk {
			n = maxChunk
		}
		if err := c.writer.writeChunk(p[:n]); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (c *vmessConn) Close() error {
	c.closeOnce.Do(func() {
		if c.terminateOnClose {
			_ = c.writer.writeChunk(nil) // terminating empty chunk
		}
	})
	return c.Conn.Close()
}

// vmessRawConn is used for VMess security=none when the client did not request
// ChunkStream. Xray's own server returns a raw reader/writer in that exact case;
// treating the following TLS ClientHello/HTTP bytes as a VMess chunk length makes
// real clients authenticate but then pass no data.
type vmessRawConn struct {
	net.Conn
}

func (c *vmessRawConn) ReadPacket() ([]byte, error) {
	buf := make([]byte, 64*1024)
	n, err := c.Conn.Read(buf)
	if n > 0 {
		return buf[:n], nil
	}
	return nil, err
}

func (c *vmessRawConn) WritePacket(p []byte) error {
	_, err := c.Conn.Write(p)
	return err
}

func newVMessConn(stream net.Conn, req vmessRequest, respBodyKey, respBodyIV [16]byte) (nativeVMessStream, error) {
	chunkMask := req.option&vmessOptChunkMasking != 0
	globalPad := req.option&vmessOptGlobalPadding != 0
	authLen := req.option&vmessOptAuthenticatedLength != 0
	chacha := req.security == vmessSecChaCha20Poly1305

	if req.security == vmessSecNone && req.option&vmessOptChunkStream == 0 {
		return &vmessRawConn{Conn: stream}, nil
	}

	var readAEAD, writeAEAD cipher.AEAD
	overhead := 16
	switch req.security {
	case vmessSecAES128GCM:
		readAEAD = newAESGCM(req.bodyKey[:])
		writeAEAD = newAESGCM(respBodyKey[:])
	case vmessSecChaCha20Poly1305:
		ra, _ := chacha20poly1305.New(vmessChaChaKey(req.bodyKey[:]))
		wa, _ := chacha20poly1305.New(vmessChaChaKey(respBodyKey[:]))
		readAEAD, writeAEAD = ra, wa
	case vmessSecNone:
		overhead = 0
	default:
		return nil, fmt.Errorf("vmess: unsupported security %d", req.security)
	}

	cr := &vmessChunkReader{r: stream, aead: readAEAD, overhead: overhead, globalPad: globalPad}
	copy(cr.ivTail[:], req.bodyIV[2:12])
	cw := &vmessChunkWriter{w: stream, aead: writeAEAD, overhead: overhead, globalPad: globalPad}
	copy(cw.ivTail[:], respBodyIV[2:12])

	if chunkMask {
		rs := sha3.NewShake128()
		rs.Write(req.bodyIV[:])
		cr.shake = rs
		ws := sha3.NewShake128()
		ws.Write(respBodyIV[:])
		cw.shake = ws
	}
	if authLen {
		cr.authLen = newVMessAuthLen(req.bodyKey, req.bodyIV, chacha)
		cw.authLen = newVMessAuthLen(req.bodyKey, req.bodyIV, chacha)
	}

	return &vmessConn{Conn: stream, reader: cr, writer: cw, terminateOnClose: req.option&vmessOptChunkStream != 0 || req.security != vmessSecNone}, nil
}

// ---------- handler ----------

func (ib *nativeInbound) handleVMess(stream net.Conn, remote net.Addr) {
	_ = stream.SetReadDeadline(time.Now().Add(30 * time.Second))

	var authid [16]byte
	if _, err := io.ReadFull(stream, authid[:]); err != nil {
		return
	}
	client := ib.matchVMess(authid, time.Now().Unix())
	if client == nil {
		logNativePreAuthRejection("native xray: inbound %q rejected unknown/expired VMess auth id from %s", ib.tag, remote)
		return
	}
	if reason := xrayMgr.nativeClientAccessDenied(client.uuid); reason != "" {
		log.Printf("native xray: inbound %q rejected VMess user %s: %s", ib.tag, client.email, reason)
		return
	}

	header, err := openVMessHeader(client.cmdKey, authid, stream)
	if err != nil {
		log.Printf("native xray: inbound %q VMess header open failed from %s: %v", ib.tag, remote, err)
		return
	}
	req, err := parseVMessHeader(header)
	if err != nil {
		log.Printf("native xray: inbound %q VMess header parse failed from %s: %v", ib.tag, remote, err)
		return
	}
	_ = stream.SetReadDeadline(time.Time{})

	if req.command != vmessCmdTCP && req.command != vmessCmdUDP {
		log.Printf("native xray: inbound %q VMess command %d not supported yet", ib.tag, req.command)
		return
	}
	releaseConnection, quotaState, ok := xrayMgr.acquireNativeClientConnection(client.uuid, client.email, stream)
	if !ok {
		return
	}
	defer releaseConnection()

	respBodyKey := sha256.Sum256(req.bodyKey[:])
	respBodyIV := sha256.Sum256(req.bodyIV[:])
	var rk, riv [16]byte
	copy(rk[:], respBodyKey[:16])
	copy(riv[:], respBodyIV[:16])

	if err := writeVMessResponseHeader(stream, rk, riv, req.respV); err != nil {
		return
	}

	vc, err := newVMessConn(stream, req, rk, riv)
	if err != nil {
		log.Printf("native xray: inbound %q VMess codec: %v", ib.tag, err)
		return
	}

	switch req.command {
	case vmessCmdTCP:
		backend, target, err := ib.nativeDialTCP(req.host, req.port)
		if err != nil {
			log.Printf("native xray: inbound %q VMess TCP dial %s failed: %v", ib.tag, target, err)
			return
		}
		log.Printf("native xray: vmess/tcp user=%s src=%s -> %s (inbound %q)", client.email, backend.LocalAddr(), target, ib.tag)
		nativeTunnel(vc, backend, client.uuid, client.email, quotaState, ib.upLimiter(), ib.downLimiter())
	case vmessCmdUDP:
		backend, target, err := ib.nativeDialUDP(req.host, req.port)
		if err != nil {
			log.Printf("native xray: inbound %q VMess UDP dial %s failed: %v", ib.tag, target, err)
			return
		}
		log.Printf("native xray: vmess/udp user=%s src=%s -> %s (inbound %q)", client.email, backend.LocalAddr(), target, ib.tag)
		nativeVMessUDPTunnel(vc, backend, client.uuid, client.email, quotaState, ib.upLimiter(), ib.downLimiter())
	}
}
