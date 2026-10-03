package main

// Shared native Xray HTTP transports are handed off before the public proxy's
// HTTP-injection cleanup writes its unsolicited SSH response. TLS is terminated
// by the panel listener, so the Xray inbound itself must use security "none".

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type sharedXrayRouter struct {
	ws           map[string]*nativeInbound
	xhttp        *nativeXHTTPListener
	httpListener *sharedXrayListener
	listeners    []net.Listener
}

type sharedXrayListener struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func (l *sharedXrayListener) Accept() (net.Conn, error) {
	select {
	case <-l.done:
		return nil, net.ErrClosed
	case c := <-l.conns:
		return c, nil
	}
}
func (l *sharedXrayListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *sharedXrayListener) Addr() net.Addr { return &net.TCPAddr{} }

func sharedXrayPath(path string) (string, error) {
	if path == "" || path == "/" || !strings.HasPrefix(path, "/") ||
		strings.ContainsAny(path, "?#%\\ \t\r\n") || strings.Contains(path, "//") ||
		strings.Contains(path, "/./") || strings.Contains(path, "/../") ||
		strings.HasSuffix(path, "/.") || strings.HasSuffix(path, "/..") {
		return "", fmt.Errorf("shared Xray path must be a distinct absolute path such as /c1")
	}
	return strings.TrimSuffix(path, "/"), nil
}

func validateSharedXrayInbound(in nativeInboundJSON) error {
	network := strings.ToLower(firstNonEmpty(in.StreamSettings.Network, "tcp"))
	if network != "ws" && network != "websocket" && network != "xhttp" && network != "splithttp" {
		return fmt.Errorf("shared Xray inbound %q requires WebSocket or XHTTP", in.Tag)
	}
	security := strings.ToLower(strings.TrimSpace(in.StreamSettings.Security))
	if security != "" && security != "none" {
		return fmt.Errorf("shared Xray inbound %q must use security none; the ConectaSSH-PRO TLS listener terminates TLS", in.Tag)
	}
	path := in.StreamSettings.WSSettings.Path
	if network == "xhttp" || network == "splithttp" {
		path = mergeNativeXHTTPSettings(in.StreamSettings.XHTTPSettings, in.StreamSettings.SplitHTTPSettings).Path
	}
	if _, err := sharedXrayPath(path); err != nil {
		return fmt.Errorf("inbound %q: %w", in.Tag, err)
	}
	return nil
}

func newSharedXrayRouter(inbounds []*nativeInbound) (*sharedXrayRouter, error) {
	r := &sharedXrayRouter{ws: make(map[string]*nativeInbound)}
	var httpInbounds []*nativeInbound
	paths := map[string]string{}
	for _, ib := range inbounds {
		if !ib.sharedPort {
			continue
		}
		path, err := sharedXrayPath(ib.path)
		if err != nil {
			return nil, fmt.Errorf("inbound %q: %w", ib.tag, err)
		}
		for prior, tag := range paths {
			if path == prior || strings.HasPrefix(path, prior+"/") || strings.HasPrefix(prior, path+"/") {
				return nil, fmt.Errorf("shared Xray paths %s (%s) and %s (%s) overlap", prior, tag, path, ib.tag)
			}
		}
		paths[path] = ib.tag
		if ib.isXHTTP() {
			httpInbounds = append(httpInbounds, ib)
		} else {
			r.ws[path] = ib
		}
	}
	if len(paths) == 0 {
		return nil, nil
	}
	if len(httpInbounds) > 0 {
		group, err := newNativeXHTTPListener("ConectaSSH-PRO public ports", httpInbounds)
		if err != nil {
			return nil, err
		}
		r.xhttp = group
		r.httpListener = &sharedXrayListener{conns: make(chan net.Conn, 128), done: make(chan struct{})}
		r.listeners = []net.Listener{r.httpListener}
	}
	return r, nil
}

func nativeSharedEnabled() bool { return nativeXray.shared.Load() != nil }

func (r *sharedXrayRouter) takeHTTP(conn net.Conn, reader *bufio.Reader) {
	select {
	case <-r.httpListener.done:
		_ = conn.Close()
	case r.httpListener.conns <- &bufferedConn{Conn: conn, r: reader}:
	default:
		_ = conn.Close()
	}
}

// nativeTakeSharedConn only runs before the public SSH proxy writes a response,
// or after the panel TLS handshake. Peek leaves every byte intact for the
// Xray transport and for normal SSH/injection clients on a negative match.
func nativeTakeSharedConn(conn net.Conn, reader *bufio.Reader) (*bufio.Reader, bool) {
	router := nativeXray.shared.Load()
	if router == nil {
		return reader, false
	}
	if reader == nil {
		reader = bufio.NewReaderSize(conn, 16*1024)
	}
	// SSH may wait for the server banner. Bound the first-byte wait so adding
	// Xray sharing does not stall every ordinary SSH connection for three seconds.
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	defer conn.SetReadDeadline(time.Time{})
	first, err := reader.Peek(1)
	if err != nil || len(first) == 0 || (first[0] != 'G' && first[0] != 'P' && first[0] != 'O' && first[0] != 'D') {
		return reader, false
	}
	_ = conn.SetReadDeadline(time.Now().Add(tunnelSniffTimeout))
	if first[0] == 'P' && router.xhttp != nil {
		prefix, err := reader.Peek(3)
		if err == nil && string(prefix) == "PRI" {
			if preface, err := reader.Peek(len("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err == nil &&
				string(preface) == "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
				router.takeHTTP(conn, reader)
				return reader, true
			}
		}
	}
	// Require a complete bounded HTTP header before trusting a path. An SSH
	// payload that happens to start with 'G' must still fall through untouched.
	var header []byte
	for n := 4; n <= 16*1024; n++ {
		peek, e := reader.Peek(n)
		if len(peek) == n && bytes.Equal(peek[n-4:], []byte("\r\n\r\n")) {
			header = peek
			break
		}
		if e != nil {
			return reader, false
		}
	}
	if len(header) == 0 {
		return reader, false
	}
	lineEnd := bytes.Index(header, []byte("\r\n"))
	if lineEnd < 0 {
		return reader, false
	}
	parts := strings.SplitN(string(header[:lineEnd]), " ", 3)
	if len(parts) != 3 || !strings.HasPrefix(parts[2], "HTTP/1.") {
		return reader, false
	}
	method := parts[0]
	if method != "GET" && method != "POST" && method != "OPTIONS" && method != "HEAD" {
		return reader, false
	}
	path := strings.SplitN(parts[1], "?", 2)[0]
	path = strings.TrimSuffix(path, "/")
	if ib := router.ws[path]; ib != nil && method == "GET" &&
		bytes.Contains(bytes.ToLower(header), []byte("upgrade: websocket")) {
		counted, ok := waitWrapTrackedNativeTransportConn(&bufferedConn{Conn: conn, r: reader})
		if !ok {
			return reader, true
		}
		xrayGo("native xray shared WebSocket", func() { ib.serve(counted) })
		return reader, true
	}
	if router.xhttp != nil {
		for _, ib := range router.xhttp.inbounds {
			if _, ok := ib.matchXHTTPPath(path); !ok {
				continue
			}
			router.takeHTTP(conn, reader)
			return reader, true
		}
	}
	return reader, false
}
