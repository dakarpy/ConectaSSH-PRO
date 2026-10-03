package main

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSharedXrayPathsRequireExplicitNonRootHTTPTransport(t *testing.T) {
	for _, body := range []string{
		`{"tag":"a","protocol":"vless","port":80,"dragoncoreSharedPort":true,"streamSettings":{"network":"tcp"}}`,
		`{"tag":"a","protocol":"vless","port":80,"dragoncoreSharedPort":true,"streamSettings":{"network":"ws","wsSettings":{"path":"/"}}}`,
		`{"tag":"a","protocol":"vless","port":80,"dragoncoreSharedPort":true,"streamSettings":{"network":"ws","security":"tls","wsSettings":{"path":"/c1"}}}`,
	} {
		if err := validateNativeInboundBindings([]byte(`{"inbounds":[` + body + `]}`)); err == nil {
			t.Fatalf("accepted invalid shared inbound: %s", body)
		}
	}
	valid := []byte(`{"inbounds":[{"tag":"a","protocol":"vless","port":80,"dragoncoreSharedPort":true,"streamSettings":{"network":"ws","wsSettings":{"path":"/c1"}}},{"tag":"b","protocol":"vmess","port":80,"dragoncoreSharedPort":true,"streamSettings":{"network":"xhttp","xhttpSettings":{"path":"/c2"}}}]}`)
	if err := validateNativeInboundBindings(valid); err != nil {
		t.Fatal(err)
	}
	overlap := strings.Replace(string(valid), "/c2", "/c1/nested", 1)
	if err := validateNativeInboundBindings([]byte(overlap)); err == nil {
		t.Fatal("accepted overlapping shared paths")
	}
}

func TestSharedXraySniffPreservesHTTPBytes(t *testing.T) {
	ib := &nativeInbound{tag: "x", transport: "xhttp", path: "/c1", sharedPort: true, xhttpSessions: make(map[string]*nativeXHTTPSession)}
	router, err := newSharedXrayRouter([]*nativeInbound{ib})
	if err != nil {
		t.Fatal(err)
	}
	nativeXray.shared.Store(router)
	defer nativeXray.shared.Store(nil)
	defer router.httpListener.Close()
	request := "OPTIONS /c1/sid HTTP/1.1\r\nHost: example.test\r\n\r\n"
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan bool, 1)
	go func() { _, taken := nativeTakeSharedConn(server, nil); done <- taken }()
	if _, err := io.WriteString(client, request); err != nil {
		t.Fatal(err)
	}
	select {
	case taken := <-done:
		if !taken {
			t.Fatal("shared path not routed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shared sniff stalled")
	}
	select {
	case routed := <-router.httpListener.conns:
		buf := make([]byte, len(request))
		if _, err := io.ReadFull(routed, buf); err != nil {
			t.Fatal(err)
		}
		if string(buf) != request {
			t.Fatalf("routed bytes changed: %q", buf)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("XHTTP connection not queued")
	}
}
