// This package is a local fork of www.bamsoftware.com/git/dnstt.git/turbotunnel
// (upstream v1.20241021.0). The only behavioural change from upstream is that
// RemoteMap's background expiry goroutine is now stoppable via Close(), wired
// through QueuePacketConn.Close(); see remotemap.go and queuepacketconn.go.
// Upstream leaks that goroutine for the process lifetime, which is harmless for
// the upstream one-shot server but leaks one goroutine per DNSTT restart in this
// integration (hot-reload / auto-restart). clientid.go and consts.go are copied
// verbatim.

package turbotunnel

import (
	"crypto/rand"
	"encoding/hex"
)

// ClientID is an abstract identifier that binds together all the communications
// belonging to a single client session, even though those communications may
// arrive from multiple IP addresses or over multiple lower-level connections.
// It plays the same role that an (IP address, port number) tuple plays in a
// net.UDPConn: it's the return address pertaining to a long-lived abstract
// client session. The client attaches its ClientID to each of its
// communications, enabling the server to disambiguate requests among its many
// clients. ClientID implements the net.Addr interface.
type ClientID [8]byte

func NewClientID() ClientID {
	var id ClientID
	_, err := rand.Read(id[:])
	if err != nil {
		panic(err)
	}
	return id
}

func (id ClientID) Network() string { return "clientid" }
func (id ClientID) String() string  { return hex.EncodeToString(id[:]) }
