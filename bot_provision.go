package main

// bot_provision.go — bridges the bot to the panel's account creation.
// SSH: Store.UpsertUser. Xray: xrayMgr.AddXrayClient + UpsertXrayClientMeta.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ---------- credential generation ----------

const credAlphabet = "abcdefghijkmnpqrstuvwxyz23456789"

func randString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// extremely unlikely; fall back to a fixed-length timestamp-free filler
		for i := range b {
			b[i] = credAlphabet[0]
		}
		return string(b)
	}
	for i := range b {
		b[i] = credAlphabet[int(b[i])%len(credAlphabet)]
	}
	return string(b)
}

func genUsername(prefix string) string {
	if prefix == "" {
		prefix = "ssh"
	}
	return prefix + randString(6)
}

func genPassword() string { return randString(10) }

func uuidV4() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// ---------- SSH ----------

func createSSHUser(ctx context.Context, store *Store, username, password string, expiresAt time.Time, maxConns, upMbps, downMbps int, owner string) error {
	cfg := UserConfig{
		Username:       username,
		Password:       password,
		MaxConnections: maxConns,
		ExpiresAt:      expiresAt.UTC().Format(time.RFC3339),
		LimitMbpsUp:    upMbps,
		LimitMbpsDown:  downMbps,
		OwnerUsername:  owner,
	}
	if err := store.UpsertUser(ctx, cfg); err != nil {
		return err
	}
	reloadUsersFromDB(ctx, store)
	return nil
}

// renewSSHUser extends an existing SSH account's expiry, preserving credentials.
func renewSSHUser(ctx context.Context, store *Store, username string, newExpiry time.Time) error {
	u, ok := userMgr.Get(username)
	if !ok {
		return fmt.Errorf("conta SSH %q não encontrada", username)
	}
	cfg := u.Cfg
	cfg.ExpiresAt = newExpiry.UTC().Format(time.RFC3339)
	if err := store.UpsertUser(ctx, cfg); err != nil {
		return err
	}
	reloadUsersFromDB(ctx, store)
	return nil
}

// ---------- Xray ----------

func createXrayClient(ctx context.Context, store *Store, inboundTag, protocol string, expiresAt time.Time, maxConns int, owner, publicHost string) (uuid, link string, err error) {
	if inboundTag == "" {
		return "", "", fmt.Errorf("plano Xray sem inbound configurado")
	}
	uuid = uuidV4()
	email := "bot-" + uuid[:8]
	if err = xrayMgr.AddXrayClient(inboundTag, uuid, email); err != nil {
		return "", "", err
	}
	exp := expiresAt
	meta := XrayClientMeta{
		UUID:          uuid,
		Name:          email,
		Email:         email,
		InboundTag:    inboundTag,
		OwnerUsername: owner,
		MaxConns:      maxConns,
		ExpiresAt:     &exp,
	}
	if e := store.UpsertXrayClientMeta(ctx, meta); e != nil {
		// The client is already live in Xray; a metadata failure must not
		// abort delivery. Log and continue.
		log.Printf("[bot] xray meta save for %s: %v", uuid, e)
	}
	xrayMgr.restartIfExternalRunning()
	link = buildXrayLink(inboundTag, protocol, uuid, publicHost, email)
	return uuid, link, nil
}

func renewXrayClient(ctx context.Context, store *Store, uuid string, newExpiry time.Time) error {
	meta, err := store.GetXrayClientMeta(ctx, uuid)
	if err != nil {
		return fmt.Errorf("cliente Xray não encontrado: %w", err)
	}
	exp := newExpiry
	meta.ExpiresAt = &exp
	return store.UpsertXrayClientMeta(ctx, *meta)
}

// ---------- Xray connection link ----------

type xrayInboundDetail struct {
	Protocol    string
	Port        int
	Network     string
	Security    string
	Path        string
	Host        string
	SNI         string
	ServiceName string
}

// inboundDetail reads streamSettings for an inbound from the raw Xray config.
func (m *XrayManager) inboundDetail(tag string) (*xrayInboundDetail, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, err := m.readConfigLocked()
	if err != nil {
		return nil, err
	}
	var cfg struct {
		Inbounds []json.RawMessage `json:"inbounds"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	for _, raw := range cfg.Inbounds {
		var ib struct {
			Tag            string                 `json:"tag"`
			Protocol       string                 `json:"protocol"`
			Port           json.RawMessage        `json:"port"`
			SharedPort     bool                   `json:"dragoncoreSharedPort"`
			StreamSettings map[string]interface{} `json:"streamSettings"`
		}
		if err := json.Unmarshal(raw, &ib); err != nil {
			continue
		}
		if ib.Tag != tag {
			continue
		}
		d := &xrayInboundDetail{Protocol: strings.ToLower(ib.Protocol)}
		var pnum int
		if json.Unmarshal(ib.Port, &pnum) == nil {
			d.Port = pnum
		} else {
			var pstr string
			if json.Unmarshal(ib.Port, &pstr) == nil {
				d.Port, _ = strconv.Atoi(pstr)
			}
		}
		if ss := ib.StreamSettings; ss != nil {
			d.Network, _ = ss["network"].(string)
			d.Security, _ = ss["security"].(string)
			d.Path, d.Host, d.ServiceName = extractStreamParams(ss, d.Network)
			if tls, ok := ss["tlsSettings"].(map[string]interface{}); ok {
				d.SNI, _ = tls["serverName"].(string)
			}
			if rl, ok := ss["realitySettings"].(map[string]interface{}); ok {
				if sn, _ := rl["serverNames"].([]interface{}); len(sn) > 0 {
					d.SNI, _ = sn[0].(string)
				}
			}
		}
		if ib.SharedPort {
			// The public listener terminates TLS before the native emulator.
			// Connection links describe the client-facing socket instead of the
			// internal streamSettings security (which must remain "none").
			if panel := getGlobalCfg(); panel != nil {
				if len(panel.TLSForwarders) > 0 {
					selected := panel.TLSForwarders[0].Listen
					for _, fwd := range panel.TLSForwarders {
						if strings.HasSuffix(fwd.Listen, ":443") {
							selected = fwd.Listen
							break
						}
					}
					if _, port, err := net.SplitHostPort(selected); err == nil {
						if value, err := strconv.Atoi(port); err == nil {
							d.Port = value
							d.Security = "tls"
						}
					}
				} else if _, port, err := net.SplitHostPort(panel.Listen); err == nil {
					if value, err := strconv.Atoi(port); err == nil {
						d.Port = value
						d.Security = "none"
					}
				}
			}
		}
		return d, nil
	}
	return nil, fmt.Errorf("inbound %q não encontrado", tag)
}

func extractStreamParams(ss map[string]interface{}, network string) (path, host, serviceName string) {
	get := func(key, field string) string {
		if sub, ok := ss[key].(map[string]interface{}); ok {
			v, _ := sub[field].(string)
			return v
		}
		return ""
	}
	switch network {
	case "ws":
		return get("wsSettings", "path"), get("wsSettings", "host"), ""
	case "xhttp":
		return get("xhttpSettings", "path"), get("xhttpSettings", "host"), ""
	case "httpupgrade":
		return get("httpupgradeSettings", "path"), get("httpupgradeSettings", "host"), ""
	case "grpc":
		return "", "", get("grpcSettings", "serviceName")
	case "http", "h2":
		return get("httpSettings", "path"), get("httpSettings", "host"), ""
	}
	return "", "", ""
}

// buildXrayLink assembles a shareable connection URI. Best-effort: if the config
// can't be read it still returns a minimal link with host/port/uuid.
func buildXrayLink(inboundTag, protocol, uuid, publicHost, label string) string {
	d, err := xrayMgr.inboundDetail(inboundTag)
	if err != nil || d == nil {
		if protocol == "" {
			protocol = "vless"
		}
		return fmt.Sprintf("%s://%s@%s#%s", protocol, uuid, publicHost, url.QueryEscape(label))
	}
	if protocol == "" {
		protocol = d.Protocol
	}
	host := publicHost
	if host == "" {
		host = d.SNI
	}
	addr := fmt.Sprintf("%s:%d", host, d.Port)

	q := url.Values{}
	if d.Network != "" {
		q.Set("type", d.Network)
	}
	if d.Security != "" {
		q.Set("security", d.Security)
	}
	if d.Path != "" {
		q.Set("path", d.Path)
	}
	if d.Host != "" {
		q.Set("host", d.Host)
	}
	if d.SNI != "" {
		q.Set("sni", d.SNI)
	}
	if d.ServiceName != "" {
		q.Set("serviceName", d.ServiceName)
	}

	switch protocol {
	case "vmess":
		conf := map[string]interface{}{
			"v": "2", "ps": label, "add": host, "port": strconv.Itoa(d.Port),
			"id": uuid, "aid": "0", "scy": "auto", "net": d.Network,
			"type": "none", "host": d.Host, "path": d.Path, "tls": d.Security, "sni": d.SNI,
		}
		b, _ := json.Marshal(conf)
		return "vmess://" + base64.StdEncoding.EncodeToString(b)
	default: // vless, trojan
		return fmt.Sprintf("%s://%s@%s?%s#%s", protocol, uuid, addr, q.Encode(), url.QueryEscape(label))
	}
}
