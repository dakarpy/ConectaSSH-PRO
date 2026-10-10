package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
)

// handleTLSListeners changes only TLS listener entries. It deliberately avoids
// applyFullConfigReload so unrelated protocols are not restarted.
func handleTLSListeners(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		cfg := getGlobalCfg()
		if cfg == nil {
			http.Error(w, "config unavailable", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"tls_forwarders": cfg.TLSForwarders, "domain": tlsDomainFromCert(cfg.TLSForwarders)})
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if globalCfgPath == "" {
		http.Error(w, "config path not set", http.StatusInternalServerError)
		return
	}
	var req struct {
		TLSForwarders []TLSForwarderConfig `json:"tls_forwarders"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128*1024))
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid TLS listener request: "+err.Error(), http.StatusBadRequest)
		return
	}
	seen := map[string]bool{}
	sharedCert, sharedKey := "", ""
	for i := range req.TLSForwarders {
		f := &req.TLSForwarders[i]
		f.Listen = strings.TrimSpace(f.Listen)
		if f.Listen == "" || f.CertFile == "" || f.KeyFile == "" {
			http.Error(w, "each TLS port requires listen, cert_file and key_file", http.StatusBadRequest)
			return
		}
		if seen[f.Listen] {
			http.Error(w, "duplicate TLS listen address: "+f.Listen, http.StatusBadRequest)
			return
		}
		seen[f.Listen] = true
		if i == 0 {
			sharedCert, sharedKey = f.CertFile, f.KeyFile
		} else if f.CertFile != sharedCert || f.KeyFile != sharedKey {
			http.Error(w, "all TLS ports must share the same domain certificate and private key", http.StatusBadRequest)
			return
		}
		if _, err := tls.LoadX509KeyPair(f.CertFile, f.KeyFile); err != nil {
			http.Error(w, fmt.Sprintf("invalid certificate/key for %s: %v", f.Listen, err), http.StatusBadRequest)
			return
		}
		if f.Enabled == nil { // explicit default for new entries
			enabled := true
			f.Enabled = &enabled
		}
	}

	globalCfgMu.Lock()
	defer globalCfgMu.Unlock()
	if globalCfg == nil {
		http.Error(w, "config unavailable", http.StatusServiceUnavailable)
		return
	}
	oldCfg := *globalCfg
	oldCfg.TLSForwarders = append([]TLSForwarderConfig(nil), globalCfg.TLSForwarders...)
	newCfg := *globalCfg
	newCfg.TLSForwarders = req.TLSForwarders
	data, err := json.MarshalIndent(&newCfg, "", "  ")
	if err != nil {
		http.Error(w, "could not encode config", http.StatusInternalServerError)
		return
	}
	if err := writeFileAtomic(globalCfgPath, data, 0o600); err != nil {
		http.Error(w, "could not save TLS configuration: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Keep the global runtime snapshot consistent without touching other services.
	globalCfg = &newCfg
	var errors []string
	if tlsPool == nil {
		errors = append(errors, "TLS listener pool is not initialized")
	} else {
		for _, err := range tlsPool.Sync(newCfg.TLSForwarders) {
			errors = append(errors, err.Error())
		}
	}
	if len(errors) > 0 {
		// Restore previous config and runtime listeners if any requested bind failed.
		oldData, _ := json.MarshalIndent(&oldCfg, "", "  ")
		_ = writeFileAtomic(globalCfgPath, oldData, 0o600)
		globalCfg = &oldCfg
		if tlsPool != nil {
			_ = tlsPool.Sync(oldCfg.TLSForwarders)
		}
		http.Error(w, "TLS change rolled back: "+strings.Join(errors, "; "), http.StatusConflict)
		return
	}
	addrs := make([]string, 0, len(newCfg.TLSForwarders))
	for _, f := range newCfg.TLSForwarders {
		state := f.Enabled == nil || *f.Enabled
		if state {
			addrs = append(addrs, f.Listen)
		}
	}
	sort.Strings(addrs)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "tls_forwarders": newCfg.TLSForwarders, "active_listeners": addrs, "domain": tlsDomainFromCert(newCfg.TLSForwarders)})
}

func tlsDomainFromCert(forwarders []TLSForwarderConfig) string {
	for _, f := range forwarders {
		if f.CertFile == "" {
			continue
		}
		cert, err := tls.LoadX509KeyPair(f.CertFile, f.KeyFile)
		if err != nil || len(cert.Certificate) == 0 {
			continue
		}
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err == nil && len(parsed.DNSNames) > 0 {
			return parsed.DNSNames[0]
		}
		if err == nil {
			return parsed.Subject.CommonName
		}
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

// bindTLSAddress is kept small for focused unit tests of port availability.
func bindTLSAddress(addr string) (net.Listener, error) { return net.Listen("tcp", addr) }
