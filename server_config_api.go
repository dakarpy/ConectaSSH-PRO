package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"sync"
)

// Note: applyFullConfigReload is defined in hotreload.go

// ---------- Global config holder ----------

var (
	globalCfgMu   sync.RWMutex
	globalCfg     *Config
	globalCfgPath string // set in main() from the -config flag

	bannerMu          sync.RWMutex
	currentBannerText string
	bannerEnabledMu   sync.RWMutex
	bannerEnabled     = true
)

func setGlobalCfg(c *Config) {
	globalCfgMu.Lock()
	globalCfg = c
	globalCfgMu.Unlock()
}

func getGlobalCfg() *Config {
	globalCfgMu.RLock()
	defer globalCfgMu.RUnlock()
	return globalCfg
}

func setBannerText(s string) {
	bannerMu.Lock()
	currentBannerText = s
	bannerMu.Unlock()
}

func getBannerText() string {
	bannerMu.RLock()
	defer bannerMu.RUnlock()
	return currentBannerText
}

func setBannerEnabled(enabled bool) {
	bannerEnabledMu.Lock()
	bannerEnabled = enabled
	bannerEnabledMu.Unlock()
}

func getBannerEnabled() bool {
	bannerEnabledMu.RLock()
	defer bannerEnabledMu.RUnlock()
	return bannerEnabled
}

// ---------- HTTP handler ----------

// handleServerConfig dispatches GET (read) and POST (write) for /api/server/config.
func handleServerConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		serverConfigGet(w, r)
	case http.MethodPost:
		serverConfigPost(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func serverConfigGet(w http.ResponseWriter, _ *http.Request) {
	if globalCfgPath == "" {
		http.Error(w, "config path not set", http.StatusInternalServerError)
		return
	}
	data, err := os.ReadFile(globalCfgPath)
	if err != nil {
		http.Error(w, "failed to read config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}

func serverConfigPost(w http.ResponseWriter, r *http.Request) {
	if globalCfgPath == "" {
		http.Error(w, "config path not set", http.StatusInternalServerError)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 512*1024+1))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	if len(body) > 512*1024 {
		http.Error(w, "config exceeds 512 KiB", http.StatusRequestEntityTooLarge)
		return
	}
	// Keep track of optional field presence separately from its value. This
	// protects a newly-added setting from being reset by a stale cached panel
	// bundle that does not know how to send the field yet. For the service
	// blocks the distinction matters twice over: a missing key must keep the
	// running service, while an explicit null is the panel disabling it.
	var fieldPresence struct {
		PAMAuthEnabled            *bool `json:"pam_auth_enabled"`
		AutoMenu                  *bool `json:"auto_menu"`
		SSHConnectionLimitEnabled *bool `json:"ssh_connection_limit_enabled"`
	}
	if err := json.Unmarshal(body, &fieldPresence); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	// json.Unmarshal into *json.RawMessage cannot distinguish a missing key
	// from an explicit JSON null: both produce nil. Service blocks use null
	// as the deliberate "disable" value, so track key presence separately.
	var serviceFieldPresence map[string]json.RawMessage
	if err := json.Unmarshal(body, &serviceFieldPresence); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	var newCfg Config
	if err := json.Unmarshal(body, &newCfg); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if newCfg.Listen == "" {
		http.Error(w, "listen address required", http.StatusBadRequest)
		return
	}
	if newCfg.Xray != nil {
		newCfg.Xray.NormalizeDefaults()
	}

	// Preserve file-based users array (not editable through the UI).
	globalCfgMu.RLock()
	if globalCfg != nil {
		newCfg.Users = globalCfg.Users
		if fieldPresence.PAMAuthEnabled == nil {
			newCfg.PAMAuthEnabled = globalCfg.PAMAuthEnabled
		}
		if fieldPresence.AutoMenu == nil {
			newCfg.AutoMenu = globalCfg.AutoMenu
		}
		if fieldPresence.SSHConnectionLimitEnabled == nil {
			newCfg.SSHConnectionLimitEnabled = globalCfg.SSHConnectionLimitEnabled
		}
		if _, present := serviceFieldPresence["bhttp"]; !present {
			newCfg.BHTTP = globalCfg.BHTTP
		}
		if _, present := serviceFieldPresence["btun"]; !present {
			newCfg.BTUN = globalCfg.BTUN
		}
		if _, present := serviceFieldPresence["hcr"]; !present {
			newCfg.HCR = globalCfg.HCR
		}
	}
	globalCfgMu.RUnlock()

	portWarnings := normalizeRuntimePorts(&newCfg)

	out, err := json.MarshalIndent(newCfg, "", "  ")
	if err != nil {
		http.Error(w, "marshal error", http.StatusInternalServerError)
		return
	}
	if err := writeFileAtomic(globalCfgPath, out, 0o600); err != nil {
		http.Error(w, "failed to write config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Apply all changes live and return health checks to the panel.
	report := applyFullConfigReload(&newCfg)
	if len(portWarnings) > 0 {
		report.Warnings = append(portWarnings, report.Warnings...)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(report)
}
