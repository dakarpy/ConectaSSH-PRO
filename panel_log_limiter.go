package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultPanelLogMaxBytes   int64 = 1 * 1024 * 1024
	defaultPanelLogCheckEvery       = 10 * time.Second
)

type panelLogResetResponse struct {
	OK       bool   `json:"ok"`
	Path     string `json:"path"`
	MaxBytes int64  `json:"max_bytes"`
}

func panelLogFilePath() string {
	path := strings.TrimSpace(os.Getenv("PANEL_LOG_FILE"))
	if path == "" {
		path = defaultPanelLogFile
	}
	return path
}

func panelLogMaxBytes() int64 {
	raw := strings.TrimSpace(os.Getenv("PANEL_LOG_MAX_BYTES"))
	if raw == "" {
		return defaultPanelLogMaxBytes
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n <= 0 {
		return defaultPanelLogMaxBytes
	}
	// Do not allow a tiny limit that would cause continuous truncation.
	if n < 64*1024 {
		return 64 * 1024
	}
	return n
}

func startPanelLogLimiter() {
	path := panelLogFilePath()
	maxBytes := panelLogMaxBytes()
	if path == "" || maxBytes <= 0 {
		return
	}
	go func() {
		_ = enforcePanelLogLimit(path, maxBytes)
		ticker := time.NewTicker(defaultPanelLogCheckEvery)
		defer ticker.Stop()
		for range ticker.C {
			_ = enforcePanelLogLimit(path, maxBytes)
		}
	}()
}

func enforcePanelLogLimit(path string, maxBytes int64) error {
	st, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if st.Size() <= maxBytes {
		return nil
	}
	return truncatePanelLog(path, maxBytes, "automatic 1 MiB log limit")
}

func truncatePanelLog(path string, maxBytes int64, reason string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s sshpanel: panel log cleaned (%s, max=%d bytes)\n", time.Now().Format(time.RFC3339), reason, maxBytes)
	return err
}

func handleSystemLogsReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	path := panelLogFilePath()
	maxBytes := panelLogMaxBytes()
	if err := truncatePanelLog(path, maxBytes, "manual clean from admin panel"); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(panelLogResetResponse{OK: true, Path: path, MaxBytes: maxBytes})
}
