package main

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
)

const defaultPanelLogFile = "/opt/sshpanel/logs/panel.log"

type systemLogsResponse struct {
	Source string   `json:"source"`
	Path   string   `json:"path,omitempty"`
	Lines  []string `json:"lines"`
}

func handleSystemLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	limit := 300
	if raw := strings.TrimSpace(r.URL.Query().Get("lines")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 2000 {
		limit = 2000
	}

	source := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("source")))
	if source == "" {
		source = "panel"
	}

	resp := systemLogsResponse{Source: source, Lines: []string{}}
	switch source {
	case "dnstt":
		resp.Lines = limitLines(getDNSTTLogLines(), limit)
	case "xray":
		resp.Lines = limitLines(xrayLogBuf.snapshot(), limit)
	default:
		resp.Source = "panel"
		path := panelLogFilePath()
		resp.Path = path
		lines, err := tailTextFile(path, limit)
		if err != nil {
			lines = []string{"unable to read " + path + ": " + err.Error()}
		}
		resp.Lines = lines
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func tailTextFile(path string, limit int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if limit <= 0 {
		limit = 300
	}
	ring := make([]string, limit)
	count := 0
	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		ring[count%limit] = scanner.Text()
		count++
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if count == 0 {
		return []string{}, nil
	}
	outLen := count
	if outLen > limit {
		outLen = limit
	}
	out := make([]string, 0, outLen)
	start := 0
	if count > limit {
		start = count % limit
	}
	for i := 0; i < outLen; i++ {
		out = append(out, ring[(start+i)%limit])
	}
	return out, nil
}

func limitLines(lines []string, limit int) []string {
	if len(lines) == 0 {
		return []string{}
	}
	if limit <= 0 || len(lines) <= limit {
		out := make([]string, len(lines))
		copy(out, lines)
		return out
	}
	out := make([]string, limit)
	copy(out, lines[len(lines)-limit:])
	return out
}
