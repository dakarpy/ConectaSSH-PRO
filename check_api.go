package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"time"
)

// CheckResponse is returned by the public /check endpoint.
type CheckResponse struct {
	Username         string `json:"username"`
	CountConnections int    `json:"count_connections"`
	ExpirationDate   string `json:"expiration_date"`
	ExpirationDays   int    `json:"expiration_days"`
	LimitConnections int    `json:"limit_connections"`
}

// handleCheck is the public user-check API. No authentication required.
// Accepts ?user=<ssh-username> or ?uuid=<xray-uuid> (or both; user takes priority).
// Returns JSON matching CheckResponse.
func handleCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	username := q.Get("user")
	uuid := q.Get("uuid")

	if username == "" && uuid == "" {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"user or uuid parameter required"}`))
		return
	}

	if username != "" {
		checkSSHUser(w, username)
		return
	}
	checkXrayUUID(w, r, uuid)
}

func checkSSHUser(w http.ResponseWriter, username string) {
	u, ok := userMgr.Get(username)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"user not found"}`))
		return
	}

	u.mu.Lock()
	activeConns := len(u.conns) + u.btunConns
	u.ActiveConns = activeConns
	maxConns := u.Cfg.MaxConnections
	expiresAt := u.ExpiresAt
	u.mu.Unlock()

	resp := CheckResponse{
		Username:         username,
		CountConnections: activeConns,
		LimitConnections: maxConns,
	}
	fillExpiry(&resp, expiresAt)
	_ = json.NewEncoder(w).Encode(resp)
}

func checkXrayUUID(w http.ResponseWriter, r *http.Request, uuid string) {
	if statsStore == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"database not configured"}`))
		return
	}

	meta, err := statsStore.GetXrayClientMeta(r.Context(), uuid)
	if err == sql.ErrNoRows {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"uuid not found"}`))
		return
	}
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"database error"}`))
		return
	}

	displayName := meta.Name
	if displayName == "" {
		displayName = meta.UUID
	}

	resp := CheckResponse{
		Username:         displayName,
		CountConnections: 0,
		LimitConnections: meta.MaxConns,
	}
	fillExpiry(&resp, meta.ExpiresAt)
	_ = json.NewEncoder(w).Encode(resp)
}

func fillExpiry(resp *CheckResponse, expiresAt *time.Time) {
	if expiresAt == nil {
		resp.ExpirationDate = "Unlimited"
		resp.ExpirationDays = -1
		return
	}
	resp.ExpirationDate = expiresAt.Local().Format("02/01/2006")
	days := int(time.Until(*expiresAt).Hours() / 24)
	if days < 0 {
		days = 0
	}
	resp.ExpirationDays = days
}
