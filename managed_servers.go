package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const managedCredentialPrefix = "enc:v1:"

func sealManagedCredential(plain string) (string, error) {
	return sealCredential(managedCredentialPrefix, plain)
}

func openManagedCredential(stored string) (string, error) {
	return openCredential(managedCredentialPrefix, stored)
}

func managedServerHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

type ManagedServer struct {
	ID            int
	Name          string
	BaseURL       string
	AdminUsername string
	AdminKey      string
	EnableSSH     bool
	EnableXray    bool
	IsActive      bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type ManagedServerDTO struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	BaseURL       string    `json:"base_url"`
	AdminUsername string    `json:"admin_username,omitempty"`
	EnableSSH     bool      `json:"enable_ssh"`
	EnableXray    bool      `json:"enable_xray"`
	IsActive      bool      `json:"is_active"`
	IsLocal       bool      `json:"is_local"`
	CreatedAt     time.Time `json:"created_at,omitempty"`
	UpdatedAt     time.Time `json:"updated_at,omitempty"`
}

type ManagedServerPayload struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	BaseURL       string `json:"base_url"`
	AdminUsername string `json:"admin_username"`
	AdminKey      string `json:"admin_key"`
	EnableSSH     bool   `json:"enable_ssh"`
	EnableXray    bool   `json:"enable_xray"`
	IsActive      bool   `json:"is_active"`
}

func (s *Store) EnsureManagedServersSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS managed_servers (
			id             SERIAL PRIMARY KEY,
			name           TEXT NOT NULL,
			base_url       TEXT NOT NULL UNIQUE,
			admin_username TEXT NOT NULL DEFAULT 'admin',
			admin_key      TEXT NOT NULL DEFAULT '',
			enable_ssh     BOOLEAN NOT NULL DEFAULT TRUE,
			enable_xray    BOOLEAN NOT NULL DEFAULT TRUE,
			is_active      BOOLEAN NOT NULL DEFAULT TRUE,
			created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`)
	if err != nil {
		return err
	}
	return s.migrateManagedServerCredentials(ctx)
}

func (s *Store) migrateManagedServerCredentials(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT id, admin_key FROM managed_servers WHERE admin_key <> '' AND admin_key NOT LIKE 'enc:v1:%'`)
	if err != nil {
		return err
	}
	type legacyCredential struct {
		id  int
		key string
	}
	var legacy []legacyCredential
	for rows.Next() {
		var item legacyCredential
		if err := rows.Scan(&item.id, &item.key); err != nil {
			rows.Close()
			return err
		}
		legacy = append(legacy, item)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, item := range legacy {
		sealed, err := sealManagedCredential(item.key)
		if err != nil {
			return fmt.Errorf("encrypt managed server credential %d: %w", item.id, err)
		}
		if _, err := s.db.ExecContext(ctx, `UPDATE managed_servers SET admin_key=$2 WHERE id=$1`, item.id, sealed); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ListManagedServers(ctx context.Context) ([]*ManagedServer, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, base_url, admin_username, admin_key, enable_ssh, enable_xray, is_active, created_at, updated_at
		FROM managed_servers ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ManagedServer
	for rows.Next() {
		ms := &ManagedServer{}
		if err := rows.Scan(&ms.ID, &ms.Name, &ms.BaseURL, &ms.AdminUsername, &ms.AdminKey, &ms.EnableSSH, &ms.EnableXray, &ms.IsActive, &ms.CreatedAt, &ms.UpdatedAt); err != nil {
			return nil, err
		}
		plainKey, err := openManagedCredential(ms.AdminKey)
		if err != nil {
			return nil, err
		}
		ms.AdminKey = plainKey
		out = append(out, ms)
	}
	return out, rows.Err()
}

func (s *Store) GetManagedServer(ctx context.Context, id int) (*ManagedServer, error) {
	ms := &ManagedServer{}
	err := s.db.QueryRowContext(ctx, `
		SELECT id, name, base_url, admin_username, admin_key, enable_ssh, enable_xray, is_active, created_at, updated_at
		FROM managed_servers WHERE id=$1`, id).
		Scan(&ms.ID, &ms.Name, &ms.BaseURL, &ms.AdminUsername, &ms.AdminKey, &ms.EnableSSH, &ms.EnableXray, &ms.IsActive, &ms.CreatedAt, &ms.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	plainKey, err := openManagedCredential(ms.AdminKey)
	if err != nil {
		return nil, err
	}
	ms.AdminKey = plainKey
	return ms, nil
}

func (s *Store) UpsertManagedServer(ctx context.Context, p ManagedServerPayload) (*ManagedServer, error) {
	name := strings.TrimSpace(p.Name)
	baseURL, baseURLErr := validateManagedServerBaseURL(p.BaseURL)
	adminUsername := strings.TrimSpace(p.AdminUsername)
	if adminUsername == "" {
		adminUsername = "admin"
	}
	if name == "" {
		return nil, fmt.Errorf("server name required")
	}
	if len(name) > 120 || strings.IndexFunc(name, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return nil, fmt.Errorf("invalid server name")
	}
	if len(adminUsername) > 128 || strings.IndexFunc(adminUsername, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return nil, fmt.Errorf("invalid admin username")
	}
	if len(p.AdminKey) > 4096 || strings.IndexFunc(p.AdminKey, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return nil, fmt.Errorf("invalid admin credential")
	}
	if baseURLErr != nil {
		return nil, baseURLErr
	}
	if p.ID != "" && p.ID != "local" {
		id, err := strconv.Atoi(p.ID)
		if err != nil || id <= 0 {
			return nil, fmt.Errorf("invalid server id")
		}
		if strings.TrimSpace(p.AdminKey) == "" {
			_, err = s.db.ExecContext(ctx, `
				UPDATE managed_servers
				SET name=$2, base_url=$3, admin_username=$4, enable_ssh=$5, enable_xray=$6, is_active=$7, updated_at=NOW()
				WHERE id=$1`, id, name, baseURL, adminUsername, p.EnableSSH, p.EnableXray, p.IsActive)
		} else {
			sealedKey, sealErr := sealManagedCredential(p.AdminKey)
			if sealErr != nil {
				return nil, fmt.Errorf("encrypt admin credential: %w", sealErr)
			}
			_, err = s.db.ExecContext(ctx, `
				UPDATE managed_servers
				SET name=$2, base_url=$3, admin_username=$4, admin_key=$5, enable_ssh=$6, enable_xray=$7, is_active=$8, updated_at=NOW()
				WHERE id=$1`, id, name, baseURL, adminUsername, sealedKey, p.EnableSSH, p.EnableXray, p.IsActive)
		}
		if err != nil {
			return nil, err
		}
		return s.GetManagedServer(ctx, id)
	}
	if strings.TrimSpace(p.AdminKey) == "" {
		return nil, fmt.Errorf("admin key/password required")
	}
	sealedKey, err := sealManagedCredential(p.AdminKey)
	if err != nil {
		return nil, fmt.Errorf("encrypt admin credential: %w", err)
	}
	var id int
	err = s.db.QueryRowContext(ctx, `
		INSERT INTO managed_servers (name, base_url, admin_username, admin_key, enable_ssh, enable_xray, is_active)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (base_url) DO UPDATE SET
			name=EXCLUDED.name,
			admin_username=EXCLUDED.admin_username,
			admin_key=EXCLUDED.admin_key,
			enable_ssh=EXCLUDED.enable_ssh,
			enable_xray=EXCLUDED.enable_xray,
			is_active=EXCLUDED.is_active,
			updated_at=NOW()
		RETURNING id`, name, baseURL, adminUsername, sealedKey, p.EnableSSH, p.EnableXray, p.IsActive).Scan(&id)
	if err != nil {
		return nil, err
	}
	return s.GetManagedServer(ctx, id)
}

func (s *Store) DeleteManagedServer(ctx context.Context, id int) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM managed_servers WHERE id=$1`, id)
	return err
}

func managedServerToDTO(ms *ManagedServer) ManagedServerDTO {
	return ManagedServerDTO{
		ID:            strconv.Itoa(ms.ID),
		Name:          ms.Name,
		BaseURL:       ms.BaseURL,
		AdminUsername: ms.AdminUsername,
		EnableSSH:     ms.EnableSSH,
		EnableXray:    ms.EnableXray,
		IsActive:      ms.IsActive,
		CreatedAt:     ms.CreatedAt,
		UpdatedAt:     ms.UpdatedAt,
	}
}

func localManagedServerDTO() ManagedServerDTO {
	cfg := getGlobalCfg()
	xrayEnabled := cfg != nil && cfg.Xray != nil && cfg.Xray.Enabled
	return ManagedServerDTO{
		ID:         "local",
		Name:       "Master node",
		BaseURL:    "local",
		EnableSSH:  true,
		EnableXray: xrayEnabled,
		IsActive:   true,
		IsLocal:    true,
	}
}

func normalizeManagedServerBaseURL(raw string) string {
	normalized, _ := validateManagedServerBaseURL(raw)
	return normalized
}

func validateManagedServerBaseURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("base url required")
	}
	lowerRaw := strings.ToLower(raw)
	if !strings.HasPrefix(lowerRaw, "http://") && !strings.HasPrefix(lowerRaw, "https://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid base url")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("base url must use http or https")
	}
	if u.User != nil {
		return "", fmt.Errorf("base url must not contain credentials")
	}
	if u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("base url must not contain a path")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && (ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()) {
		return "", fmt.Errorf("base url uses a forbidden address")
	}
	u.Path = ""
	u.RawQuery = ""
	u.Fragment = ""
	return strings.TrimRight(u.String(), "/"), nil
}

func requestedServerID(r *http.Request) string {
	id := strings.TrimSpace(r.URL.Query().Get("server_id"))
	if id == "" {
		id = strings.TrimSpace(r.URL.Query().Get("server"))
	}
	return id
}

func managedServerFromID(ctx context.Context, store *Store, id string) (*ManagedServer, bool, error) {
	id = strings.TrimSpace(id)
	if id == "" || id == "local" || id == "0" {
		return nil, false, nil
	}
	if store == nil {
		return nil, false, fmt.Errorf("database not configured")
	}
	n, err := strconv.Atoi(id)
	if err != nil || n <= 0 {
		return nil, false, fmt.Errorf("invalid server id")
	}
	ms, err := store.GetManagedServer(ctx, n)
	if err != nil {
		return nil, false, err
	}
	if ms == nil {
		return nil, false, fmt.Errorf("server not found")
	}
	if !ms.IsActive {
		return nil, false, fmt.Errorf("server is disabled")
	}
	return ms, true, nil
}

func remoteLoginToken(ctx context.Context, ms *ManagedServer) (string, error) {
	body, _ := json.Marshal(map[string]string{"username": ms.AdminUsername, "password": ms.AdminKey})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ms.BaseURL+"/api/auth/login", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	client := managedServerHTTPClient(15 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("remote login failed: %s", strings.TrimSpace(string(data)))
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(data, &out); err != nil || out.Token == "" {
		return "", fmt.Errorf("remote login returned no token")
	}
	return out.Token, nil
}

func proxyManagedServer(ctx context.Context, ms *ManagedServer, method, path string, body []byte, contentType string) (int, []byte, string, error) {
	token, err := remoteLoginToken(ctx, ms)
	if err != nil {
		return 0, nil, "", err
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	req, err := http.NewRequestWithContext(ctx, method, ms.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, "", err
	}
	if contentType == "" {
		contentType = "application/json"
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-Session-Token", token)
	client := managedServerHTTPClient(30 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	return resp.StatusCode, data, resp.Header.Get("Content-Type"), nil
}

func handleManagedProxyOrLocal(store *Store, local http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if proxyManagedServerFromRequest(w, r, store, "", nil, "") {
			return
		}
		local(w, r)
	}
}

func writeProxyResponse(w http.ResponseWriter, status int, body []byte, contentType string) {
	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	if status == 0 {
		status = http.StatusBadGateway
	}
	w.WriteHeader(status)
	if len(body) > 0 {
		_, _ = w.Write(body)
	}
}

func proxyManagedServerFromRequest(w http.ResponseWriter, r *http.Request, store *Store, remotePath string, body []byte, filterOwner string) bool {
	ms, remote, err := managedServerFromID(r.Context(), store, requestedServerID(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return true
	}
	if !remote {
		return false
	}
	if remotePath == "" {
		remotePath = r.URL.Path
		if r.URL.RawQuery != "" {
			q := r.URL.Query()
			q.Del("server_id")
			q.Del("server")
			if enc := q.Encode(); enc != "" {
				remotePath += "?" + enc
			}
		}
	}
	if body == nil && r.Body != nil && r.Method != http.MethodGet {
		body, _ = io.ReadAll(io.LimitReader(r.Body, 2*1024*1024))
	}
	status, data, ct, err := proxyManagedServer(r.Context(), ms, r.Method, remotePath, body, r.Header.Get("Content-Type"))
	if err != nil {
		http.Error(w, "remote server error: "+err.Error(), http.StatusBadGateway)
		return true
	}
	if status >= 200 && status < 300 && filterOwner != "" && strings.Contains(ct, "json") {
		if filtered, ok := filterRemoteOwnerJSON(remotePath, data, filterOwner); ok {
			data = filtered
		}
	}
	writeProxyResponse(w, status, data, ct)
	return true
}

func filterRemoteOwnerJSON(path string, data []byte, owner string) ([]byte, bool) {
	if owner == "" || len(data) == 0 {
		return data, false
	}
	if strings.HasPrefix(path, "/api/users") {
		var rows []map[string]interface{}
		if err := json.Unmarshal(data, &rows); err != nil {
			return data, false
		}
		out := rows[:0]
		for _, row := range rows {
			if strings.TrimSpace(fmt.Sprint(row["owner_username"])) == owner {
				out = append(out, row)
			}
		}
		filtered, _ := json.Marshal(out)
		return filtered, true
	}
	if strings.HasPrefix(path, "/api/xray/inbounds") {
		var inbounds []map[string]interface{}
		if err := json.Unmarshal(data, &inbounds); err != nil {
			return data, false
		}
		for _, ib := range inbounds {
			clients, _ := ib["clients"].([]interface{})
			filtered := make([]interface{}, 0, len(clients))
			for _, c := range clients {
				m, _ := c.(map[string]interface{})
				if strings.TrimSpace(fmt.Sprint(m["owner_username"])) == owner {
					filtered = append(filtered, c)
				}
			}
			ib["clients"] = filtered
		}
		filtered, _ := json.Marshal(inbounds)
		return filtered, true
	}
	return data, false
}

func handleServers(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if store == nil {
			http.Error(w, "database not configured", http.StatusServiceUnavailable)
			return
		}
		sess := sessionFromCtx(r.Context())
		switch r.Method {
		case http.MethodGet:
			rows, err := store.ListManagedServers(r.Context())
			if err != nil {
				http.Error(w, "db error", http.StatusInternalServerError)
				return
			}
			out := []ManagedServerDTO{localManagedServerDTO()}
			for _, ms := range rows {
				if sess != nil && sess.Role == RoleReseller && !ms.IsActive {
					continue
				}
				dto := managedServerToDTO(ms)
				if sess != nil && sess.Role == RoleReseller {
					dto.AdminUsername = ""
				}
				out = append(out, dto)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(out)
		case http.MethodPost:
			if sess == nil || sess.Role != RoleSuperAdmin {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			var p ManagedServerPayload
			if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
				http.Error(w, "invalid json", http.StatusBadRequest)
				return
			}
			ms, err := store.UpsertManagedServer(r.Context(), p)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(managedServerToDTO(ms))
		case http.MethodDelete:
			if sess == nil || sess.Role != RoleSuperAdmin {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			idStr := strings.TrimSpace(r.URL.Query().Get("id"))
			id, err := strconv.Atoi(idStr)
			if err != nil || id <= 0 {
				http.Error(w, "invalid server id", http.StatusBadRequest)
				return
			}
			if err := store.DeleteManagedServer(r.Context(), id); err != nil {
				http.Error(w, "db error", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

func handleServerTest(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if store == nil {
			http.Error(w, "database not configured", http.StatusServiceUnavailable)
			return
		}
		var p ManagedServerPayload
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		ms := &ManagedServer{Name: p.Name, BaseURL: normalizeManagedServerBaseURL(p.BaseURL), AdminUsername: strings.TrimSpace(p.AdminUsername), AdminKey: p.AdminKey, EnableSSH: p.EnableSSH, EnableXray: p.EnableXray, IsActive: true}
		if p.ID != "" && p.ID != "local" && (ms.BaseURL == "" || ms.AdminKey == "") {
			id, _ := strconv.Atoi(p.ID)
			if id > 0 {
				stored, err := store.GetManagedServer(r.Context(), id)
				if err == nil && stored != nil {
					if ms.BaseURL == "" {
						ms.BaseURL = stored.BaseURL
					}
					if ms.AdminUsername == "" {
						ms.AdminUsername = stored.AdminUsername
					}
					if ms.AdminKey == "" {
						ms.AdminKey = stored.AdminKey
					}
				}
			}
		}
		if ms.AdminUsername == "" {
			ms.AdminUsername = "admin"
		}
		if ms.BaseURL == "" || ms.AdminKey == "" {
			http.Error(w, "base url and admin key/password required", http.StatusBadRequest)
			return
		}
		token, err := remoteLoginToken(r.Context(), ms)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		_ = token
		status, data, _, err := proxyManagedServer(r.Context(), ms, http.MethodGet, "/api/auth/me", nil, "application/json")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		if status < 200 || status >= 300 {
			http.Error(w, strings.TrimSpace(string(data)), http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "message": "remote login ok"})
	}
}

func handleManagedServerConfig(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := requestedServerID(r)
		if id == "" || id == "local" || id == "0" {
			handleServerConfig(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body := []byte(nil)
		if r.Method == http.MethodPost {
			var err error
			body, err = io.ReadAll(io.LimitReader(r.Body, 512*1024))
			if err != nil {
				http.Error(w, "failed to read body", http.StatusBadRequest)
				return
			}
		}
		ms, remote, err := managedServerFromID(r.Context(), store, id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !remote {
			handleServerConfig(w, r)
			return
		}
		status, data, ct, err := proxyManagedServer(r.Context(), ms, r.Method, "/api/server/config", body, "application/json")
		if err != nil {
			log.Printf("managed server config proxy %s: %v", ms.BaseURL, err)
			http.Error(w, "remote server error: "+err.Error(), http.StatusBadGateway)
			return
		}
		writeProxyResponse(w, status, data, ct)
	}
}

func remoteSSHUserOwner(ctx context.Context, ms *ManagedServer, username string) (owner string, exists bool, err error) {
	if username == "" {
		return "", false, nil
	}
	status, data, _, err := proxyManagedServer(ctx, ms, http.MethodGet, "/api/users", nil, "application/json")
	if err != nil || status < 200 || status >= 300 {
		if err == nil {
			err = fmt.Errorf("remote users returned HTTP %d", status)
		}
		return "", false, err
	}
	var rows []map[string]interface{}
	if err := json.Unmarshal(data, &rows); err != nil {
		return "", false, err
	}
	for _, row := range rows {
		if fmt.Sprint(row["username"]) == username {
			return strings.TrimSpace(fmt.Sprint(row["owner_username"])), true, nil
		}
	}
	return "", false, nil
}

func remoteSSHUserOwned(ctx context.Context, ms *ManagedServer, username, owner string) bool {
	actualOwner, exists, err := remoteSSHUserOwner(ctx, ms, username)
	return err == nil && exists && actualOwner == owner
}

func remoteXrayClientOwner(ctx context.Context, ms *ManagedServer, uuid string) (owner string, exists bool, err error) {
	if uuid == "" {
		return "", false, nil
	}
	status, data, _, err := proxyManagedServer(ctx, ms, http.MethodGet, "/api/xray/inbounds", nil, "application/json")
	if err != nil || status < 200 || status >= 300 {
		if err == nil {
			err = fmt.Errorf("remote Xray inbounds returned HTTP %d", status)
		}
		return "", false, err
	}
	var inbounds []map[string]interface{}
	if err := json.Unmarshal(data, &inbounds); err != nil {
		return "", false, err
	}
	for _, ib := range inbounds {
		clients, _ := ib["clients"].([]interface{})
		for _, c := range clients {
			m, _ := c.(map[string]interface{})
			if fmt.Sprint(m["id"]) == uuid {
				return strings.TrimSpace(fmt.Sprint(m["owner_username"])), true, nil
			}
		}
	}
	return "", false, nil
}

func remoteXrayClientOwned(ctx context.Context, ms *ManagedServer, uuid, owner string) bool {
	actualOwner, exists, err := remoteXrayClientOwner(ctx, ms, uuid)
	return err == nil && exists && actualOwner == owner
}

func countOwnedQuotaAcrossManagedServers(ctx context.Context, store *Store, owner string) (int, error) {
	if store == nil || owner == "" {
		return 0, nil
	}
	total := countOwnedQuota(ctx, store, owner)
	servers, err := store.ListManagedServers(ctx)
	if err != nil {
		return 0, err
	}
	for _, ms := range servers {
		if !ms.IsActive {
			continue
		}
		if ms.EnableSSH {
			status, data, _, err := proxyManagedServer(ctx, ms, http.MethodGet, "/api/users", nil, "application/json")
			if err != nil || status < 200 || status >= 300 {
				if err == nil {
					err = fmt.Errorf("remote users returned HTTP %d", status)
				}
				return 0, err
			}
			var users []map[string]interface{}
			if err := json.Unmarshal(data, &users); err != nil {
				return 0, err
			}
			for _, user := range users {
				if strings.TrimSpace(fmt.Sprint(user["owner_username"])) == owner {
					total++
				}
			}
		}
		if ms.EnableXray {
			status, data, _, err := proxyManagedServer(ctx, ms, http.MethodGet, "/api/xray/inbounds", nil, "application/json")
			if err != nil || status < 200 || status >= 300 {
				if err == nil {
					err = fmt.Errorf("remote Xray inbounds returned HTTP %d", status)
				}
				return 0, err
			}
			var inbounds []map[string]interface{}
			if err := json.Unmarshal(data, &inbounds); err != nil {
				return 0, err
			}
			for _, inbound := range inbounds {
				clients, _ := inbound["clients"].([]interface{})
				for _, client := range clients {
					item, _ := client.(map[string]interface{})
					if strings.TrimSpace(fmt.Sprint(item["owner_username"])) == owner {
						total++
					}
				}
			}
		}
	}
	return total, nil
}
