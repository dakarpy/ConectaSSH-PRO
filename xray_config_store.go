package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

// EnsureXrayConfigSchema creates the DB table used as the canonical store for
// Xray JSON configs. The config_file path is used as a stable key so local and
// remote nodes can keep independent configs in the same database if needed.
func (s *Store) EnsureXrayConfigSchema(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS xray_configs (
			config_key  TEXT PRIMARY KEY,
			config_json JSONB NOT NULL,
			updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`ALTER TABLE xray_configs ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) GetXrayConfig(ctx context.Context, configKey string) ([]byte, bool, error) {
	if configKey == "" {
		configKey = "default"
	}
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT config_json::text FROM xray_configs WHERE config_key = $1`, configKey).Scan(&raw)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, false, nil
		}
		return nil, false, err
	}
	if !json.Valid([]byte(raw)) {
		return nil, false, fmt.Errorf("stored Xray config %q is not valid JSON", configKey)
	}
	return []byte(raw), true, nil
}

func (s *Store) UpsertXrayConfig(ctx context.Context, configKey string, data []byte) error {
	if configKey == "" {
		configKey = "default"
	}
	if !json.Valid(data) {
		return fmt.Errorf("invalid Xray JSON config")
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO xray_configs (config_key, config_json, updated_at)
		VALUES ($1, $2::jsonb, NOW())
		ON CONFLICT (config_key) DO UPDATE SET
			config_json = EXCLUDED.config_json,
			updated_at = NOW()`, configKey, string(data))
	return err
}

func (s *Store) ListXrayClientsByInbound(ctx context.Context, inboundTag string) ([]*XrayClientMeta, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT uuid, name, email, inbound_tag, COALESCE(owner_username, ''), expires_at, max_conns,
		       COALESCE(data_quota_bytes, 0), COALESCE(quota_action, 'block'), COALESCE(quota_throttle_mbps, 1), created_at,
		       COALESCE(total_uplink_bytes, 0), COALESCE(total_downlink_bytes, 0), last_active, COALESCE(active_connections, 0)
		FROM xray_clients WHERE inbound_tag = $1 ORDER BY created_at DESC`, inboundTag)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanXrayClientMetaRows(rows)
}

// ImportXrayClientsFromConfig mirrors client UUIDs found in an existing Xray
// JSON config into xray_clients. This lets native mode inherit users from the
// external Xray config and keeps the DB as the hot-reloadable client index.
// It intentionally preserves owner/expiry/quota fields for existing rows.
func (s *Store) ImportXrayClientsFromConfig(ctx context.Context, data []byte) (int, error) {
	if s == nil || len(data) == 0 {
		return 0, nil
	}
	var cfg struct {
		Inbounds []struct {
			Tag      string `json:"tag"`
			Protocol string `json:"protocol"`
			Settings struct {
				Clients []struct {
					ID       string `json:"id"`
					Password string `json:"password"`
					Email    string `json:"email"`
				} `json:"clients"`
				Users []struct {
					ID       string `json:"id"`
					Password string `json:"password"`
					Email    string `json:"email"`
				} `json:"users"`
			} `json:"settings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return 0, err
	}
	imported := 0
	for _, ib := range cfg.Inbounds {
		proto := strings.ToLower(strings.TrimSpace(ib.Protocol))
		if proto != "vless" && proto != "vmess" && proto != "trojan" {
			continue
		}
		inboundTag := strings.TrimSpace(ib.Tag)
		configClients := ib.Settings.Clients
		if len(ib.Settings.Users) > 0 {
			configClients = append(configClients, ib.Settings.Users...)
		}
		for _, c := range configClients {
			uuid := strings.TrimSpace(c.ID)
			if uuid == "" {
				uuid = strings.TrimSpace(c.Password)
			}
			if uuid == "" {
				continue
			}
			email := strings.TrimSpace(c.Email)
			if email == "" {
				email = uuid
			}
			_, err := s.db.ExecContext(ctx, `
				INSERT INTO xray_clients (uuid, name, email, inbound_tag)
				VALUES ($1, $2, $3, $4)
				ON CONFLICT (uuid) DO UPDATE SET
					email       = CASE WHEN xray_clients.email = '' THEN EXCLUDED.email ELSE xray_clients.email END,
					name        = CASE WHEN xray_clients.name = '' THEN EXCLUDED.name ELSE xray_clients.name END,
					inbound_tag = CASE WHEN EXCLUDED.inbound_tag <> '' THEN EXCLUDED.inbound_tag ELSE xray_clients.inbound_tag END`,
				uuid, email, email, inboundTag)
			if err != nil {
				return imported, err
			}
			imported++
		}
	}
	return imported, nil
}
