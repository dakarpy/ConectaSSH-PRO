package main

import (
	"context"
	"database/sql"
	"log"
	"time"
)

// XrayClientMeta holds metadata stored in PostgreSQL for an Xray client.
// Xray's own config only stores uuid/email/level; expiry, display name,
// reseller owner, and connection policy live here.
type XrayClientMeta struct {
	UUID               string
	Name               string
	Email              string
	InboundTag         string
	OwnerUsername      string
	ExpiresAt          *time.Time
	MaxConns           int
	DataQuotaBytes     int64
	QuotaAction        string
	QuotaThrottleMbps  int
	CreatedAt          time.Time
	TotalUplinkBytes   int64
	TotalDownlinkBytes int64
	LastActive         *time.Time
	ActiveConnections  int
}

func (s *Store) EnsureXrayClientsSchema(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS xray_clients (
			uuid                  TEXT PRIMARY KEY,
			name                  TEXT NOT NULL DEFAULT '',
			email                 TEXT NOT NULL DEFAULT '',
			inbound_tag           TEXT NOT NULL DEFAULT '',
			owner_username        TEXT NOT NULL DEFAULT '',
			expires_at            TIMESTAMPTZ,
			max_conns             INT NOT NULL DEFAULT 0,
			data_quota_bytes      BIGINT NOT NULL DEFAULT 0,
			quota_action          TEXT NOT NULL DEFAULT 'block',
			quota_throttle_mbps   INT NOT NULL DEFAULT 1,
			created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			total_uplink_bytes    BIGINT NOT NULL DEFAULT 0,
			total_downlink_bytes  BIGINT NOT NULL DEFAULT 0,
			last_active           TIMESTAMPTZ,
			active_connections    INT NOT NULL DEFAULT 0
		)`,
		`ALTER TABLE xray_clients ADD COLUMN IF NOT EXISTS owner_username TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE xray_clients ADD COLUMN IF NOT EXISTS data_quota_bytes BIGINT NOT NULL DEFAULT 0`,
		`ALTER TABLE xray_clients ADD COLUMN IF NOT EXISTS quota_action TEXT NOT NULL DEFAULT 'block'`,
		`ALTER TABLE xray_clients ADD COLUMN IF NOT EXISTS quota_throttle_mbps INT NOT NULL DEFAULT 1`,
		`ALTER TABLE xray_clients ADD COLUMN IF NOT EXISTS total_uplink_bytes BIGINT NOT NULL DEFAULT 0`,
		`ALTER TABLE xray_clients ADD COLUMN IF NOT EXISTS total_downlink_bytes BIGINT NOT NULL DEFAULT 0`,
		`ALTER TABLE xray_clients ADD COLUMN IF NOT EXISTS last_active TIMESTAMPTZ`,
		`ALTER TABLE xray_clients ADD COLUMN IF NOT EXISTS active_connections INT NOT NULL DEFAULT 0`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) UpsertXrayClientMeta(ctx context.Context, m XrayClientMeta) error {
	var expiresAt interface{}
	if m.ExpiresAt != nil {
		expiresAt = *m.ExpiresAt
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO xray_clients (uuid, name, email, inbound_tag, owner_username, expires_at, max_conns, data_quota_bytes, quota_action, quota_throttle_mbps)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (uuid) DO UPDATE SET
			name           = EXCLUDED.name,
			email          = EXCLUDED.email,
			inbound_tag    = CASE WHEN EXCLUDED.inbound_tag <> '' THEN EXCLUDED.inbound_tag ELSE xray_clients.inbound_tag END,
			owner_username = CASE WHEN EXCLUDED.owner_username <> '' THEN EXCLUDED.owner_username ELSE xray_clients.owner_username END,
			expires_at          = EXCLUDED.expires_at,
			max_conns           = EXCLUDED.max_conns,
			data_quota_bytes    = EXCLUDED.data_quota_bytes,
			quota_action        = EXCLUDED.quota_action,
			quota_throttle_mbps = EXCLUDED.quota_throttle_mbps`,
		m.UUID, m.Name, m.Email, m.InboundTag, m.OwnerUsername, expiresAt, m.MaxConns,
		m.DataQuotaBytes, normalizeQuotaAction(m.QuotaAction), quotaThrottleMbpsOrDefault(m.QuotaThrottleMbps))
	return err
}

func (s *Store) GetXrayClientMeta(ctx context.Context, uuid string) (*XrayClientMeta, error) {
	m := &XrayClientMeta{}
	var expiresAt sql.NullTime
	var lastActive sql.NullTime
	err := s.db.QueryRowContext(ctx, `
		SELECT uuid, name, email, inbound_tag, COALESCE(owner_username, ''), expires_at, max_conns,
		       COALESCE(data_quota_bytes, 0), COALESCE(quota_action, 'block'), COALESCE(quota_throttle_mbps, 1), created_at,
		       COALESCE(total_uplink_bytes, 0), COALESCE(total_downlink_bytes, 0), last_active, COALESCE(active_connections, 0)
		FROM xray_clients WHERE uuid = $1`, uuid).
		Scan(&m.UUID, &m.Name, &m.Email, &m.InboundTag, &m.OwnerUsername, &expiresAt, &m.MaxConns,
			&m.DataQuotaBytes, &m.QuotaAction, &m.QuotaThrottleMbps, &m.CreatedAt,
			&m.TotalUplinkBytes, &m.TotalDownlinkBytes, &lastActive, &m.ActiveConnections)
	if err != nil {
		return nil, err
	}
	if expiresAt.Valid {
		m.ExpiresAt = &expiresAt.Time
	}
	if lastActive.Valid {
		m.LastActive = &lastActive.Time
	}
	return m, nil
}

func (s *Store) DeleteXrayClientMeta(ctx context.Context, uuid string) error {
	// Serialize deletion with the native stats flusher. Otherwise a batch that
	// was swapped out just before DELETE could finish afterward and, if the same
	// UUID is recreated quickly, apply stale traffic/active deltas to the new row.
	xrayMgr.nativeTrafficPersistMu.Lock()
	defer xrayMgr.nativeTrafficPersistMu.Unlock()
	_, err := s.db.ExecContext(ctx, `DELETE FROM xray_clients WHERE uuid = $1`, uuid)
	if err == nil {
		xrayMgr.removeNativeQuotaPolicy(uuid)
	}
	return err
}

func (s *Store) ListAllXrayClients(ctx context.Context) ([]*XrayClientMeta, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT uuid, name, email, inbound_tag, COALESCE(owner_username, ''), expires_at, max_conns,
		       COALESCE(data_quota_bytes, 0), COALESCE(quota_action, 'block'), COALESCE(quota_throttle_mbps, 1), created_at,
		       COALESCE(total_uplink_bytes, 0), COALESCE(total_downlink_bytes, 0), last_active, COALESCE(active_connections, 0)
		FROM xray_clients ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanXrayClientMetaRows(rows)
}

func (s *Store) ListXrayClientsByOwner(ctx context.Context, ownerUsername string) ([]*XrayClientMeta, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT uuid, name, email, inbound_tag, COALESCE(owner_username, ''), expires_at, max_conns,
		       COALESCE(data_quota_bytes, 0), COALESCE(quota_action, 'block'), COALESCE(quota_throttle_mbps, 1), created_at,
		       COALESCE(total_uplink_bytes, 0), COALESCE(total_downlink_bytes, 0), last_active, COALESCE(active_connections, 0)
		FROM xray_clients WHERE owner_username = $1 ORDER BY created_at DESC`, ownerUsername)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanXrayClientMetaRows(rows)
}

func (s *Store) CountXrayClientsByOwner(ctx context.Context, ownerUsername string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM xray_clients WHERE owner_username = $1`, ownerUsername).Scan(&n)
	return n, err
}

func (s *Store) ListExpiredXrayClients(ctx context.Context) ([]*XrayClientMeta, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT uuid, name, email, inbound_tag, COALESCE(owner_username, ''), expires_at, max_conns,
		       COALESCE(data_quota_bytes, 0), COALESCE(quota_action, 'block'), COALESCE(quota_throttle_mbps, 1), created_at,
		       COALESCE(total_uplink_bytes, 0), COALESCE(total_downlink_bytes, 0), last_active, COALESCE(active_connections, 0)
		FROM xray_clients WHERE expires_at IS NOT NULL AND expires_at <= NOW()`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanXrayClientMetaRows(rows)
}

func scanXrayClientMetaRows(rows *sql.Rows) ([]*XrayClientMeta, error) {
	var out []*XrayClientMeta
	for rows.Next() {
		m := &XrayClientMeta{}
		var expiresAt sql.NullTime
		var lastActive sql.NullTime
		if err := rows.Scan(&m.UUID, &m.Name, &m.Email, &m.InboundTag, &m.OwnerUsername, &expiresAt, &m.MaxConns,
			&m.DataQuotaBytes, &m.QuotaAction, &m.QuotaThrottleMbps, &m.CreatedAt,
			&m.TotalUplinkBytes, &m.TotalDownlinkBytes, &lastActive, &m.ActiveConnections); err != nil {
			return nil, err
		}
		if expiresAt.Valid {
			m.ExpiresAt = &expiresAt.Time
		}
		if lastActive.Valid {
			m.LastActive = &lastActive.Time
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ResetXrayActiveConnections clears stale online counters after the panel starts.
// Native mode then increments/decrements active_connections for real live streams.
func (s *Store) ResetXrayActiveConnections(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `UPDATE xray_clients SET active_connections = 0`)
	return err
}

// AddXrayClientTrafficBatch persists native-emulator traffic deltas. It keeps
// totals in PostgreSQL so bandwidth remains visible after panel restarts.
func (s *Store) AddXrayClientTrafficBatch(ctx context.Context, deltas map[string]xrayPendingTraffic) error {
	if len(deltas) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `
		UPDATE xray_clients SET
			email                = CASE WHEN email = '' AND $2 <> '' THEN $2 ELSE email END,
			name                 = CASE WHEN name = '' AND $2 <> '' THEN $2 ELSE name END,
			total_uplink_bytes   = GREATEST(total_uplink_bytes + GREATEST($3::BIGINT, 0), 0),
			total_downlink_bytes = GREATEST(total_downlink_bytes + GREATEST($4::BIGINT, 0), 0),
			last_active          = NOW()
		WHERE uuid = $1`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for uuid, d := range deltas {
		if uuid == "" || (d.Uplink == 0 && d.Downlink == 0) {
			continue
		}
		if _, err := stmt.ExecContext(ctx, uuid, d.Email, d.Uplink, d.Downlink); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// AddXrayClientActiveBatch persists native online-counter deltas without
// launching a database goroutine/query for every connect and disconnect.
func (s *Store) AddXrayClientActiveBatch(ctx context.Context, deltas map[string]xrayPendingActive) error {
	if len(deltas) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `
		UPDATE xray_clients SET
			email              = CASE WHEN email = '' AND $2 <> '' THEN $2 ELSE email END,
			name               = CASE WHEN name = '' AND $2 <> '' THEN $2 ELSE name END,
			last_active        = CASE WHEN $4::BOOLEAN THEN NOW() ELSE last_active END,
			active_connections = GREATEST(active_connections + $3::INT, 0)
		WHERE uuid = $1`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for uuid, d := range deltas {
		if uuid == "" || (d.Delta == 0 && !d.Connected) {
			continue
		}
		if _, err := stmt.ExecContext(ctx, uuid, d.Email, d.Delta, d.Connected); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func countOwnedXrayClients(ctx context.Context, store *Store, ownerUsername string) int {
	if store == nil || ownerUsername == "" {
		return 0
	}
	n, err := store.CountXrayClientsByOwner(ctx, ownerUsername)
	if err != nil {
		log.Printf("count xray clients for %s: %v", ownerUsername, err)
		return 0
	}
	return n
}

func countOwnedQuota(ctx context.Context, store *Store, ownerUsername string) int {
	return countOwnedUsers(ownerUsername) + countOwnedXrayClients(ctx, store, ownerUsername)
}

func removeOwnerXrayClients(ctx context.Context, store *Store, ownerUsername string) {
	if store == nil || ownerUsername == "" {
		return
	}
	clients, err := store.ListXrayClientsByOwner(ctx, ownerUsername)
	if err != nil {
		log.Printf("xray owner cleanup: list %s: %v", ownerUsername, err)
		return
	}
	needRestart := false
	for _, m := range clients {
		if m.InboundTag != "" {
			if err := xrayMgr.RemoveXrayClient(m.InboundTag, m.UUID); err != nil {
				log.Printf("xray owner cleanup: remove %s from %s: %v", m.UUID, m.InboundTag, err)
			} else {
				needRestart = true
			}
		}
		if err := store.DeleteXrayClientMeta(ctx, m.UUID); err != nil {
			log.Printf("xray owner cleanup: delete meta %s: %v", m.UUID, err)
		}
	}
	if needRestart {
		xrayMgr.restartIfExternalRunning()
	}
}

// suspendOwnerXrayClients revokes transport access while preserving metadata,
// expiry, traffic and quota. This makes reseller suspension/renewal reversible.
func suspendOwnerXrayClients(ctx context.Context, store *Store, ownerUsername string) {
	if store == nil || ownerUsername == "" {
		return
	}
	clients, err := store.ListXrayClientsByOwner(ctx, ownerUsername)
	if err != nil {
		log.Printf("xray owner suspension: list %s: %v", ownerUsername, err)
		return
	}
	changed := false
	for _, m := range clients {
		xrayMgr.disconnectNativeClient(m.UUID)
		if m.InboundTag == "" {
			continue
		}
		if err := xrayMgr.RemoveXrayClient(m.InboundTag, m.UUID); err != nil {
			log.Printf("xray owner suspension: remove %s from %s: %v", m.UUID, m.InboundTag, err)
			continue
		}
		changed = true
	}
	if changed {
		xrayMgr.restartIfExternalRunning()
	}
}

// restoreOwnerXrayClients reactivates non-expired clients after reseller renewal.
func restoreOwnerXrayClients(ctx context.Context, store *Store, ownerUsername string) {
	if store == nil || ownerUsername == "" {
		return
	}
	clients, err := store.ListXrayClientsByOwner(ctx, ownerUsername)
	if err != nil {
		log.Printf("xray owner restore: list %s: %v", ownerUsername, err)
		return
	}
	now := time.Now()
	changed := false
	for _, m := range clients {
		if m.InboundTag == "" || (m.ExpiresAt != nil && !m.ExpiresAt.After(now)) {
			continue
		}
		email := m.Email
		if email == "" {
			email = m.UUID
		}
		if err := xrayMgr.EnsureXrayClient(m.InboundTag, m.UUID, email); err != nil {
			log.Printf("xray owner restore: add %s to %s: %v", m.UUID, m.InboundTag, err)
			continue
		}
		xrayMgr.setNativeQuotaPolicy(m)
		changed = true
	}
	if changed {
		xrayMgr.restartIfExternalRunning()
	}
}

// startXrayClientExpiryChecker runs a background goroutine that removes expired
// Xray clients from both the config file and the database every 5 minutes.
func startXrayClientExpiryChecker(store *Store) {
	if store == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			expireXrayClientsOnce(store)
		}
	}()
}

func expireXrayClientsOnce(store *Store) {
	if store == nil {
		return
	}
	ctx := context.Background()
	expired, err := store.ListExpiredXrayClients(ctx)
	if err != nil {
		log.Printf("xray expiry checker: list error: %v", err)
		return
	}
	needRestart := false
	for _, m := range expired {
		tag := m.InboundTag
		xrayMgr.disconnectNativeClient(m.UUID)
		if tag != "" {
			if err := xrayMgr.RemoveXrayClient(tag, m.UUID); err != nil {
				log.Printf("xray expiry: remove %s from %s: %v", m.UUID, tag, err)
			} else {
				needRestart = true
			}
		}
		if err := store.DeleteXrayClientMeta(ctx, m.UUID); err != nil {
			log.Printf("xray expiry: delete meta %s: %v", m.UUID, err)
		}
		log.Printf("xray expiry: removed expired client %q (%s) from inbound %s", m.Name, m.UUID, tag)
	}
	if needRestart {
		xrayMgr.restartIfExternalRunning()
	}
}

// ResetXrayClientTraffic clears a client's persistent usage without removing
// the account or changing its expiry/quota policy.
func (s *Store) ResetXrayClientTraffic(ctx context.Context, uuid string) error {
	if s == nil || uuid == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE xray_clients SET
			total_uplink_bytes = 0,
			total_downlink_bytes = 0,
			last_active = NULL
		WHERE uuid = $1`, uuid)
	return err
}
