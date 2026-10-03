package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"
)

type IfaceUsageDelta struct {
	Iface   string
	RxBytes uint64
	TxBytes uint64
	At      time.Time
}

var ifaceUsagePending = struct {
	mu sync.Mutex
	m  map[string]ifaceCounters
}{m: make(map[string]ifaceCounters)}

func addPendingIfaceUsage(iface string, rxBytes, txBytes uint64) {
	if isIgnoredInterface(iface) || (rxBytes == 0 && txBytes == 0) {
		return
	}
	ifaceUsagePending.mu.Lock()
	defer ifaceUsagePending.mu.Unlock()
	p := ifaceUsagePending.m[iface]
	p.RxBytes += rxBytes
	p.TxBytes += txBytes
	ifaceUsagePending.m[iface] = p
}

func flushPendingIfaceUsage(at time.Time) []IfaceUsageDelta {
	ifaceUsagePending.mu.Lock()
	defer ifaceUsagePending.mu.Unlock()
	if len(ifaceUsagePending.m) == 0 {
		return nil
	}
	deltas := make([]IfaceUsageDelta, 0, len(ifaceUsagePending.m))
	for iface, ctrs := range ifaceUsagePending.m {
		if isIgnoredInterface(iface) {
			continue
		}
		deltas = append(deltas, IfaceUsageDelta{Iface: iface, RxBytes: ctrs.RxBytes, TxBytes: ctrs.TxBytes, At: at})
	}
	ifaceUsagePending.m = make(map[string]ifaceCounters)
	return deltas
}

func restorePendingIfaceUsage(deltas []IfaceUsageDelta) {
	ifaceUsagePending.mu.Lock()
	defer ifaceUsagePending.mu.Unlock()
	for _, d := range deltas {
		if isIgnoredInterface(d.Iface) {
			continue
		}
		p := ifaceUsagePending.m[d.Iface]
		p.RxBytes += d.RxBytes
		p.TxBytes += d.TxBytes
		ifaceUsagePending.m[d.Iface] = p
	}
}

func clearPendingIfaceUsage() {
	ifaceUsagePending.mu.Lock()
	ifaceUsagePending.m = make(map[string]ifaceCounters)
	ifaceUsagePending.mu.Unlock()
}

type VnstatUsageRow struct {
	Iface      string `json:"iface"`
	Period     string `json:"period"`
	RxBytes    uint64 `json:"rx_bytes"`
	TxBytes    uint64 `json:"tx_bytes"`
	TotalBytes uint64 `json:"total_bytes"`
}

type VnstatDTO struct {
	Daily           []VnstatUsageRow `json:"daily"`
	Monthly         []VnstatUsageRow `json:"monthly"`
	UpdatedAt       time.Time        `json:"updated_at"`
	TodayPeriod     string           `json:"today_period"`
	MonthPeriod     string           `json:"month_period"`
	TodayTotalBytes uint64           `json:"today_total_bytes"`
	MonthTotalBytes uint64           `json:"month_total_bytes"`
	InterfaceCount  int              `json:"interface_count"`
}

func (s *Store) EnsureIfaceUsageTables(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS ssh_iface_daily_usage (
			usage_date DATE NOT NULL,
			iface TEXT NOT NULL,
			rx_bytes BIGINT NOT NULL DEFAULT 0,
			tx_bytes BIGINT NOT NULL DEFAULT 0,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			PRIMARY KEY (usage_date, iface)
		)`,
		`CREATE TABLE IF NOT EXISTS ssh_iface_monthly_usage (
			month_start DATE NOT NULL,
			iface TEXT NOT NULL,
			rx_bytes BIGINT NOT NULL DEFAULT 0,
			tx_bytes BIGINT NOT NULL DEFAULT 0,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			PRIMARY KEY (month_start, iface)
		)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) UpsertIfaceUsageDeltas(ctx context.Context, deltas []IfaceUsageDelta) error {
	if len(deltas) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, d := range deltas {
		if isIgnoredInterface(d.Iface) || (d.RxBytes == 0 && d.TxBytes == 0) {
			continue
		}
		at := d.At
		if at.IsZero() {
			at = time.Now()
		}
		day := at.Format("2006-01-02")
		month := time.Date(at.Year(), at.Month(), 1, 0, 0, 0, 0, at.Location()).Format("2006-01-02")

		if _, err := tx.ExecContext(ctx, `
			INSERT INTO ssh_iface_daily_usage (usage_date, iface, rx_bytes, tx_bytes, updated_at)
			VALUES ($1, $2, $3, $4, NOW())
			ON CONFLICT (usage_date, iface) DO UPDATE
			SET rx_bytes = ssh_iface_daily_usage.rx_bytes + EXCLUDED.rx_bytes,
				tx_bytes = ssh_iface_daily_usage.tx_bytes + EXCLUDED.tx_bytes,
				updated_at = NOW()`,
			day, d.Iface, d.RxBytes, d.TxBytes); err != nil {
			return err
		}

		if _, err := tx.ExecContext(ctx, `
			INSERT INTO ssh_iface_monthly_usage (month_start, iface, rx_bytes, tx_bytes, updated_at)
			VALUES ($1, $2, $3, $4, NOW())
			ON CONFLICT (month_start, iface) DO UPDATE
			SET rx_bytes = ssh_iface_monthly_usage.rx_bytes + EXCLUDED.rx_bytes,
				tx_bytes = ssh_iface_monthly_usage.tx_bytes + EXCLUDED.tx_bytes,
				updated_at = NOW()`,
			month, d.Iface, d.RxBytes, d.TxBytes); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *Store) LoadIfaceUsage(ctx context.Context, days, months int) (VnstatDTO, error) {
	if days <= 0 || days > 366 {
		days = 31
	}
	if months <= 0 || months > 60 {
		months = 12
	}

	now := time.Now()
	todayPeriod := now.Format("2006-01-02")
	monthPeriod := now.Format("2006-01")
	out := VnstatDTO{UpdatedAt: now, TodayPeriod: todayPeriod, MonthPeriod: monthPeriod}
	ifaceSet := make(map[string]struct{})

	dailyRows, err := s.db.QueryContext(ctx, `
		SELECT iface, usage_date::text, rx_bytes, tx_bytes
		FROM ssh_iface_daily_usage
		WHERE usage_date >= CURRENT_DATE - $1::int
		  AND iface <> 'lo'
		ORDER BY usage_date DESC, iface ASC`, days-1)
	if err != nil {
		return out, err
	}
	defer dailyRows.Close()
	for dailyRows.Next() {
		var r VnstatUsageRow
		if err := dailyRows.Scan(&r.Iface, &r.Period, &r.RxBytes, &r.TxBytes); err != nil {
			return out, err
		}
		r.TotalBytes = r.RxBytes + r.TxBytes
		out.Daily = append(out.Daily, r)
		ifaceSet[r.Iface] = struct{}{}
		if r.Period == todayPeriod {
			out.TodayTotalBytes += r.TotalBytes
		}
	}
	if err := dailyRows.Err(); err != nil {
		return out, err
	}

	monthlyRows, err := s.db.QueryContext(ctx, `
		SELECT iface, to_char(month_start, 'YYYY-MM') AS period, rx_bytes, tx_bytes
		FROM ssh_iface_monthly_usage
		WHERE month_start >= (date_trunc('month', CURRENT_DATE)::date - ($1::int * INTERVAL '1 month'))
		  AND iface <> 'lo'
		ORDER BY month_start DESC, iface ASC`, months-1)
	if err != nil {
		return out, err
	}
	defer monthlyRows.Close()
	for monthlyRows.Next() {
		var r VnstatUsageRow
		if err := monthlyRows.Scan(&r.Iface, &r.Period, &r.RxBytes, &r.TxBytes); err != nil {
			return out, err
		}
		r.TotalBytes = r.RxBytes + r.TxBytes
		out.Monthly = append(out.Monthly, r)
		ifaceSet[r.Iface] = struct{}{}
		if r.Period == monthPeriod {
			out.MonthTotalBytes += r.TotalBytes
		}
	}
	if err := monthlyRows.Err(); err != nil {
		return out, err
	}

	out.InterfaceCount = len(ifaceSet)

	return out, nil
}

func (s *Store) ResetIfaceUsage(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `TRUNCATE TABLE ssh_iface_daily_usage, ssh_iface_monthly_usage`); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ReplaceIfaceTotals(ctx context.Context, rows []IfaceTotals) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM ssh_iface_totals`); err != nil {
		return err
	}
	for _, r := range rows {
		if isIgnoredInterface(r.Iface) {
			continue
		}
		resetAt := r.ResetAt
		if resetAt.IsZero() {
			resetAt = time.Now()
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO ssh_iface_totals (iface, total_rx_bytes, total_tx_bytes, last_kernel_rx_bytes, last_kernel_tx_bytes, updated_at, reset_at)
			VALUES ($1, $2, $3, $4, $5, NOW(), $6)`,
			r.Iface, r.TotalRxBytes, r.TotalTxBytes, r.LastKernelRxBytes, r.LastKernelTxBytes, resetAt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func handleVnstat(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if store == nil {
			http.Error(w, "database not configured", http.StatusServiceUnavailable)
			return
		}
		days := parsePositiveInt(r.URL.Query().Get("days"), 31)
		months := parsePositiveInt(r.URL.Query().Get("months"), 12)
		data, err := store.LoadIfaceUsage(r.Context(), days, months)
		if err != nil {
			log.Printf("failed to load vnstat usage: %v", err)
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(data)
	}
}

func handleVnstatReset(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if store == nil {
			http.Error(w, "database not configured", http.StatusServiceUnavailable)
			return
		}
		if err := store.ResetIfaceUsage(r.Context()); err != nil {
			log.Printf("failed to reset vnstat usage: %v", err)
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		clearPendingIfaceUsage()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}
}

func handleResetInterfaceStats(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if store == nil || ifaceTotalsMgr == nil {
			http.Error(w, "interface totals persistence not configured", http.StatusServiceUnavailable)
			return
		}

		netMap, err := readNetDev()
		if err != nil {
			log.Printf("failed to read interfaces for reset: %v", err)
			http.Error(w, "failed to read interfaces", http.StatusInternalServerError)
			return
		}
		rows := ifaceTotalsMgr.ResetAllToKernel(netMap)
		if err := store.ReplaceIfaceTotals(r.Context(), rows); err != nil {
			log.Printf("failed to reset interface totals: %v", err)
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}

		stats := getCurrentStats()
		for i := range stats.Interfaces {
			stats.Interfaces[i].RxBytes = 0
			stats.Interfaces[i].TxBytes = 0
		}
		setCurrentStats(stats)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}
}

func parsePositiveInt(raw string, fallback int) int {
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}
