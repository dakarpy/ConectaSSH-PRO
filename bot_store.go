package main

// bot_store.go — PostgreSQL persistence for the Telegram sales bot.
//
// Tables (all created idempotently by EnsureBotSchema):
//   bot_users            — Telegram customers/resellers
//   bot_plans            — sellable SSH/Xray plans
//   bot_credit_packages  — reseller credit top-up packages
//   bot_transactions     — PIX payments (Mercado Pago)
//   bot_credits_ledger   — auditable credit movements
//   bot_settings         — editable bot texts (key/value)
//   bot_config           — single-row bot config with encrypted secrets

import (
	"context"
	"database/sql"
	"time"

	"github.com/lib/pq"
)

// ---------- Models ----------

type BotUser struct {
	TelegramID          int64
	Username            string
	FirstName           string
	Role                string // customer | reseller | blocked
	LinkedAdminUsername string
	CreditBalance       int
	TrialUsed           bool
	CreatedAt           time.Time
	LastSeenAt          time.Time
}

type BotPlan struct {
	ID             int
	Name           string
	Kind           string // ssh | xray
	Days           int
	MaxConnections int
	LimitMbpsUp    int
	LimitMbpsDown  int
	XrayInboundTag string
	XrayProtocol   string
	PriceCents     int
	CreditCost     int
	ServerID       string
	IsActive       bool
	SortOrder      int
}

type BotCreditPackage struct {
	ID         int
	Name       string
	Credits    int
	PriceCents int
	IsActive   bool
	SortOrder  int
}

type BotTransaction struct {
	ID             int
	TelegramID     int64
	Type           string // plan_purchase | plan_renewal | credit_topup
	PlanID         *int
	PackageID      *int
	Credits        int
	AmountCents    int
	MPPaymentID    string
	MPQRCode       string
	MPQRBase64     string
	Status         string // pending | approved | expired | refunded | error
	TargetUsername string // account/uuid created or renewed
	RenewTarget    string // for renewals: existing account/uuid to extend
	CreatedAt      time.Time
	PaidAt         *time.Time
	ExpiresAt      *time.Time
}

type BotLedgerEntry struct {
	ID           int
	TelegramID   int64
	Delta        int
	Reason       string
	RefTxnID     *int
	BalanceAfter int
	CreatedAt    time.Time
}

// ---------- Schema ----------

func (s *Store) EnsureBotSchema(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS bot_users (
			telegram_id            BIGINT PRIMARY KEY,
			username               TEXT NOT NULL DEFAULT '',
			first_name             TEXT NOT NULL DEFAULT '',
			role                   TEXT NOT NULL DEFAULT 'customer',
			linked_admin_username  TEXT NOT NULL DEFAULT '',
			credit_balance         INT NOT NULL DEFAULT 0,
			trial_used             BOOLEAN NOT NULL DEFAULT false,
			created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			last_seen_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS bot_plans (
			id               SERIAL PRIMARY KEY,
			name             TEXT NOT NULL DEFAULT '',
			kind             TEXT NOT NULL DEFAULT 'ssh',
			days             INT NOT NULL DEFAULT 30,
			max_connections  INT NOT NULL DEFAULT 1,
			limit_mbps_up    INT NOT NULL DEFAULT 0,
			limit_mbps_down  INT NOT NULL DEFAULT 0,
			xray_inbound_tag TEXT NOT NULL DEFAULT '',
			xray_protocol    TEXT NOT NULL DEFAULT '',
			price_cents      INT NOT NULL DEFAULT 0,
			credit_cost      INT NOT NULL DEFAULT 1,
			server_id        TEXT NOT NULL DEFAULT '',
			is_active        BOOLEAN NOT NULL DEFAULT true,
			sort_order       INT NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS bot_credit_packages (
			id           SERIAL PRIMARY KEY,
			name         TEXT NOT NULL DEFAULT '',
			credits      INT NOT NULL DEFAULT 0,
			price_cents  INT NOT NULL DEFAULT 0,
			is_active    BOOLEAN NOT NULL DEFAULT true,
			sort_order   INT NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS bot_transactions (
			id               SERIAL PRIMARY KEY,
			telegram_id      BIGINT NOT NULL,
			type             TEXT NOT NULL,
			plan_id          INT,
			package_id       INT,
			credits          INT NOT NULL DEFAULT 0,
			amount_cents     INT NOT NULL DEFAULT 0,
			mp_payment_id    TEXT NOT NULL DEFAULT '',
			mp_qr_code       TEXT NOT NULL DEFAULT '',
			mp_qr_base64     TEXT NOT NULL DEFAULT '',
			status           TEXT NOT NULL DEFAULT 'pending',
			target_username  TEXT NOT NULL DEFAULT '',
			renew_target     TEXT NOT NULL DEFAULT '',
			created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			paid_at          TIMESTAMPTZ,
			expires_at       TIMESTAMPTZ
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS bot_transactions_mp_payment_id_uidx
			ON bot_transactions (mp_payment_id) WHERE mp_payment_id <> ''`,
		`CREATE TABLE IF NOT EXISTS bot_credits_ledger (
			id                 SERIAL PRIMARY KEY,
			telegram_id        BIGINT NOT NULL,
			delta              INT NOT NULL,
			reason             TEXT NOT NULL DEFAULT '',
			ref_transaction_id INT,
			balance_after      INT NOT NULL DEFAULT 0,
			created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS bot_settings (
			key    TEXT PRIMARY KEY,
			value  TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS bot_config (
			id                          INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
			enabled                     BOOLEAN NOT NULL DEFAULT false,
			telegram_mode               TEXT NOT NULL DEFAULT 'polling',
			telegram_webhook_url        TEXT NOT NULL DEFAULT '',
			mp_confirm_mode             TEXT NOT NULL DEFAULT 'polling',
			mp_poll_interval            TEXT NOT NULL DEFAULT '20s',
			pix_expiration_minutes      INT NOT NULL DEFAULT 30,
			trial_enabled               BOOLEAN NOT NULL DEFAULT true,
			trial_hours                 INT NOT NULL DEFAULT 1,
			trial_max_connections       INT NOT NULL DEFAULT 1,
			trial_kind                  TEXT NOT NULL DEFAULT 'ssh',
			trial_inbound_tag           TEXT NOT NULL DEFAULT '',
			admin_telegram_ids          BIGINT[] NOT NULL DEFAULT '{}',
			currency                    TEXT NOT NULL DEFAULT 'BRL',
			public_host                 TEXT NOT NULL DEFAULT '',
			xray_public_host            TEXT NOT NULL DEFAULT '',
			telegram_token_enc          BYTEA,
			telegram_webhook_secret_enc BYTEA,
			mp_access_token_enc         BYTEA,
			mp_webhook_secret_enc       BYTEA,
			updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`INSERT INTO bot_config (id) VALUES (1) ON CONFLICT (id) DO NOTHING`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

// ---------- bot_users ----------

// UpsertBotUser inserts a user or refreshes username/first_name/last_seen.
// Role, credits, linkage and trial_used are preserved on update.
func (s *Store) UpsertBotUser(ctx context.Context, u *BotUser) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO bot_users (telegram_id, username, first_name, last_seen_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (telegram_id) DO UPDATE
		SET username = EXCLUDED.username,
		    first_name = EXCLUDED.first_name,
		    last_seen_at = NOW()`,
		u.TelegramID, u.Username, u.FirstName)
	return err
}

func scanBotUser(row interface{ Scan(...interface{}) error }) (*BotUser, error) {
	var u BotUser
	err := row.Scan(&u.TelegramID, &u.Username, &u.FirstName, &u.Role,
		&u.LinkedAdminUsername, &u.CreditBalance, &u.TrialUsed, &u.CreatedAt, &u.LastSeenAt)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

const botUserCols = `telegram_id, username, first_name, role, linked_admin_username, credit_balance, trial_used, created_at, last_seen_at`

func (s *Store) GetBotUser(ctx context.Context, telegramID int64) (*BotUser, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+botUserCols+` FROM bot_users WHERE telegram_id=$1`, telegramID)
	return scanBotUser(row)
}

func (s *Store) ListBotUsers(ctx context.Context) ([]*BotUser, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+botUserCols+` FROM bot_users ORDER BY last_seen_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*BotUser
	for rows.Next() {
		u, err := scanBotUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// SetBotUserRole updates role and reseller linkage.
func (s *Store) SetBotUserRole(ctx context.Context, telegramID int64, role, linkedAdmin string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE bot_users SET role=$2, linked_admin_username=$3 WHERE telegram_id=$1`,
		telegramID, role, linkedAdmin)
	return err
}

func (s *Store) SetBotUserTrialUsed(ctx context.Context, telegramID int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE bot_users SET trial_used=true WHERE telegram_id=$1`, telegramID)
	return err
}

// AdjustCredits changes a reseller's balance atomically and writes a ledger row.
// Returns the resulting balance. Fails (rolls back) if the balance would go negative.
func (s *Store) AdjustCredits(ctx context.Context, telegramID int64, delta int, reason string, refTxn *int) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var balance int
	if err := tx.QueryRowContext(ctx,
		`UPDATE bot_users SET credit_balance = credit_balance + $2
		 WHERE telegram_id=$1 RETURNING credit_balance`,
		telegramID, delta).Scan(&balance); err != nil {
		return 0, err
	}
	if balance < 0 {
		return 0, errInsufficientCredits
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO bot_credits_ledger (telegram_id, delta, reason, ref_transaction_id, balance_after)
		 VALUES ($1,$2,$3,$4,$5)`,
		telegramID, delta, reason, refTxn, balance); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return balance, nil
}

func (s *Store) ListLedger(ctx context.Context, telegramID int64, limit int) ([]*BotLedgerEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, telegram_id, delta, reason, ref_transaction_id, balance_after, created_at
		 FROM bot_credits_ledger WHERE telegram_id=$1 ORDER BY id DESC LIMIT $2`, telegramID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*BotLedgerEntry
	for rows.Next() {
		var e BotLedgerEntry
		if err := rows.Scan(&e.ID, &e.TelegramID, &e.Delta, &e.Reason, &e.RefTxnID, &e.BalanceAfter, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}

// ---------- bot_plans ----------

const botPlanCols = `id, name, kind, days, max_connections, limit_mbps_up, limit_mbps_down, xray_inbound_tag, xray_protocol, price_cents, credit_cost, server_id, is_active, sort_order`

func scanBotPlan(row interface{ Scan(...interface{}) error }) (*BotPlan, error) {
	var p BotPlan
	err := row.Scan(&p.ID, &p.Name, &p.Kind, &p.Days, &p.MaxConnections, &p.LimitMbpsUp, &p.LimitMbpsDown,
		&p.XrayInboundTag, &p.XrayProtocol, &p.PriceCents, &p.CreditCost, &p.ServerID, &p.IsActive, &p.SortOrder)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *Store) ListPlans(ctx context.Context, onlyActive bool) ([]*BotPlan, error) {
	q := `SELECT ` + botPlanCols + ` FROM bot_plans`
	if onlyActive {
		q += ` WHERE is_active=true`
	}
	q += ` ORDER BY sort_order, id`
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*BotPlan
	for rows.Next() {
		p, err := scanBotPlan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) GetPlan(ctx context.Context, id int) (*BotPlan, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+botPlanCols+` FROM bot_plans WHERE id=$1`, id)
	return scanBotPlan(row)
}

func (s *Store) UpsertPlan(ctx context.Context, p *BotPlan) error {
	if p.ID == 0 {
		return s.db.QueryRowContext(ctx, `
			INSERT INTO bot_plans (name, kind, days, max_connections, limit_mbps_up, limit_mbps_down,
				xray_inbound_tag, xray_protocol, price_cents, credit_cost, server_id, is_active, sort_order)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING id`,
			p.Name, p.Kind, p.Days, p.MaxConnections, p.LimitMbpsUp, p.LimitMbpsDown,
			p.XrayInboundTag, p.XrayProtocol, p.PriceCents, p.CreditCost, p.ServerID, p.IsActive, p.SortOrder,
		).Scan(&p.ID)
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE bot_plans SET name=$2, kind=$3, days=$4, max_connections=$5, limit_mbps_up=$6, limit_mbps_down=$7,
			xray_inbound_tag=$8, xray_protocol=$9, price_cents=$10, credit_cost=$11, server_id=$12, is_active=$13, sort_order=$14
		WHERE id=$1`,
		p.ID, p.Name, p.Kind, p.Days, p.MaxConnections, p.LimitMbpsUp, p.LimitMbpsDown,
		p.XrayInboundTag, p.XrayProtocol, p.PriceCents, p.CreditCost, p.ServerID, p.IsActive, p.SortOrder)
	return err
}

func (s *Store) DeletePlan(ctx context.Context, id int) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM bot_plans WHERE id=$1`, id)
	return err
}

// ---------- bot_credit_packages ----------

const botPkgCols = `id, name, credits, price_cents, is_active, sort_order`

func scanBotPkg(row interface{ Scan(...interface{}) error }) (*BotCreditPackage, error) {
	var p BotCreditPackage
	if err := row.Scan(&p.ID, &p.Name, &p.Credits, &p.PriceCents, &p.IsActive, &p.SortOrder); err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *Store) ListCreditPackages(ctx context.Context, onlyActive bool) ([]*BotCreditPackage, error) {
	q := `SELECT ` + botPkgCols + ` FROM bot_credit_packages`
	if onlyActive {
		q += ` WHERE is_active=true`
	}
	q += ` ORDER BY sort_order, id`
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*BotCreditPackage
	for rows.Next() {
		p, err := scanBotPkg(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) GetCreditPackage(ctx context.Context, id int) (*BotCreditPackage, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+botPkgCols+` FROM bot_credit_packages WHERE id=$1`, id)
	return scanBotPkg(row)
}

func (s *Store) UpsertCreditPackage(ctx context.Context, p *BotCreditPackage) error {
	if p.ID == 0 {
		return s.db.QueryRowContext(ctx,
			`INSERT INTO bot_credit_packages (name, credits, price_cents, is_active, sort_order)
			 VALUES ($1,$2,$3,$4,$5) RETURNING id`,
			p.Name, p.Credits, p.PriceCents, p.IsActive, p.SortOrder).Scan(&p.ID)
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE bot_credit_packages SET name=$2, credits=$3, price_cents=$4, is_active=$5, sort_order=$6 WHERE id=$1`,
		p.ID, p.Name, p.Credits, p.PriceCents, p.IsActive, p.SortOrder)
	return err
}

func (s *Store) DeleteCreditPackage(ctx context.Context, id int) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM bot_credit_packages WHERE id=$1`, id)
	return err
}

// ---------- bot_transactions ----------

const botTxnCols = `id, telegram_id, type, plan_id, package_id, credits, amount_cents, mp_payment_id, mp_qr_code, mp_qr_base64, status, target_username, renew_target, created_at, paid_at, expires_at`

func scanBotTxn(row interface{ Scan(...interface{}) error }) (*BotTransaction, error) {
	var t BotTransaction
	err := row.Scan(&t.ID, &t.TelegramID, &t.Type, &t.PlanID, &t.PackageID, &t.Credits, &t.AmountCents,
		&t.MPPaymentID, &t.MPQRCode, &t.MPQRBase64, &t.Status, &t.TargetUsername, &t.RenewTarget,
		&t.CreatedAt, &t.PaidAt, &t.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Store) CreateTransaction(ctx context.Context, t *BotTransaction) error {
	return s.db.QueryRowContext(ctx, `
		INSERT INTO bot_transactions (telegram_id, type, plan_id, package_id, credits, amount_cents,
			mp_payment_id, mp_qr_code, mp_qr_base64, status, target_username, renew_target, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING id, created_at`,
		t.TelegramID, t.Type, t.PlanID, t.PackageID, t.Credits, t.AmountCents,
		t.MPPaymentID, t.MPQRCode, t.MPQRBase64, t.Status, t.TargetUsername, t.RenewTarget, t.ExpiresAt,
	).Scan(&t.ID, &t.CreatedAt)
}

func (s *Store) GetTransaction(ctx context.Context, id int) (*BotTransaction, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+botTxnCols+` FROM bot_transactions WHERE id=$1`, id)
	return scanBotTxn(row)
}

func (s *Store) GetTransactionByMPID(ctx context.Context, mpID string) (*BotTransaction, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+botTxnCols+` FROM bot_transactions WHERE mp_payment_id=$1`, mpID)
	return scanBotTxn(row)
}

func (s *Store) ListPendingTransactions(ctx context.Context) ([]*BotTransaction, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+botTxnCols+` FROM bot_transactions WHERE status='pending' AND mp_payment_id <> '' ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*BotTransaction
	for rows.Next() {
		t, err := scanBotTxn(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) ListUserTransactions(ctx context.Context, telegramID int64, limit int) ([]*BotTransaction, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+botTxnCols+` FROM bot_transactions WHERE telegram_id=$1 ORDER BY id DESC LIMIT $2`, telegramID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*BotTransaction
	for rows.Next() {
		t, err := scanBotTxn(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) ListTransactions(ctx context.Context, status string, limit int) ([]*BotTransaction, error) {
	if limit <= 0 {
		limit = 200
	}
	var rows *sql.Rows
	var err error
	if status != "" {
		rows, err = s.db.QueryContext(ctx, `SELECT `+botTxnCols+` FROM bot_transactions WHERE status=$1 ORDER BY id DESC LIMIT $2`, status, limit)
	} else {
		rows, err = s.db.QueryContext(ctx, `SELECT `+botTxnCols+` FROM bot_transactions ORDER BY id DESC LIMIT $1`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*BotTransaction
	for rows.Next() {
		t, err := scanBotTxn(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// MarkTransactionApproved atomically flips a pending txn to approved. It returns
// true only for the caller that actually performed the transition, giving
// idempotent delivery even if webhook and poller race.
func (s *Store) MarkTransactionApproved(ctx context.Context, id int) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE bot_transactions SET status='approved', paid_at=NOW() WHERE id=$1 AND status='pending'`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (s *Store) SetTransactionStatus(ctx context.Context, id int, status string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE bot_transactions SET status=$2 WHERE id=$1`, id, status)
	return err
}

func (s *Store) SetTransactionTarget(ctx context.Context, id int, target string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE bot_transactions SET target_username=$2 WHERE id=$1`, id, target)
	return err
}

// ---------- bot_settings ----------

func (s *Store) GetSetting(ctx context.Context, key, def string) string {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM bot_settings WHERE key=$1`, key).Scan(&v)
	if err != nil {
		return def
	}
	return v
}

func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO bot_settings (key, value) VALUES ($1,$2)
		 ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value`, key, value)
	return err
}

func (s *Store) AllSettings(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, value FROM bot_settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// ---------- bot_config (row) ----------

// botConfigRow mirrors the DB row; secrets stay encrypted here.
type botConfigRow struct {
	Enabled                  bool
	TelegramMode             string
	TelegramWebhookURL       string
	MPConfirmMode            string
	MPPollInterval           string
	PixExpirationMinutes     int
	TrialEnabled             bool
	TrialHours               int
	TrialMaxConnections      int
	TrialKind                string
	TrialInboundTag          string
	AdminTelegramIDs         []int64
	Currency                 string
	PublicHost               string
	XrayPublicHost           string
	TelegramTokenEnc         []byte
	TelegramWebhookSecretEnc []byte
	MPAccessTokenEnc         []byte
	MPWebhookSecretEnc       []byte
}

func (s *Store) getBotConfigRow(ctx context.Context) (*botConfigRow, error) {
	var r botConfigRow
	var ids pq.Int64Array
	err := s.db.QueryRowContext(ctx, `
		SELECT enabled, telegram_mode, telegram_webhook_url, mp_confirm_mode, mp_poll_interval,
			pix_expiration_minutes, trial_enabled, trial_hours, trial_max_connections, trial_kind,
			trial_inbound_tag, admin_telegram_ids, currency, public_host, xray_public_host,
			telegram_token_enc, telegram_webhook_secret_enc, mp_access_token_enc, mp_webhook_secret_enc
		FROM bot_config WHERE id=1`).Scan(
		&r.Enabled, &r.TelegramMode, &r.TelegramWebhookURL, &r.MPConfirmMode, &r.MPPollInterval,
		&r.PixExpirationMinutes, &r.TrialEnabled, &r.TrialHours, &r.TrialMaxConnections, &r.TrialKind,
		&r.TrialInboundTag, &ids, &r.Currency, &r.PublicHost, &r.XrayPublicHost,
		&r.TelegramTokenEnc, &r.TelegramWebhookSecretEnc, &r.MPAccessTokenEnc, &r.MPWebhookSecretEnc)
	if err != nil {
		return nil, err
	}
	r.AdminTelegramIDs = []int64(ids)
	return &r, nil
}

// saveBotConfigRow writes the non-secret fields plus any encrypted blobs that
// are non-nil (nil blob = keep existing secret).
func (s *Store) saveBotConfigRow(ctx context.Context, r *botConfigRow, tokEnc, tgSecEnc, mpEnc, mpSecEnc []byte) error {
	set := `enabled=$1, telegram_mode=$2, telegram_webhook_url=$3, mp_confirm_mode=$4, mp_poll_interval=$5,
		pix_expiration_minutes=$6, trial_enabled=$7, trial_hours=$8, trial_max_connections=$9, trial_kind=$10,
		trial_inbound_tag=$11, admin_telegram_ids=$12, currency=$13, public_host=$14, xray_public_host=$15,
		updated_at=NOW()`
	args := []interface{}{
		r.Enabled, r.TelegramMode, r.TelegramWebhookURL, r.MPConfirmMode, r.MPPollInterval,
		r.PixExpirationMinutes, r.TrialEnabled, r.TrialHours, r.TrialMaxConnections, r.TrialKind,
		r.TrialInboundTag, pq.Array(r.AdminTelegramIDs), r.Currency, r.PublicHost, r.XrayPublicHost,
	}
	n := len(args)
	if tokEnc != nil {
		n++
		set += `, telegram_token_enc=$` + botItoa(n)
		args = append(args, tokEnc)
	}
	if tgSecEnc != nil {
		n++
		set += `, telegram_webhook_secret_enc=$` + botItoa(n)
		args = append(args, tgSecEnc)
	}
	if mpEnc != nil {
		n++
		set += `, mp_access_token_enc=$` + botItoa(n)
		args = append(args, mpEnc)
	}
	if mpSecEnc != nil {
		n++
		set += `, mp_webhook_secret_enc=$` + botItoa(n)
		args = append(args, mpSecEnc)
	}
	_, err := s.db.ExecContext(ctx, `UPDATE bot_config SET `+set+` WHERE id=1`, args...)
	return err
}
