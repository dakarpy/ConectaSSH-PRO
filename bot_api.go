package main

// bot_api.go — /api/bot/* admin endpoints (superadmin).

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
)

var botSettingKeys = map[string]int{
	"welcome_text": 4096,
	"contact_text": 4096,
	"app_text":     4096,
	"app_url":      2048,
}

func botHasControlCharacters(value string) bool {
	return strings.IndexFunc(value, func(r rune) bool {
		return unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t'
	}) >= 0
}

func botHasAnyControlCharacters(value string) bool {
	return strings.IndexFunc(value, unicode.IsControl) >= 0
}

func validateBotPlan(p *BotPlan) error {
	p.Name = strings.TrimSpace(p.Name)
	p.Kind = strings.ToLower(strings.TrimSpace(p.Kind))
	p.XrayProtocol = strings.ToLower(strings.TrimSpace(p.XrayProtocol))
	p.XrayInboundTag = strings.TrimSpace(p.XrayInboundTag)
	p.ServerID = strings.TrimSpace(p.ServerID)
	if p.Name == "" || len(p.Name) > 120 || botHasControlCharacters(p.Name) {
		return fmt.Errorf("plan name must contain 1-120 safe characters")
	}
	if p.Kind != "ssh" && p.Kind != "xray" {
		return fmt.Errorf("plan kind must be ssh or xray")
	}
	if p.Days < 1 || p.Days > 3650 || p.MaxConnections < 0 || p.MaxConnections > 10000 {
		return fmt.Errorf("invalid plan duration or connection limit")
	}
	if p.LimitMbpsUp < 0 || p.LimitMbpsUp > 1000000 || p.LimitMbpsDown < 0 || p.LimitMbpsDown > 1000000 {
		return fmt.Errorf("invalid bandwidth limit")
	}
	if p.PriceCents < 0 || p.PriceCents > 1000000000 || p.CreditCost < 0 || p.CreditCost > 1000000000 {
		return fmt.Errorf("invalid plan price or credit cost")
	}
	if p.Kind == "xray" && p.XrayProtocol != "" && p.XrayProtocol != "vless" && p.XrayProtocol != "vmess" && p.XrayProtocol != "trojan" {
		return fmt.Errorf("invalid Xray protocol")
	}
	if len(p.XrayInboundTag) > 128 || len(p.ServerID) > 128 {
		return fmt.Errorf("inbound tag or server id is too long")
	}
	return nil
}

func validateBotPackage(p *BotCreditPackage) error {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" || len(p.Name) > 120 || botHasControlCharacters(p.Name) {
		return fmt.Errorf("package name must contain 1-120 safe characters")
	}
	if p.Credits < 1 || p.Credits > 1000000000 || p.PriceCents < 0 || p.PriceCents > 1000000000 {
		return fmt.Errorf("invalid package credits or price")
	}
	return nil
}

func botWriteJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func botStoreReady(w http.ResponseWriter, store *Store) bool {
	if store == nil {
		http.Error(w, "database not configured", http.StatusServiceUnavailable)
		return false
	}
	return true
}

// ---------- Config ----------

type botConfigDTO struct {
	Enabled              bool    `json:"enabled"`
	MPConfirmMode        string  `json:"mp_confirm_mode"`
	MPPollInterval       string  `json:"mp_poll_interval"`
	PixExpirationMinutes int     `json:"pix_expiration_minutes"`
	TrialEnabled         bool    `json:"trial_enabled"`
	TrialHours           int     `json:"trial_hours"`
	TrialMaxConnections  int     `json:"trial_max_connections"`
	TrialKind            string  `json:"trial_kind"`
	TrialInboundTag      string  `json:"trial_inbound_tag"`
	AdminTelegramIDs     []int64 `json:"admin_telegram_ids"`
	Currency             string  `json:"currency"`
	PublicHost           string  `json:"public_host"`
	XrayPublicHost       string  `json:"xray_public_host"`
	HasTelegramToken     bool    `json:"has_telegram_token"`
	HasMPAccessToken     bool    `json:"has_mp_access_token"`
	HasMPWebhookSecret   bool    `json:"has_mp_webhook_secret"`
	// Write-only secret fields (empty on GET; empty on POST = keep existing).
	TelegramToken   string `json:"telegram_token"`
	MPAccessToken   string `json:"mp_access_token"`
	MPWebhookSecret string `json:"mp_webhook_secret"`
}

func handleBotConfig(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !botStoreReady(w, store) {
			return
		}
		ctx := r.Context()
		switch r.Method {
		case http.MethodGet:
			cfg, err := LoadBotConfig(ctx, store)
			if err != nil {
				http.Error(w, "load config: "+err.Error(), http.StatusInternalServerError)
				return
			}
			botWriteJSON(w, botConfigDTO{
				Enabled:              cfg.Enabled,
				MPConfirmMode:        cfg.MPConfirmMode,
				MPPollInterval:       cfg.MPPollInterval,
				PixExpirationMinutes: cfg.PixExpirationMinutes,
				TrialEnabled:         cfg.TrialEnabled,
				TrialHours:           cfg.TrialHours,
				TrialMaxConnections:  cfg.TrialMaxConnections,
				TrialKind:            cfg.TrialKind,
				TrialInboundTag:      cfg.TrialInboundTag,
				AdminTelegramIDs:     cfg.AdminTelegramIDs,
				Currency:             cfg.Currency,
				PublicHost:           cfg.PublicHost,
				XrayPublicHost:       cfg.XrayPublicHost,
				HasTelegramToken:     cfg.TelegramToken != "",
				HasMPAccessToken:     cfg.MPAccessToken != "",
				HasMPWebhookSecret:   cfg.MPWebhookSecret != "",
			})
		case http.MethodPost:
			var dto botConfigDTO
			r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
			dec := json.NewDecoder(r.Body)
			dec.DisallowUnknownFields()
			if err := dec.Decode(&dto); err != nil {
				http.Error(w, "invalid json", http.StatusBadRequest)
				return
			}
			dto.MPConfirmMode = strings.ToLower(strings.TrimSpace(dto.MPConfirmMode))
			if dto.MPConfirmMode != "polling" && dto.MPConfirmMode != "webhook" {
				http.Error(w, "confirmation mode must be polling or webhook", http.StatusBadRequest)
				return
			}
			pollInterval, err := time.ParseDuration(strings.TrimSpace(dto.MPPollInterval))
			if err != nil || pollInterval < 5*time.Second || pollInterval > 5*time.Minute {
				http.Error(w, "poll interval must be between 5s and 5m", http.StatusBadRequest)
				return
			}
			if dto.PixExpirationMinutes < 5 || dto.PixExpirationMinutes > 1440 || dto.TrialHours < 1 || dto.TrialHours > 720 || dto.TrialMaxConnections < 1 || dto.TrialMaxConnections > 1000 {
				http.Error(w, "invalid PIX expiration or trial limits", http.StatusBadRequest)
				return
			}
			dto.TrialKind = strings.ToLower(strings.TrimSpace(dto.TrialKind))
			if dto.TrialKind != "ssh" && dto.TrialKind != "xray" {
				http.Error(w, "trial kind must be ssh or xray", http.StatusBadRequest)
				return
			}
			if len(dto.AdminTelegramIDs) > 100 {
				http.Error(w, "too many admin Telegram IDs", http.StatusBadRequest)
				return
			}
			for _, id := range dto.AdminTelegramIDs {
				if id <= 0 {
					http.Error(w, "admin Telegram IDs must be positive", http.StatusBadRequest)
					return
				}
			}
			for _, value := range []string{dto.TelegramToken, dto.MPAccessToken, dto.MPWebhookSecret, dto.PublicHost, dto.XrayPublicHost, dto.TrialInboundTag} {
				if len(value) > 2048 || botHasAnyControlCharacters(value) {
					http.Error(w, "configuration contains an invalid value", http.StatusBadRequest)
					return
				}
			}
			existing, err := LoadBotConfig(ctx, store)
			if err != nil {
				http.Error(w, "load existing config", http.StatusInternalServerError)
				return
			}
			effectiveTelegramToken := strings.TrimSpace(dto.TelegramToken)
			if effectiveTelegramToken == "" {
				effectiveTelegramToken = existing.TelegramToken
			}
			if dto.Enabled && effectiveTelegramToken == "" {
				http.Error(w, "Telegram token is required before enabling the bot", http.StatusBadRequest)
				return
			}
			effectiveWebhookSecret := strings.TrimSpace(dto.MPWebhookSecret)
			if effectiveWebhookSecret == "" {
				effectiveWebhookSecret = existing.MPWebhookSecret
			}
			if dto.MPConfirmMode == "webhook" && len(effectiveWebhookSecret) < 16 {
				http.Error(w, "a webhook secret of at least 16 characters is required", http.StatusBadRequest)
				return
			}
			cfg := &BotConfig{
				Enabled:              dto.Enabled,
				TelegramToken:        strings.TrimSpace(dto.TelegramToken),
				MPAccessToken:        strings.TrimSpace(dto.MPAccessToken),
				MPConfirmMode:        dto.MPConfirmMode,
				MPWebhookSecret:      strings.TrimSpace(dto.MPWebhookSecret),
				MPPollInterval:       dto.MPPollInterval,
				PixExpirationMinutes: dto.PixExpirationMinutes,
				TrialEnabled:         dto.TrialEnabled,
				TrialHours:           dto.TrialHours,
				TrialMaxConnections:  dto.TrialMaxConnections,
				TrialKind:            dto.TrialKind,
				TrialInboundTag:      strings.TrimSpace(dto.TrialInboundTag),
				AdminTelegramIDs:     dto.AdminTelegramIDs,
				Currency:             dto.Currency,
				PublicHost:           strings.TrimSpace(dto.PublicHost),
				XrayPublicHost:       strings.TrimSpace(dto.XrayPublicHost),
			}
			if err := SaveBotConfig(ctx, store, cfg); err != nil {
				http.Error(w, "save config: "+err.Error(), http.StatusInternalServerError)
				return
			}
			reloadBotService(store)
			botWriteJSON(w, map[string]bool{"ok": true})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

// ---------- Plans ----------

func handleBotPlans(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !botStoreReady(w, store) {
			return
		}
		ctx := r.Context()
		switch r.Method {
		case http.MethodGet:
			plans, err := store.ListPlans(ctx, false)
			if err != nil {
				http.Error(w, "db error", http.StatusInternalServerError)
				return
			}
			botWriteJSON(w, plans)
		case http.MethodPost:
			var p BotPlan
			if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
				http.Error(w, "invalid json", http.StatusBadRequest)
				return
			}
			if p.Kind == "" {
				p.Kind = "ssh"
			}
			if err := validateBotPlan(&p); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if err := store.UpsertPlan(ctx, &p); err != nil {
				http.Error(w, "db error: "+err.Error(), http.StatusInternalServerError)
				return
			}
			botWriteJSON(w, p)
		case http.MethodDelete:
			id, _ := strconv.Atoi(r.URL.Query().Get("id"))
			if id <= 0 {
				http.Error(w, "invalid id", http.StatusBadRequest)
				return
			}
			if err := store.DeletePlan(ctx, id); err != nil {
				http.Error(w, "db error", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

// ---------- Credit packages ----------

func handleBotCreditPackages(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !botStoreReady(w, store) {
			return
		}
		ctx := r.Context()
		switch r.Method {
		case http.MethodGet:
			pkgs, err := store.ListCreditPackages(ctx, false)
			if err != nil {
				http.Error(w, "db error", http.StatusInternalServerError)
				return
			}
			botWriteJSON(w, pkgs)
		case http.MethodPost:
			var p BotCreditPackage
			if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
				http.Error(w, "invalid json", http.StatusBadRequest)
				return
			}
			if err := validateBotPackage(&p); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if err := store.UpsertCreditPackage(ctx, &p); err != nil {
				http.Error(w, "db error", http.StatusInternalServerError)
				return
			}
			botWriteJSON(w, p)
		case http.MethodDelete:
			id, _ := strconv.Atoi(r.URL.Query().Get("id"))
			if id <= 0 {
				http.Error(w, "invalid id", http.StatusBadRequest)
				return
			}
			if err := store.DeleteCreditPackage(ctx, id); err != nil {
				http.Error(w, "db error", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

// ---------- Bot users ----------

func handleBotUsers(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !botStoreReady(w, store) {
			return
		}
		ctx := r.Context()
		switch r.Method {
		case http.MethodGet:
			users, err := store.ListBotUsers(ctx)
			if err != nil {
				http.Error(w, "db error", http.StatusInternalServerError)
				return
			}
			botWriteJSON(w, users)
		case http.MethodPost:
			var req struct {
				TelegramID          int64  `json:"telegram_id"`
				Action              string `json:"action"`
				Role                string `json:"role"`
				LinkedAdminUsername string `json:"linked_admin_username"`
				Credits             int    `json:"credits"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.TelegramID == 0 {
				http.Error(w, "invalid json", http.StatusBadRequest)
				return
			}
			switch req.Action {
			case "set_role":
				if req.Role == "" {
					req.Role = "customer"
				}
				req.Role = strings.ToLower(strings.TrimSpace(req.Role))
				if req.Role != "customer" && req.Role != "reseller" && req.Role != "blocked" {
					http.Error(w, "role must be customer, reseller, or blocked", http.StatusBadRequest)
					return
				}
				req.LinkedAdminUsername = strings.TrimSpace(req.LinkedAdminUsername)
				if req.Role == "reseller" {
					linked, err := store.GetAdminUserByUsername(ctx, req.LinkedAdminUsername)
					if err != nil || linked == nil || linked.Role != RoleReseller {
						http.Error(w, "linked reseller account not found", http.StatusBadRequest)
						return
					}
				} else {
					req.LinkedAdminUsername = ""
				}
				if err := store.SetBotUserRole(ctx, req.TelegramID, req.Role, req.LinkedAdminUsername); err != nil {
					http.Error(w, "db error", http.StatusInternalServerError)
					return
				}
			case "block":
				if err := store.SetBotUserRole(ctx, req.TelegramID, "blocked", ""); err != nil {
					http.Error(w, "db error", http.StatusInternalServerError)
					return
				}
			case "unblock":
				if err := store.SetBotUserRole(ctx, req.TelegramID, "customer", ""); err != nil {
					http.Error(w, "db error", http.StatusInternalServerError)
					return
				}
			case "adjust_credits":
				if req.Credits == 0 || req.Credits < -1000000000 || req.Credits > 1000000000 {
					http.Error(w, "invalid credit adjustment", http.StatusBadRequest)
					return
				}
				if _, err := store.AdjustCredits(ctx, req.TelegramID, req.Credits, "admin_adjust", nil); err != nil {
					http.Error(w, "adjust: "+err.Error(), http.StatusBadRequest)
					return
				}
			default:
				http.Error(w, "unknown action", http.StatusBadRequest)
				return
			}
			botWriteJSON(w, map[string]bool{"ok": true})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

// ---------- Transactions ----------

func handleBotTransactions(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !botStoreReady(w, store) {
			return
		}
		ctx := r.Context()
		switch r.Method {
		case http.MethodGet:
			status := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))
			if status != "" && status != "pending" && status != "approved" && status != "expired" && status != "refunded" && status != "error" {
				http.Error(w, "invalid status", http.StatusBadRequest)
				return
			}
			limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
			if limit <= 0 {
				limit = 200
			}
			if limit > 500 {
				limit = 500
			}
			txns, err := store.ListTransactions(ctx, status, limit)
			if err != nil {
				http.Error(w, "db error", http.StatusInternalServerError)
				return
			}
			botWriteJSON(w, txns)
		case http.MethodPost:
			var req struct {
				ID     int    `json:"id"`
				Action string `json:"action"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == 0 {
				http.Error(w, "invalid json", http.StatusBadRequest)
				return
			}
			switch req.Action {
			case "refund":
				if err := store.SetTransactionStatus(ctx, req.ID, "refunded"); err != nil {
					http.Error(w, "db error", http.StatusInternalServerError)
					return
				}
			case "reprocess":
				if b := currentBot(); b != nil {
					go b.tryFulfill(req.ID)
				} else {
					http.Error(w, "bot not running", http.StatusServiceUnavailable)
					return
				}
			default:
				http.Error(w, "unknown action", http.StatusBadRequest)
				return
			}
			botWriteJSON(w, map[string]bool{"ok": true})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

// ---------- Settings (bot texts) ----------

func handleBotSettings(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !botStoreReady(w, store) {
			return
		}
		ctx := r.Context()
		switch r.Method {
		case http.MethodGet:
			all, err := store.AllSettings(ctx)
			if err != nil {
				http.Error(w, "db error", http.StatusInternalServerError)
				return
			}
			botWriteJSON(w, all)
		case http.MethodPost:
			var kv map[string]string
			if err := json.NewDecoder(r.Body).Decode(&kv); err != nil {
				http.Error(w, "invalid json", http.StatusBadRequest)
				return
			}
			for k, v := range kv {
				maxLen, ok := botSettingKeys[k]
				if !ok || len(v) > maxLen || botHasControlCharacters(v) {
					http.Error(w, "invalid bot setting", http.StatusBadRequest)
					return
				}
				if k == "app_url" && strings.TrimSpace(v) != "" {
					u, err := url.ParseRequestURI(strings.TrimSpace(v))
					if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
						http.Error(w, "app_url must be an http or https URL", http.StatusBadRequest)
						return
					}
				}
				if err := store.SetSetting(ctx, k, v); err != nil {
					http.Error(w, "db error", http.StatusInternalServerError)
					return
				}
			}
			botWriteJSON(w, map[string]bool{"ok": true})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

// ---------- Connectivity test ----------

func handleBotTest(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !botStoreReady(w, store) {
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		ctx := r.Context()
		var req struct {
			TelegramToken string `json:"telegram_token"`
			MPAccessToken string `json:"mp_access_token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		cfg, _ := LoadBotConfig(ctx, store)
		tgToken := strings.TrimSpace(req.TelegramToken)
		mpToken := strings.TrimSpace(req.MPAccessToken)
		if cfg != nil {
			if tgToken == "" {
				tgToken = cfg.TelegramToken
			}
			if mpToken == "" {
				mpToken = cfg.MPAccessToken
			}
		}
		out := map[string]interface{}{}
		if tgToken != "" {
			name, err := newTGClient(tgToken).getMe(ctx)
			if err != nil {
				out["telegram_ok"] = false
				out["telegram_error"] = err.Error()
			} else {
				out["telegram_ok"] = true
				out["telegram_bot"] = "@" + name
			}
		} else {
			out["telegram_ok"] = false
			out["telegram_error"] = "no token configured"
		}
		if mpToken != "" {
			_, err := newMPClient(mpToken).do(ctx, http.MethodGet, "/v1/payment_methods", nil, "")
			if err != nil {
				out["mp_ok"] = false
				out["mp_error"] = err.Error()
			} else {
				out["mp_ok"] = true
			}
		} else {
			out["mp_ok"] = false
			out["mp_error"] = "no token configured"
		}
		botWriteJSON(w, out)
	}
}
