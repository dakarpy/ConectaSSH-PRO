package main

// bot_config.go — in-memory bot configuration loaded from the bot_config table.
// Secrets are decrypted here and never persisted in plaintext.

import (
	"context"
	"errors"
	"strconv"
)

var errInsufficientCredits = errors.New("insufficient credits")

func botItoa(n int) string { return strconv.Itoa(n) }

// BotConfig is the decrypted, ready-to-use bot configuration.
// Telegram always uses long-polling (no webhook). The webhook/polling toggle
// applies only to Mercado Pago payment confirmation (MPConfirmMode).
type BotConfig struct {
	Enabled              bool
	TelegramToken        string
	MPAccessToken        string
	MPConfirmMode        string // webhook | polling
	MPWebhookSecret      string
	MPPollInterval       string
	PixExpirationMinutes int
	TrialEnabled         bool
	TrialHours           int
	TrialMaxConnections  int
	TrialKind            string // ssh | xray
	TrialInboundTag      string
	AdminTelegramIDs     []int64
	Currency             string
	PublicHost           string // SSH connection host shown to buyers
	XrayPublicHost       string // host used to build vless/vmess links
}

// LoadBotConfig reads the config row and decrypts secrets into a BotConfig.
func LoadBotConfig(ctx context.Context, store *Store) (*BotConfig, error) {
	r, err := store.getBotConfigRow(ctx)
	if err != nil {
		return nil, err
	}
	tok, err := decryptSecret(r.TelegramTokenEnc)
	if err != nil {
		return nil, err
	}
	mp, err := decryptSecret(r.MPAccessTokenEnc)
	if err != nil {
		return nil, err
	}
	mpSec, err := decryptSecret(r.MPWebhookSecretEnc)
	if err != nil {
		return nil, err
	}

	cfg := &BotConfig{
		Enabled:              r.Enabled,
		TelegramToken:        tok,
		MPAccessToken:        mp,
		MPConfirmMode:        r.MPConfirmMode,
		MPWebhookSecret:      mpSec,
		MPPollInterval:       r.MPPollInterval,
		PixExpirationMinutes: r.PixExpirationMinutes,
		TrialEnabled:         r.TrialEnabled,
		TrialHours:           r.TrialHours,
		TrialMaxConnections:  r.TrialMaxConnections,
		TrialKind:            r.TrialKind,
		TrialInboundTag:      r.TrialInboundTag,
		AdminTelegramIDs:     r.AdminTelegramIDs,
		Currency:             r.Currency,
		PublicHost:           r.PublicHost,
		XrayPublicHost:       r.XrayPublicHost,
	}
	cfg.applyDefaults()
	return cfg, nil
}

func (c *BotConfig) applyDefaults() {
	if c.MPConfirmMode == "" {
		c.MPConfirmMode = "polling"
	}
	if c.MPPollInterval == "" {
		c.MPPollInterval = "20s"
	}
	if c.PixExpirationMinutes <= 0 {
		c.PixExpirationMinutes = 30
	}
	if c.TrialHours <= 0 {
		c.TrialHours = 1
	}
	if c.TrialMaxConnections <= 0 {
		c.TrialMaxConnections = 1
	}
	if c.TrialKind == "" {
		c.TrialKind = "ssh"
	}
	if c.Currency == "" {
		c.Currency = "BRL"
	}
}

func (c *BotConfig) isAdmin(telegramID int64) bool {
	for _, id := range c.AdminTelegramIDs {
		if id == telegramID {
			return true
		}
	}
	return false
}

// SaveBotConfig persists a BotConfig. Empty secret fields preserve the stored
// value (nil blob → column left unchanged).
func SaveBotConfig(ctx context.Context, store *Store, cfg *BotConfig) error {
	cfg.applyDefaults()
	row := &botConfigRow{
		Enabled:              cfg.Enabled,
		TelegramMode:         "polling", // Telegram is always long-polling
		TelegramWebhookURL:   "",
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
	}
	var tokEnc, mpEnc, mpSecEnc []byte
	var err error
	if cfg.TelegramToken != "" {
		if tokEnc, err = encryptSecret(cfg.TelegramToken); err != nil {
			return err
		}
	}
	if cfg.MPAccessToken != "" {
		if mpEnc, err = encryptSecret(cfg.MPAccessToken); err != nil {
			return err
		}
	}
	if cfg.MPWebhookSecret != "" {
		if mpSecEnc, err = encryptSecret(cfg.MPWebhookSecret); err != nil {
			return err
		}
	}
	// tgSecEnc is always nil now (no Telegram webhook secret).
	return store.saveBotConfigRow(ctx, row, tokEnc, nil, mpEnc, mpSecEnc)
}
