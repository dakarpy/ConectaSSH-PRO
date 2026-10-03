package main

// bot_crypto.go — secret encryption for the Telegram/Mercado Pago bot.
//
// Bot tokens (Telegram bot token, Mercado Pago access token, webhook secrets)
// are stored in PostgreSQL encrypted with AES-256-GCM. The 32-byte master key
// lives OUTSIDE the database, so a DB dump alone never reveals the secrets:
//   1) env BOT_MASTER_KEY (64 hex chars), if set; otherwise
//   2) a 0600 key file next to config.json (bot_master.key); otherwise
//   3) generated with crypto/rand on first use and written to that key file.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	botKeyOnce sync.Once
	botKey     []byte
	botKeyErr  error
)

// botMasterKeyPath returns the on-disk location of the AES master key.
func botMasterKeyPath() string {
	if globalCfgPath != "" {
		return filepath.Join(filepath.Dir(globalCfgPath), "bot_master.key")
	}
	return "/opt/sshpanel/bot_master.key"
}

// loadBotMasterKey resolves the 32-byte master key (env → file → generate).
func loadBotMasterKey() ([]byte, error) {
	botKeyOnce.Do(func() {
		if env := strings.TrimSpace(os.Getenv("BOT_MASTER_KEY")); env != "" {
			k, err := hex.DecodeString(env)
			if err != nil {
				botKeyErr = fmt.Errorf("BOT_MASTER_KEY invalid hex: %w", err)
				return
			}
			if len(k) != 32 {
				botKeyErr = fmt.Errorf("BOT_MASTER_KEY must be 32 bytes (64 hex chars), got %d", len(k))
				return
			}
			botKey = k
			return
		}

		path := botMasterKeyPath()
		data, err := os.ReadFile(path)
		if err == nil {
			k, derr := hex.DecodeString(strings.TrimSpace(string(data)))
			if derr == nil && len(k) == 32 {
				botKey = k
				return
			}
			// Refuse to overwrite a bad key file — overwriting would make
			// existing ciphertext undecryptable and silently lose secrets.
			botKeyErr = fmt.Errorf("bot master key file %s is invalid; refusing to overwrite", path)
			return
		}
		if !errors.Is(err, os.ErrNotExist) {
			botKeyErr = fmt.Errorf("read bot master key: %w", err)
			return
		}

		k := make([]byte, 32)
		if _, e := rand.Read(k); e != nil {
			botKeyErr = fmt.Errorf("generate bot master key: %w", e)
			return
		}
		if e := os.WriteFile(path, []byte(hex.EncodeToString(k)), 0o600); e != nil {
			botKeyErr = fmt.Errorf("write bot master key %s: %w", path, e)
			return
		}
		botKey = k
	})
	return botKey, botKeyErr
}

// encryptSecret encrypts a plaintext secret. Empty input returns nil (no blob).
func encryptSecret(plain string) ([]byte, error) {
	if plain == "" {
		return nil, nil
	}
	key, err := loadBotMasterKey()
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	// Output is nonce || ciphertext(+tag).
	return gcm.Seal(nonce, nonce, []byte(plain), nil), nil
}

// decryptSecret reverses encryptSecret. Empty/nil input returns "".
func decryptSecret(enc []byte) (string, error) {
	if len(enc) == 0 {
		return "", nil
	}
	key, err := loadBotMasterKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(enc) < gcm.NonceSize() {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ct := enc[:gcm.NonceSize()], enc[gcm.NonceSize():]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt secret: %w", err)
	}
	return string(pt), nil
}

// maskSecret returns a log-safe representation of a secret.
func maskSecret(s string) string {
	if s == "" {
		return "(empty)"
	}
	if len(s) <= 6 {
		return "***"
	}
	return s[:3] + "***" + s[len(s)-2:]
}
