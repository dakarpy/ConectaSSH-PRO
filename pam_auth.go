package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/GehirnInc/crypt"
	_ "github.com/GehirnInc/crypt/apr1_crypt"
	_ "github.com/GehirnInc/crypt/md5_crypt"
	_ "github.com/GehirnInc/crypt/sha256_crypt"
	_ "github.com/GehirnInc/crypt/sha512_crypt"
	"github.com/openwall/yescrypt-go"
	"golang.org/x/crypto/bcrypt"
)

const (
	shadowFile = "/etc/shadow"
	passwdFile = "/etc/passwd"

	// minLoginUID / nobodyUID bound the accounts eligible for auto-import.
	// Regular human login accounts start at UID 1000 on Debian/Ubuntu; system
	// and service accounts (and "nobody") are excluded.
	minLoginUID = 1000
	nobodyUID   = 65534
)

var errNoSystemPassword = errors.New("account has no usable password")

// pamLogger writes PAM auth diagnostics straight to stderr (captured by
// journald) so they remain visible even when "Quiet Logs" redirects the default
// logger to io.Discard. Use pamLogf for anything an operator needs to see when
// debugging why a system login was accepted or refused.
var pamLogger = log.New(os.Stderr, "", log.LstdFlags)

func pamLogf(format string, args ...interface{}) { pamLogger.Printf(format, args...) }

// pamAuthEnabled mirrors Config.PAMAuthEnabled and is toggled live on config
// reload. Guarded atomically so passwordCallback can read it lock-free.
var pamAuthEnabled atomic.Bool

func setPAMAuthEnabled(v bool) {
	pamAuthEnabled.Store(v)
	state := "disabled"
	if v {
		state = "ENABLED"
	}
	pamLogf("PAM: system (Linux /etc/shadow) login is now %s", state)
}
func isPAMAuthEnabled() bool { return pamAuthEnabled.Load() }

// importPAMUser registers a freshly PAM-authenticated account in the running
// user manager and persists it (marked use_pam) so it shows up in the panel and
// later logins are re-verified against the system password. Idempotent: a
// second concurrent/subsequent login for the same user is a no-op.
func importPAMUser(username string) {
	cfg := UserConfig{Username: username, UsePAM: true}
	// Carry over the Linux account expiry (/etc/shadow field 8) so the panel's
	// "Vence em" shows the real expiration instead of "—".
	var expPtr *time.Time
	if exp := shadowAccountExpiry(username); exp != nil {
		cfg.ExpiresAt = exp.Format(time.RFC3339)
		expPtr = exp
	}
	st := &UserState{Cfg: cfg, ExpiresAt: expPtr}
	if !userMgr.AddIfAbsent(st) {
		return // already present in memory
	}
	pamLogf("PAM: auto-imported system user %s into the panel", username)
	if statsStore != nil {
		if err := statsStore.UpsertUser(context.Background(), cfg); err != nil {
			pamLogf("PAM: failed to persist auto-imported user %s: %v", username, err)
		}
	}
}

// isRegularLoginUser reports whether username is a regular human login account
// (UID >= 1000 and not "nobody"), by parsing /etc/passwd. System/service
// accounts and root are excluded from auto-import.
func isRegularLoginUser(username string) bool {
	data, err := os.ReadFile(passwdFile)
	if err != nil {
		pamLogf("PAM: cannot read %s: %v", passwdFile, err)
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		fields := strings.Split(line, ":")
		if len(fields) < 3 || fields[0] != username {
			continue
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil {
			return false
		}
		return uid >= minLoginUID && uid != nobodyUID
	}
	return false
}

// shadowAccountExpiry returns the account expiration date from /etc/shadow
// field 8 (days since 1970-01-01), or nil if the account never expires (empty
// field) or the value is unusable. This is the `chage -E` / `useradd -e` date,
// which maps to the panel's per-user expiry.
func shadowAccountExpiry(username string) *time.Time {
	data, err := os.ReadFile(shadowFile)
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(strings.TrimRight(line, "\r"), ":")
		if len(fields) < 8 || fields[0] != username {
			continue
		}
		expStr := strings.TrimSpace(fields[7])
		if expStr == "" {
			return nil // no account expiry set
		}
		days, err := strconv.Atoi(expStr)
		if err != nil || days <= 0 {
			return nil
		}
		t := time.Unix(int64(days)*86400, 0).UTC()
		return &t
	}
	return nil
}

// authenticatePAM verifies password against the Linux system account matching
// username. It reads the account's hash from /etc/shadow (the panel runs as
// root) and recomputes it with the same algorithm — this is the "just the auth"
// behaviour: the supplied password is checked exactly as the system would,
// with no account/session management and nothing to do with the SSH daemon.
//
// It is called "PAM" for continuity with the user-facing flag, but it does not
// link libpam; it verifies the crypt(3) hash directly. Supported hash formats:
// yescrypt ($y$), sha512-crypt ($6$), sha256-crypt ($5$), md5-crypt ($1$),
// apr1 ($apr1$) and bcrypt ($2a$/$2b$/$2y$). Returns nil on success.
func authenticatePAM(username, password string) error {
	if username == "" {
		return errors.New("shadow: empty username")
	}
	hash, err := lookupShadowHash(username)
	if err != nil {
		return err
	}
	return verifyCryptHash(hash, password)
}

// lookupShadowHash returns the password hash field for username from /etc/shadow.
func lookupShadowHash(username string) (string, error) {
	data, err := os.ReadFile(shadowFile)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", shadowFile, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 2 || fields[0] != username {
			continue
		}
		hash := fields[1]
		// Empty, or locked/disabled accounts (! or * in the hash field) have no
		// password that any input can match — reject rather than risk a match.
		if hash == "" || strings.HasPrefix(hash, "!") || strings.HasPrefix(hash, "*") {
			return "", errNoSystemPassword
		}
		return hash, nil
	}
	return "", fmt.Errorf("shadow: user %q not found", username)
}

// verifyCryptHash checks password against a crypt(3)-style hash string,
// dispatching on the hash prefix. Returns nil only on an exact match.
func verifyCryptHash(hash, password string) error {
	switch {
	case strings.HasPrefix(hash, "$y$"):
		computed, err := yescrypt.Hash([]byte(password), []byte(hash))
		if err != nil {
			return fmt.Errorf("yescrypt: %w", err)
		}
		if subtle.ConstantTimeCompare(computed, []byte(hash)) == 1 {
			return nil
		}
		return errors.New("password mismatch")
	case strings.HasPrefix(hash, "$2a$"), strings.HasPrefix(hash, "$2b$"), strings.HasPrefix(hash, "$2y$"):
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	case crypt.IsHashSupported(hash):
		return crypt.NewFromHash(hash).Verify(hash, []byte(password))
	case isTraditionalDES(hash):
		computed, err := desCrypt(password, hash)
		if err != nil {
			return fmt.Errorf("descrypt: %w", err)
		}
		if subtle.ConstantTimeCompare([]byte(computed), []byte(hash)) == 1 {
			return nil
		}
		return errors.New("password mismatch")
	default:
		return fmt.Errorf("shadow: unsupported hash format")
	}
}

// isTraditionalDES reports whether hash looks like a classic 13-character
// DES crypt(3) hash (2 salt chars + 11 hash chars, all from the crypt alphabet,
// no "$" scheme prefix). Used by old Linux/UNIX accounts.
func isTraditionalDES(hash string) bool {
	if len(hash) != 13 {
		return false
	}
	for i := 0; i < len(hash); i++ {
		if crypt64Decode(hash[i]) < 0 {
			return false
		}
	}
	return true
}
