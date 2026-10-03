package btun

import (
	"context"
	"io"
)

// Authenticator verifies a BTUN credential. The panel supplies its own
// implementation backed by the same account database the built-in SSH server
// uses, so a BTUN login is exactly as strong as an SSH login on this server.
//
// This package deliberately ships no PAM, /etc/shadow or password-file
// backend: BTUN accounts are panel accounts and nothing else.
type Authenticator interface {
	Authenticate(username, password string) error
	Name() string
}

// AllowAuthenticator accepts every credential. It exists only for the package
// tests, which exercise the wire protocol rather than the account database. It
// is never selectable from the panel configuration.
type AllowAuthenticator struct{}

func (AllowAuthenticator) Authenticate(_, _ string) error { return nil }
func (AllowAuthenticator) Name() string                   { return "allow-insecure" }

// Accountant lets the embedding application admit a freshly authenticated
// session and then meter its traffic. It is optional: when Config.Accountant
// is nil, sessions are admitted unconditionally and no metering happens.
type Accountant interface {
	// Admit is called once per session, immediately after the credential was
	// accepted. Returning an error refuses the session, which is how
	// per-account connection limits are enforced. The returned Ledger is
	// closed exactly once when the session ends.
	//
	// closer ends this session on demand, so the application can force a
	// disconnect (an account being deleted, edited, or hit by a panel-wide
	// restart) without waiting for the next packet to be metered.
	Admit(username, remote string, closer io.Closer) (Ledger, error)
}

// Ledger meters one BTUN session. Uplink and Downlink are called before the
// corresponding packet is forwarded, so returning an error drops the session
// instead of letting it exceed its allowance. Implementations must be safe for
// concurrent use: Uplink runs on the session's reader goroutine while Downlink
// runs on the shared TUN reader goroutine.
type Ledger interface {
	// Uplink accounts for n bytes travelling client -> internet. It may block
	// while rate limiting and returns an error when the session must end.
	Uplink(ctx context.Context, n int) error
	// Downlink accounts for n bytes travelling internet -> client.
	Downlink(ctx context.Context, n int) error
	// Close releases whatever the ledger reserved for this session.
	Close()
}

// nopLedger is used when no Accountant is configured.
type nopLedger struct{}

func (nopLedger) Uplink(context.Context, int) error   { return nil }
func (nopLedger) Downlink(context.Context, int) error { return nil }
func (nopLedger) Close()                              {}
