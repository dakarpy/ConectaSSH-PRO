package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// makeTestCertPair returns PEM cert/key material for the given domain.
func makeTestCertPair(t *testing.T, domain string, notBefore, notAfter time.Time) (certPEM, keyPEM string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{domain},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("certgen: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

func useTempCertsDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old := tlsCertsDir
	tlsCertsDir = dir
	t.Cleanup(func() { tlsCertsDir = old })
	oldCfg := getGlobalCfg()
	t.Cleanup(func() { setGlobalCfg(oldCfg) })
	return dir
}

func postCertUpdate(t *testing.T, body map[string]interface{}) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/tls/certs/update", strings.NewReader(string(raw)))
	rec := httptest.NewRecorder()
	handleTLSCertUpdate(rec, req)
	return rec
}

func TestCertUpdateStoresNamedCertAndReportsExpiry(t *testing.T) {
	dir := useTempCertsDir(t)
	certPEM, keyPEM := makeTestCertPair(t, "panel.example.com", time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour))

	rec := postCertUpdate(t, map[string]interface{}{
		"name":      "panel-example",
		"fullchain": certPEM,
		"privkey":   keyPEM,
		"reload":    false,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		CertFile string      `json:"cert_file"`
		KeyFile  string      `json:"key_file"`
		Cert     tlsCertInfo `json:"cert"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	wantCert := filepath.Join(dir, "panel-example", tlsCertFileName)
	if filepath.Clean(resp.CertFile) != wantCert {
		t.Fatalf("cert_file = %q, want %q", resp.CertFile, wantCert)
	}
	if !resp.Cert.KeyOK {
		t.Fatalf("expected key to match certificate: %+v", resp.Cert)
	}
	if resp.Cert.Expired || resp.Cert.DaysLeft < 25 {
		t.Fatalf("unexpected expiry data: %+v", resp.Cert)
	}
	if len(resp.Cert.Domains) != 1 || resp.Cert.Domains[0] != "panel.example.com" {
		t.Fatalf("domains = %v", resp.Cert.Domains)
	}
	data, err := os.ReadFile(wantCert)
	if err != nil || !strings.Contains(string(data), "BEGIN CERTIFICATE") {
		t.Fatalf("cert not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "panel-example", tlsKeyFileName)); err != nil {
		t.Fatalf("key not written: %v", err)
	}
}

func TestCertUpdateReplacesInPlaceAndKeepsBackup(t *testing.T) {
	dir := useTempCertsDir(t)
	oldCert, oldKey := makeTestCertPair(t, "old.example.com", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if rec := postCertUpdate(t, map[string]interface{}{
		"name": "renew-me", "fullchain": oldCert, "privkey": oldKey, "reload": false,
	}); rec.Code != http.StatusOK {
		t.Fatalf("seed failed: %s", rec.Body.String())
	}
	certFile := filepath.Join(dir, "renew-me", tlsCertFileName)
	keyFile := filepath.Join(dir, "renew-me", tlsKeyFileName)

	newCert, newKey := makeTestCertPair(t, "new.example.com", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	rec := postCertUpdate(t, map[string]interface{}{
		"cert_file": certFile, "key_file": keyFile,
		"fullchain": newCert, "privkey": newKey, "reload": false,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Cert     tlsCertInfo `json:"cert"`
		Warnings []string    `json:"warnings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Cert.Domains[0] != "new.example.com" {
		t.Fatalf("cert was not replaced: %+v", resp.Cert)
	}
	backup, err := os.ReadFile(certFile + ".bak")
	if err != nil {
		t.Fatalf("no backup written: %v", err)
	}
	if strings.TrimSpace(string(backup)) != strings.TrimSpace(oldCert) {
		t.Fatal("backup does not hold the previous certificate")
	}
	if _, err := os.Stat(keyFile + ".bak"); err != nil {
		t.Fatalf("no key backup: %v", err)
	}
	joined := strings.Join(resp.Warnings, " | ")
	if !strings.Contains(joined, "domínios mudaram") {
		t.Fatalf("expected a domain-change warning, got %q", joined)
	}
}

func TestCertUpdateRejectsBadInput(t *testing.T) {
	dir := useTempCertsDir(t)
	certPEM, keyPEM := makeTestCertPair(t, "a.example.com", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	_, otherKey := makeTestCertPair(t, "b.example.com", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	expiredCert, expiredKey := makeTestCertPair(t, "old.example.com", time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
	// Absolute, but neither panel-managed nor referenced by the configuration.
	unmanaged := t.TempDir()

	cases := []struct {
		name string
		body map[string]interface{}
		want string
	}{
		{"missing key", map[string]interface{}{"name": "x", "fullchain": certPEM}, "obrigatórios"},
		{"mismatched pair", map[string]interface{}{"name": "x", "fullchain": certPEM, "privkey": otherKey}, "não correspondentes"},
		{"expired without force", map[string]interface{}{"name": "x", "fullchain": expiredCert, "privkey": expiredKey}, "expirou"},
		{"unmanaged path", map[string]interface{}{
			"cert_file": filepath.Join(unmanaged, "cert.pem"),
			"key_file":  filepath.Join(unmanaged, "key.pem"),
			"fullchain": certPEM, "privkey": keyPEM,
		}, "não gerenciado"},
		{"relative path", map[string]interface{}{"cert_file": "certs/cert.pem", "fullchain": certPEM, "privkey": keyPEM}, "absoluto"},
		{"bad name", map[string]interface{}{"name": "../escape", "fullchain": certPEM, "privkey": keyPEM}, "nome"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := postCertUpdate(t, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status %d, want 400 (body %s)", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.want) {
				t.Fatalf("body %q does not mention %q", rec.Body.String(), tc.want)
			}
		})
	}
	if entries, err := os.ReadDir(dir); err == nil && len(entries) != 0 {
		t.Fatalf("rejected requests wrote %d entries to the certs dir", len(entries))
	}
}

func TestCertUpdateForceAcceptsExpiredCert(t *testing.T) {
	useTempCertsDir(t)
	expiredCert, expiredKey := makeTestCertPair(t, "old.example.com", time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
	rec := postCertUpdate(t, map[string]interface{}{
		"name": "forced", "fullchain": expiredCert, "privkey": expiredKey, "reload": false, "force": true,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Cert     tlsCertInfo `json:"cert"`
		Warnings []string    `json:"warnings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Cert.Expired {
		t.Fatal("expected the stored certificate to be reported as expired")
	}
	if !strings.Contains(strings.Join(resp.Warnings, " | "), "expirado") {
		t.Fatalf("expected an expiry warning, got %v", resp.Warnings)
	}
}

// A certificate referenced only by the running config (for example a certbot
// path outside the panel directory) must still be updatable in place, because
// that is what makes a renewal invisible to the rest of the configuration.
func TestCertUpdateAllowsPathReferencedByConfig(t *testing.T) {
	useTempCertsDir(t)
	external := t.TempDir()
	certFile := filepath.Join(external, "fullchain.pem")
	keyFile := filepath.Join(external, "privkey.pem")
	oldCert, oldKey := makeTestCertPair(t, "tunnel.example.com", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err := os.WriteFile(certFile, []byte(oldCert), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte(oldKey), 0o600); err != nil {
		t.Fatal(err)
	}
	setGlobalCfg(&Config{TLSForwarders: []TLSForwarderConfig{{
		Listen: "0.0.0.0:8443", CertFile: certFile, KeyFile: keyFile,
	}}})

	newCert, newKey := makeTestCertPair(t, "tunnel.example.com", time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour))
	rec := postCertUpdate(t, map[string]interface{}{
		"cert_file": certFile, "key_file": keyFile,
		"fullchain": newCert, "privkey": newKey, "reload": false,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	stored, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(stored)) != strings.TrimSpace(newCert) {
		t.Fatal("external certificate path was not updated")
	}
	var resp struct {
		Cert tlsCertInfo `json:"cert"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Cert.UsedBy) != 1 || resp.Cert.UsedBy[0].Ref != "0.0.0.0:8443" {
		t.Fatalf("expected the TLS forwarder to be reported as consumer, got %+v", resp.Cert.UsedBy)
	}
}

func TestTLSCertListReportsConfiguredAndManagedCerts(t *testing.T) {
	dir := useTempCertsDir(t)
	certPEM, keyPEM := makeTestCertPair(t, "listed.example.com", time.Now().Add(-time.Hour), time.Now().Add(10*24*time.Hour))
	if err := os.MkdirAll(filepath.Join(dir, "listed"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "listed", tlsCertFileName), []byte(certPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "listed", tlsKeyFileName), []byte(keyPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	setGlobalCfg(&Config{})

	req := httptest.NewRequest(http.MethodGet, "/api/tls/certs", nil)
	rec := httptest.NewRecorder()
	handleTLSCertList(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Certs []tlsCertInfo `json:"certs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Certs) != 1 {
		t.Fatalf("expected 1 cert, got %d (%+v)", len(resp.Certs), resp.Certs)
	}
	got := resp.Certs[0]
	if got.Name != "listed" || !got.Managed || !got.KeyOK || !got.SelfSigned {
		t.Fatalf("unexpected cert info: %+v", got)
	}
	if !got.Expiring || got.Expired {
		t.Fatalf("a cert expiring in 10 days should be flagged as expiring: %+v", got)
	}
}
