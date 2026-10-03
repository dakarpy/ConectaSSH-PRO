package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/mail"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// tlsCertsDir holds panel-managed certificates. It is a var so tests can point
// it at a temporary directory.
var tlsCertsDir = "/opt/sshpanel/certs"

var (
	tlsDNSNamePattern   = regexp.MustCompile(`^(?:\*\.)?(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	tlsStoreNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

func normalizeTLSDomain(raw string, allowWildcard bool) (domain string, dirName string, err error) {
	domain = strings.TrimSuffix(strings.TrimSpace(raw), ".")
	if domain == "" || len(domain) > 253 || strings.ContainsAny(domain, "/\\\x00\r\n") {
		return "", "", fmt.Errorf("invalid domain")
	}
	if ip := net.ParseIP(domain); ip != nil {
		return domain, strings.ReplaceAll(domain, ":", "_"), nil
	}
	if strings.HasPrefix(domain, "*.") && !allowWildcard {
		return "", "", fmt.Errorf("wildcard domains are not supported by this operation")
	}
	if !tlsDNSNamePattern.MatchString(domain) {
		return "", "", fmt.Errorf("invalid domain")
	}
	dirName = strings.ReplaceAll(domain, "*", "_wildcard_")
	return domain, dirName, nil
}

func normalizeTLSStoreName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if !tlsStoreNamePattern.MatchString(name) {
		return "", fmt.Errorf("name must use only letters, numbers, dot, underscore, or hyphen")
	}
	return name, nil
}

// handleTLSGenerateSelfSigned generates a self-signed TLS certificate for the
// given domain, writes it to /opt/sshpanel/certs/<domain>/, and returns the paths.
func handleTLSGenerateSelfSigned(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Domain string `json:"domain"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Domain == "" {
		http.Error(w, "domain required", http.StatusBadRequest)
		return
	}
	domain, dirName, err := normalizeTLSDomain(req.Domain, true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	certDir := filepath.Join(tlsCertsDir, dirName)
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		http.Error(w, "mkdir: "+err.Error(), http.StatusInternalServerError)
		return
	}
	certFile := filepath.Join(certDir, "cert.pem")
	keyFile := filepath.Join(certDir, "key.pem")

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		http.Error(w, "keygen: "+err.Error(), http.StatusInternalServerError)
		return
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		http.Error(w, "serial generation failed", http.StatusInternalServerError)
		return
	}
	tmpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{domain},
	}
	if net.ParseIP(domain) != nil {
		tmpl.DNSNames = nil
		tmpl.IPAddresses = []net.IP{net.ParseIP(domain)}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		http.Error(w, "certgen: "+err.Error(), http.StatusInternalServerError)
		return
	}
	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		http.Error(w, "marshal key: "+err.Error(), http.StatusInternalServerError)
		return
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})
	if err := writeFileAtomic(certFile, certPEM, 0o600); err != nil {
		http.Error(w, "write cert: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := writeFileAtomic(keyFile, keyPEM, 0o600); err != nil {
		http.Error(w, "write key: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"cert_file": certFile,
		"key_file":  keyFile,
	})
}

// handleTLSLetsEncrypt runs certbot to obtain a certificate via Let's Encrypt.
// Requires certbot installed on the server and port 80 available.
func handleTLSLetsEncrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Domain string `json:"domain"`
		Email  string `json:"email"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Domain == "" || req.Email == "" {
		http.Error(w, "domain and email required", http.StatusBadRequest)
		return
	}
	domain, _, err := normalizeTLSDomain(req.Domain, false)
	if err != nil || net.ParseIP(domain) != nil {
		http.Error(w, "a valid DNS domain is required", http.StatusBadRequest)
		return
	}
	email := strings.TrimSpace(req.Email)
	parsedEmail, err := mail.ParseAddress(email)
	if err != nil || parsedEmail.Address != email || len(email) > 254 {
		http.Error(w, "valid email required", http.StatusBadRequest)
		return
	}

	cmd := exec.Command("certbot", "certonly", "--standalone", "--non-interactive",
		"--agree-tos", "-m", email, "-d", domain)
	out, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, fmt.Sprintf("certbot failed: %v\n%s", err, string(out)), http.StatusInternalServerError)
		return
	}

	certFile := "/etc/letsencrypt/live/" + domain + "/fullchain.pem"
	keyFile := "/etc/letsencrypt/live/" + domain + "/privkey.pem"

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"cert_file": certFile,
		"key_file":  keyFile,
		"output":    string(out),
	})
}

// handleTLSUploadPEM accepts PEM text for cert and key, saves them to disk under
// /opt/sshpanel/certs/<name>/, and returns the file paths.
func handleTLSUploadPEM(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Name string `json:"name"`
		Cert string `json:"cert"`
		Key  string `json:"key"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" || req.Cert == "" || req.Key == "" {
		http.Error(w, "name, cert, and key required", http.StatusBadRequest)
		return
	}
	name, err := normalizeTLSStoreName(req.Name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(req.Cert) > 1024*1024 || len(req.Key) > 1024*1024 {
		http.Error(w, "certificate or key is too large", http.StatusRequestEntityTooLarge)
		return
	}
	pair, err := tls.X509KeyPair([]byte(req.Cert), []byte(req.Key))
	if err != nil || len(pair.Certificate) == 0 {
		http.Error(w, "certificate and private key are invalid or do not match", http.StatusBadRequest)
		return
	}
	if _, err := x509.ParseCertificate(pair.Certificate[0]); err != nil {
		http.Error(w, "invalid leaf certificate", http.StatusBadRequest)
		return
	}
	certDir := filepath.Join(tlsCertsDir, name)
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		http.Error(w, "mkdir: "+err.Error(), http.StatusInternalServerError)
		return
	}
	certFile := filepath.Join(certDir, "cert.pem")
	keyFile := filepath.Join(certDir, "key.pem")
	if err := writeFileAtomic(certFile, []byte(req.Cert), 0o600); err != nil {
		http.Error(w, "write cert: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := writeFileAtomic(keyFile, []byte(req.Key), 0o600); err != nil {
		http.Error(w, "write key: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"cert_file": certFile,
		"key_file":  keyFile,
	})
}
