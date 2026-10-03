package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Certificate management for the panel: list the TLS material this node already
// uses and replace it in place (fullchain + privkey) when an operator renews a
// certificate. Replacing in place is what makes renewal painless — every place
// that references the old paths (TLS forwarders, Xray inbounds) keeps working,
// and only the listeners that actually serve the certificate are rebound.

const (
	tlsCertFileName = "cert.pem"
	tlsKeyFileName  = "key.pem"
	// Two PEM blobs plus JSON overhead. Certificates are a few KB; RSA chains
	// with several intermediates still stay far below this.
	maxTLSCertRequestBody = 4 << 20
	maxTLSPEMBytes        = 1 << 20
	// Certificates expiring inside this window are flagged in the panel.
	tlsCertExpiryWarnDays = 21
)

// tlsCertUsage records one consumer of a certificate so the panel can show what
// a replacement is going to affect.
type tlsCertUsage struct {
	Kind string `json:"kind"` // tls_forwarder | xray_inbound
	Ref  string `json:"ref"`  // listen address or inbound tag
}

type tlsCertInfo struct {
	Name       string         `json:"name"`
	CertFile   string         `json:"cert_file"`
	KeyFile    string         `json:"key_file"`
	Managed    bool           `json:"managed"` // stored under /opt/sshpanel/certs
	Exists     bool           `json:"exists"`
	Subject    string         `json:"subject,omitempty"`
	Issuer     string         `json:"issuer,omitempty"`
	Domains    []string       `json:"domains"`
	NotBefore  string         `json:"not_before,omitempty"`
	NotAfter   string         `json:"not_after,omitempty"`
	DaysLeft   int            `json:"days_left"`
	Expired    bool           `json:"expired"`
	Expiring   bool           `json:"expiring"`
	SelfSigned bool           `json:"self_signed"`
	ChainLen   int            `json:"chain_length"`
	KeyType    string         `json:"key_type,omitempty"`
	KeyOK      bool           `json:"key_ok"`
	Modified   string         `json:"modified,omitempty"`
	Error      string         `json:"error,omitempty"`
	UsedBy     []tlsCertUsage `json:"used_by"`
}

type tlsCertRef struct {
	certFile string
	keyFile  string
	managed  bool
	usage    []tlsCertUsage
}

type tlsCertRefSet struct {
	byCert map[string]*tlsCertRef
	order  []string
}

func newTLSCertRefSet() *tlsCertRefSet {
	return &tlsCertRefSet{byCert: map[string]*tlsCertRef{}}
}

func (s *tlsCertRefSet) add(certFile, keyFile string, usage ...tlsCertUsage) *tlsCertRef {
	certFile = strings.TrimSpace(certFile)
	if certFile == "" {
		return nil
	}
	certFile = filepath.Clean(certFile)
	ref, ok := s.byCert[certFile]
	if !ok {
		ref = &tlsCertRef{certFile: certFile, managed: isUnderTLSCertsDir(certFile)}
		s.byCert[certFile] = ref
		s.order = append(s.order, certFile)
	}
	if ref.keyFile == "" && strings.TrimSpace(keyFile) != "" {
		ref.keyFile = filepath.Clean(strings.TrimSpace(keyFile))
	}
	for _, u := range usage {
		if u.Kind == "" {
			continue
		}
		dup := false
		for _, have := range ref.usage {
			if have == u {
				dup = true
				break
			}
		}
		if !dup {
			ref.usage = append(ref.usage, u)
		}
	}
	return ref
}

func (s *tlsCertRefSet) list() []*tlsCertRef {
	out := make([]*tlsCertRef, 0, len(s.order))
	for _, key := range s.order {
		out = append(out, s.byCert[key])
	}
	return out
}

func isUnderTLSCertsDir(path string) bool {
	rel, err := filepath.Rel(filepath.Clean(tlsCertsDir), filepath.Clean(path))
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// samePathRef compares two file paths, following symlinks when both sides can be
// resolved. /etc/letsencrypt/live/<domain>/fullchain.pem is a symlink, so a
// plain string compare is not enough to match a config reference to a real file.
func samePathRef(a, b string) bool {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if a == "" || b == "" {
		return false
	}
	if filepath.Clean(a) == filepath.Clean(b) {
		return true
	}
	ra, errA := filepath.EvalSymlinks(a)
	rb, errB := filepath.EvalSymlinks(b)
	return errA == nil && errB == nil && ra == rb
}

// collectTLSCertRefs gathers every certificate this node knows about: the ones
// stored in the panel's cert directory plus the ones referenced by the running
// config (TLS forwarders) and the Xray config (inbound tlsSettings).
func collectTLSCertRefs() *tlsCertRefSet {
	set := newTLSCertRefSet()

	gc := getGlobalCfg()
	var fallbackCert, fallbackKey string
	if gc != nil {
		for _, fwd := range gc.TLSForwarders {
			if strings.TrimSpace(fwd.CertFile) == "" {
				continue
			}
			if fallbackCert == "" {
				fallbackCert, fallbackKey = fwd.CertFile, fwd.KeyFile
			}
			listen := strings.TrimSpace(fwd.Listen)
			if listen == "" {
				listen = "(unbound)"
			}
			set.add(fwd.CertFile, fwd.KeyFile, tlsCertUsage{Kind: "tls_forwarder", Ref: listen})
		}
	}

	for _, u := range xrayInboundCertUsage(fallbackCert, fallbackKey) {
		set.add(u.certFile, u.keyFile, tlsCertUsage{Kind: "xray_inbound", Ref: u.tag})
	}

	// Panel-managed certificates (self-signed, pasted, or previously updated).
	entries, err := os.ReadDir(tlsCertsDir)
	if err == nil {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			if e.IsDir() {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		for _, name := range names {
			certFile := filepath.Join(tlsCertsDir, name, tlsCertFileName)
			if _, err := os.Stat(certFile); err != nil {
				continue
			}
			set.add(certFile, filepath.Join(tlsCertsDir, name, tlsKeyFileName))
		}
	}
	return set
}

type xrayCertRef struct {
	tag      string
	certFile string
	keyFile  string
}

// xrayInboundCertUsage returns the certificate each TLS-enabled Xray inbound
// serves. Inbounds that enable TLS without naming a certificate inherit the
// first TLS forwarder's material (see buildInboundTLS), so they are reported
// against that path — replacing it does affect them.
func xrayInboundCertUsage(fallbackCert, fallbackKey string) []xrayCertRef {
	if xrayMgr == nil {
		return nil
	}
	data, err := xrayMgr.GetConfig()
	if err != nil || len(data) == 0 {
		return nil
	}
	var cf struct {
		Inbounds []struct {
			Tag            string `json:"tag"`
			StreamSettings struct {
				Security    string `json:"security"`
				TLSSettings struct {
					Certificates []struct {
						CertificateFile string `json:"certificateFile"`
						KeyFile         string `json:"keyFile"`
					} `json:"certificates"`
				} `json:"tlsSettings"`
			} `json:"streamSettings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(data, &cf); err != nil {
		return nil
	}
	var out []xrayCertRef
	for i, in := range cf.Inbounds {
		security := strings.ToLower(strings.TrimSpace(in.StreamSettings.Security))
		certs := in.StreamSettings.TLSSettings.Certificates
		if security != "tls" && len(certs) == 0 {
			continue
		}
		tag := strings.TrimSpace(in.Tag)
		if tag == "" {
			tag = fmt.Sprintf("inbound-%d", i+1)
		}
		if len(certs) > 0 && strings.TrimSpace(certs[0].CertificateFile) != "" {
			out = append(out, xrayCertRef{tag: tag, certFile: certs[0].CertificateFile, keyFile: certs[0].KeyFile})
			continue
		}
		if security == "tls" && strings.TrimSpace(fallbackCert) != "" {
			out = append(out, xrayCertRef{tag: tag + " (herda do TLS forwarder)", certFile: fallbackCert, keyFile: fallbackKey})
		}
	}
	return out
}

func tlsCertDisplayName(certFile string) string {
	dir := filepath.Base(filepath.Dir(certFile))
	if dir == "" || dir == "." || dir == string(filepath.Separator) {
		return filepath.Base(certFile)
	}
	if dir == "live" || dir == "certs" {
		return filepath.Base(certFile)
	}
	return dir
}

func tlsKeyTypeName(key interface{}) string {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return fmt.Sprintf("RSA %d", k.N.BitLen())
	case *ecdsa.PrivateKey:
		return "ECDSA " + k.Curve.Params().Name
	case ed25519.PrivateKey:
		return "Ed25519"
	}
	return ""
}

func parsePEMCertChain(data []byte) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		crt, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		chain = append(chain, crt)
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("no CERTIFICATE block found")
	}
	return chain, nil
}

func certDomains(leaf *x509.Certificate) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(leaf.DNSNames)+len(leaf.IPAddresses)+1)
	for _, d := range leaf.DNSNames {
		if d = strings.TrimSpace(d); d != "" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	for _, ip := range leaf.IPAddresses {
		s := ip.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	if len(out) == 0 && strings.TrimSpace(leaf.Subject.CommonName) != "" {
		out = append(out, strings.TrimSpace(leaf.Subject.CommonName))
	}
	return out
}

func describeTLSCert(ref *tlsCertRef) tlsCertInfo {
	info := tlsCertInfo{
		Name:     tlsCertDisplayName(ref.certFile),
		CertFile: ref.certFile,
		KeyFile:  ref.keyFile,
		Managed:  ref.managed,
		Domains:  []string{},
		UsedBy:   ref.usage,
	}
	if info.UsedBy == nil {
		info.UsedBy = []tlsCertUsage{}
	}
	st, err := os.Stat(ref.certFile)
	if err != nil {
		info.Error = "arquivo não encontrado"
		return info
	}
	info.Exists = true
	info.Modified = st.ModTime().UTC().Format(time.RFC3339)

	certPEM, err := os.ReadFile(ref.certFile)
	if err != nil {
		info.Error = "leitura do certificado: " + err.Error()
		return info
	}
	chain, err := parsePEMCertChain(certPEM)
	if err != nil {
		info.Error = "certificado inválido: " + err.Error()
		return info
	}
	leaf := chain[0]
	info.ChainLen = len(chain)
	info.Subject = leaf.Subject.CommonName
	info.Issuer = leaf.Issuer.CommonName
	if info.Issuer == "" && len(leaf.Issuer.Organization) > 0 {
		info.Issuer = leaf.Issuer.Organization[0]
	}
	info.Domains = certDomains(leaf)
	info.NotBefore = leaf.NotBefore.UTC().Format(time.RFC3339)
	info.NotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
	info.SelfSigned = string(leaf.RawIssuer) == string(leaf.RawSubject)
	now := time.Now()
	info.Expired = now.After(leaf.NotAfter)
	info.DaysLeft = int(leaf.NotAfter.Sub(now).Hours() / 24)
	info.Expiring = !info.Expired && info.DaysLeft <= tlsCertExpiryWarnDays

	if ref.keyFile != "" {
		keyPEM, err := os.ReadFile(ref.keyFile)
		if err != nil {
			info.Error = "leitura da chave: " + err.Error()
			return info
		}
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			info.Error = "a chave privada não corresponde ao certificado"
			return info
		}
		info.KeyOK = true
		info.KeyType = tlsKeyTypeName(pair.PrivateKey)
	} else {
		info.Error = "nenhuma chave privada associada"
	}
	return info
}

// handleTLSCertList returns every certificate this node uses, with expiry and
// the listeners/inbounds that serve it.
func handleTLSCertList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	refs := collectTLSCertRefs().list()
	out := make([]tlsCertInfo, 0, len(refs))
	for _, ref := range refs {
		out = append(out, describeTLSCert(ref))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"certs_dir": tlsCertsDir,
		"certs":     out,
	})
}

type tlsCertUpdateRequest struct {
	// Name creates or replaces a panel-managed certificate under
	// /opt/sshpanel/certs/<name>/. Ignored when CertFile is set.
	Name string `json:"name"`
	// CertFile/KeyFile target an existing certificate in place so every
	// reference to those paths keeps working after the renewal.
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
	// Fullchain/Privkey hold the PEM text. cert/key are accepted as aliases.
	Fullchain string `json:"fullchain"`
	Privkey   string `json:"privkey"`
	Cert      string `json:"cert"`
	Key       string `json:"key"`
	Reload    *bool  `json:"reload"`
	Force     bool   `json:"force"`
}

type tlsCertReloadResult struct {
	TLSForwarders []string `json:"tls_forwarders"`
	XrayInbounds  []string `json:"xray_inbounds"`
	XrayRestarted bool     `json:"xray_restarted"`
}

func normalizeTLSFilePath(raw string) (string, error) {
	p := strings.TrimSpace(raw)
	if p == "" {
		return "", fmt.Errorf("caminho vazio")
	}
	if strings.ContainsAny(p, "\x00\r\n") {
		return "", fmt.Errorf("caminho inválido")
	}
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("o caminho precisa ser absoluto")
	}
	return filepath.Clean(p), nil
}

func normalizePEMText(raw string) string {
	s := strings.ReplaceAll(strings.TrimSpace(raw), "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	if s == "" {
		return ""
	}
	return s + "\n"
}

// resolveTLSCertTarget decides which files the new PEM material is written to
// and rejects paths that are neither panel-managed nor already referenced by the
// running configuration. Without that check this endpoint would be an arbitrary
// root file-write primitive.
func resolveTLSCertTarget(req tlsCertUpdateRequest) (certFile, keyFile string, warnings []string, err error) {
	if strings.TrimSpace(req.CertFile) != "" {
		certFile, err = normalizeTLSFilePath(req.CertFile)
		if err != nil {
			return "", "", nil, err
		}
		refs := collectTLSCertRefs()
		var known *tlsCertRef
		for _, ref := range refs.list() {
			if samePathRef(ref.certFile, certFile) {
				known = ref
				break
			}
		}
		if known == nil && !isUnderTLSCertsDir(certFile) {
			return "", "", nil, fmt.Errorf("caminho não gerenciado pelo painel: use um certificado já referenciado na configuração ou informe um nome para armazenar em %s", tlsCertsDir)
		}
		if strings.TrimSpace(req.KeyFile) != "" {
			keyFile, err = normalizeTLSFilePath(req.KeyFile)
			if err != nil {
				return "", "", nil, err
			}
		} else if known != nil && known.keyFile != "" {
			keyFile = known.keyFile
		} else {
			keyFile = filepath.Join(filepath.Dir(certFile), tlsKeyFileName)
		}
		if !isUnderTLSCertsDir(keyFile) {
			keyKnown := known != nil && samePathRef(known.keyFile, keyFile)
			if !keyKnown && filepath.Dir(keyFile) != filepath.Dir(certFile) {
				return "", "", nil, fmt.Errorf("a chave precisa estar na mesma pasta do certificado ou já estar referenciada na configuração")
			}
		}
		return certFile, keyFile, warnings, nil
	}

	name, nameErr := normalizeTLSStoreName(req.Name)
	if nameErr != nil {
		return "", "", nil, fmt.Errorf("informe cert_file de um certificado existente ou um nome para armazenar: %v", nameErr)
	}
	dir := filepath.Join(tlsCertsDir, name)
	return filepath.Join(dir, tlsCertFileName), filepath.Join(dir, tlsKeyFileName), warnings, nil
}

// writeTLSMaterial replaces path with data, keeping a .bak copy of the previous
// content and preserving the existing file mode. Symlinked targets (certbot
// layout) are followed so the link structure survives the update.
func writeTLSMaterial(path string, data []byte, defaultMode os.FileMode) (string, []string, error) {
	var warnings []string
	target := path
	if lst, err := os.Lstat(path); err == nil && lst.Mode()&os.ModeSymlink != 0 {
		if resolved, err := filepath.EvalSymlinks(path); err == nil {
			target = resolved
			warnings = append(warnings, fmt.Sprintf("%s é um link para %s; o conteúdo real foi substituído", path, resolved))
		}
	}
	mode := defaultMode
	if st, err := os.Stat(target); err == nil {
		mode = st.Mode().Perm()
		if old, err := os.ReadFile(target); err == nil {
			if err := writeFileAtomic(target+".bak", old, mode); err != nil {
				warnings = append(warnings, "não foi possível gravar backup de "+filepath.Base(target)+": "+err.Error())
			}
		}
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return target, warnings, err
	}
	if err := writeFileAtomic(target, data, mode); err != nil {
		return target, warnings, err
	}
	return target, warnings, nil
}

// handleTLSCertUpdate replaces a certificate's fullchain + private key and
// reloads whatever serves it, so a renewal takes effect without touching any
// other configuration.
func handleTLSCertUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTLSCertRequestBody)
	var req tlsCertUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "corpo inválido: "+err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Fullchain) == "" {
		req.Fullchain = req.Cert
	}
	if strings.TrimSpace(req.Privkey) == "" {
		req.Privkey = req.Key
	}
	certPEM := normalizePEMText(req.Fullchain)
	keyPEM := normalizePEMText(req.Privkey)
	if certPEM == "" || keyPEM == "" {
		http.Error(w, "fullchain (certificado) e privkey (chave privada) são obrigatórios", http.StatusBadRequest)
		return
	}
	if len(certPEM) > maxTLSPEMBytes || len(keyPEM) > maxTLSPEMBytes {
		http.Error(w, "certificado ou chave muito grandes", http.StatusRequestEntityTooLarge)
		return
	}

	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil || len(pair.Certificate) == 0 {
		http.Error(w, "certificado e chave privada inválidos ou não correspondentes", http.StatusBadRequest)
		return
	}
	chain, err := parsePEMCertChain([]byte(certPEM))
	if err != nil {
		http.Error(w, "certificado inválido: "+err.Error(), http.StatusBadRequest)
		return
	}
	leaf := chain[0]
	now := time.Now()
	if now.After(leaf.NotAfter) && !req.Force {
		http.Error(w, fmt.Sprintf("este certificado expirou em %s; envie force=true para gravar mesmo assim",
			leaf.NotAfter.UTC().Format("2006-01-02")), http.StatusBadRequest)
		return
	}

	certFile, keyFile, warnings, err := resolveTLSCertTarget(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if len(chain) < 2 && !leaf.IsCA && string(leaf.RawIssuer) != string(leaf.RawSubject) {
		warnings = append(warnings, "o PEM enviado contém apenas o certificado final; cole o fullchain.pem completo para evitar erros de cadeia em alguns clientes")
	}
	if now.Before(leaf.NotBefore) {
		warnings = append(warnings, "o certificado só é válido a partir de "+leaf.NotBefore.UTC().Format("2006-01-02 15:04")+" UTC")
	}
	if now.After(leaf.NotAfter) {
		warnings = append(warnings, "certificado já expirado — gravado por causa de force=true")
	}
	// Domain mismatch is usually a wrong paste, but a domain change can be
	// intentional, so it is reported rather than blocked.
	if oldPEM, err := os.ReadFile(certFile); err == nil {
		if oldChain, err := parsePEMCertChain(oldPEM); err == nil {
			oldDomains, newDomains := certDomains(oldChain[0]), certDomains(leaf)
			if strings.Join(oldDomains, ",") != strings.Join(newDomains, ",") {
				warnings = append(warnings, fmt.Sprintf("os domínios mudaram: antes %s, agora %s",
					strings.Join(oldDomains, ", "), strings.Join(newDomains, ", ")))
			}
		}
	}

	writtenCert, certWarn, err := writeTLSMaterial(certFile, []byte(certPEM), 0o600)
	warnings = append(warnings, certWarn...)
	if err != nil {
		http.Error(w, "gravar certificado: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writtenKey, keyWarn, err := writeTLSMaterial(keyFile, []byte(keyPEM), 0o600)
	warnings = append(warnings, keyWarn...)
	if err != nil {
		http.Error(w, "gravar chave: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("tls: certificate updated cert=%s key=%s cn=%q not_after=%s",
		writtenCert, writtenKey, leaf.Subject.CommonName, leaf.NotAfter.UTC().Format(time.RFC3339))

	reload := tlsCertReloadResult{TLSForwarders: []string{}, XrayInbounds: []string{}}
	if req.Reload == nil || *req.Reload {
		var reloadWarn []string
		reload, reloadWarn = reloadTLSCertConsumers(certFile, keyFile)
		warnings = append(warnings, reloadWarn...)
	}

	info := describeTLSCert(&tlsCertRef{
		certFile: certFile,
		keyFile:  keyFile,
		managed:  isUnderTLSCertsDir(certFile),
		usage:    certUsageFor(certFile, keyFile),
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"cert_file": certFile,
		"key_file":  keyFile,
		"cert":      info,
		"reloaded":  reload,
		"warnings":  warnings,
	})
}

func certUsageFor(certFile, keyFile string) []tlsCertUsage {
	for _, ref := range collectTLSCertRefs().list() {
		if samePathRef(ref.certFile, certFile) {
			return ref.usage
		}
	}
	return nil
}

// reloadTLSCertConsumers rebinds the TLS forwarders that serve the replaced
// certificate and restarts Xray when one of its inbounds uses it. Certificates
// are read once when a listener is created, so nothing short of rebinding picks
// up new material. Established connections are not owned by the listeners and
// keep running.
func reloadTLSCertConsumers(certFile, keyFile string) (tlsCertReloadResult, []string) {
	result := tlsCertReloadResult{TLSForwarders: []string{}, XrayInbounds: []string{}}
	var warnings []string

	gc := getGlobalCfg()
	var fallbackCert, fallbackKey string
	if gc != nil {
		for _, fwd := range gc.TLSForwarders {
			if strings.TrimSpace(fwd.CertFile) != "" {
				fallbackCert, fallbackKey = fwd.CertFile, fwd.KeyFile
				break
			}
		}
		var affected []string
		for _, fwd := range gc.TLSForwarders {
			if samePathRef(fwd.CertFile, certFile) || samePathRef(fwd.KeyFile, keyFile) {
				if listen := strings.TrimSpace(fwd.Listen); listen != "" {
					affected = append(affected, listen)
				}
			}
		}
		if len(affected) > 0 && tlsPool != nil {
			tlsPool.Drop(affected, "certificate updated")
			for _, e := range tlsPool.Sync(gc.TLSForwarders) {
				warnings = append(warnings, fmt.Sprintf("recarregar TLS forwarder: %v", e))
			}
			for _, addr := range affected {
				if tlsPool.Has(addr) {
					result.TLSForwarders = append(result.TLSForwarders, addr)
				} else {
					warnings = append(warnings, "o TLS forwarder "+addr+" não voltou a escutar; verifique os logs")
				}
			}
		}
	}

	for _, u := range xrayInboundCertUsage(fallbackCert, fallbackKey) {
		if samePathRef(u.certFile, certFile) || samePathRef(u.keyFile, keyFile) {
			result.XrayInbounds = append(result.XrayInbounds, u.tag)
		}
	}
	if len(result.XrayInbounds) > 0 && xrayMgr != nil {
		st := xrayMgr.Status()
		if st.Enabled && st.Running {
			if err := xrayMgr.Restart(); err != nil {
				warnings = append(warnings, fmt.Sprintf("reiniciar Xray: %v", err))
			} else {
				result.XrayRestarted = true
			}
		} else if st.Enabled {
			warnings = append(warnings, "o Xray usa este certificado mas não está em execução")
		}
	}
	return result, warnings
}
