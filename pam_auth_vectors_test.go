package main

import "testing"

// Known crypt(3) test vectors covering the formats found in /etc/shadow across
// old and new Linux. verifyCryptHash must accept the right password and reject
// the wrong one for each.
func TestVerifyCryptHashVectors(t *testing.T) {
	cases := []struct {
		name string
		hash string
		pw   string
	}{
		{
			name: "sha512crypt $6$ (glibc, older Linux)",
			// openssl passwd -6 -salt saltstring "Hello world!"
			hash: "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1",
			pw:   "Hello world!",
		},
		{
			name: "yescrypt $y$ (Debian 11+/Ubuntu 22.04+)",
			hash: "$y$j9T$e8R9q85ZuzUkArEUurdtS.$esON.7y6H.u3UCPVCpbRFueRpAut2n2cMf1EhpjbuiC",
			pw:   "pleaseletmein",
		},
		{
			// Real DES-crypt account from the production server's /etc/shadow.
			name: "traditional DES (old Linux) — testedragon",
			hash: "pae9A3UKpfaU6",
			pw:   "testedragon",
		},
		{
			name: "traditional DES (old Linux) — ipv6dragon",
			hash: "pa9eao3LI6u.6",
			pw:   "0tMGUL9chq8D",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := verifyCryptHash(c.hash, c.pw); err != nil {
				t.Errorf("correct password REJECTED: %v", err)
			}
			// Build a wrong password that differs in the FIRST character, so the
			// check is meaningful even for traditional DES (which only considers
			// the first 8 bytes of the password).
			wrong := "Z" + c.pw
			if err := verifyCryptHash(c.hash, wrong); err == nil {
				t.Errorf("wrong password ACCEPTED")
			}
		})
	}
}
