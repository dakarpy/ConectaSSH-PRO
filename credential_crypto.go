package main

import (
	"encoding/base64"
	"fmt"
	"strings"
)

func sealCredential(prefix, plain string) (string, error) {
	if plain == "" || strings.HasPrefix(plain, prefix) {
		return plain, nil
	}
	enc, err := encryptSecret(plain)
	if err != nil {
		return "", err
	}
	return prefix + base64.RawStdEncoding.EncodeToString(enc), nil
}

func openCredential(prefix, stored string) (string, error) {
	if !strings.HasPrefix(stored, prefix) {
		return stored, nil
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(stored, prefix))
	if err != nil {
		return "", fmt.Errorf("decode encrypted credential: %w", err)
	}
	return decryptSecret(raw)
}
