package domainconnect

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// generateSignature creates RSA-SHA256 signature parameters for Domain Connect.
// Returns map with "sig", "key" and optionally other signing params.
func generateSignature(domain, host string, params map[string]string, privateKeyPEM []byte, keyID string) (map[string]string, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS1 format
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected RSA private key")
	}

	// Generate timestamp first since it must be included in signature
	sigts := fmt.Sprintf("%d", time.Now().Unix())

	// Build signature data: domain + host + sorted params + sigts
	sigData := url.Values{}
	sigData.Set("domain", domain)
	if host != "" {
		sigData.Set("host", host)
	}

	// Add params in sorted order
	var keys []string
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		sigData.Set(k, params[k])
	}

	// Add sigts to signed data (required by Domain Connect spec)
	sigData.Set("sigts", sigts)

	// Build the string to sign (sorted by key)
	var parts []string
	sortedKeys := make([]string, 0, len(sigData))
	for k := range sigData {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)
	for _, k := range sortedKeys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, sigData.Get(k)))
	}
	dataToSign := strings.Join(parts, "&")

	// SHA256 hash
	hash := sha256.Sum256([]byte(dataToSign))

	// RSA sign
	sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hash[:])
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	result := map[string]string{
		"sig":   base64.RawURLEncoding.EncodeToString(sig),
		"sigts": sigts,
	}
	if keyID != "" {
		result["key"] = keyID
	}

	return result, nil
}
