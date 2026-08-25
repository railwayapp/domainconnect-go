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
)

// parsePrivateKey parses a PEM-encoded RSA private key (PKCS8 or PKCS1).
func parsePrivateKey(privateKeyPEM []byte) (*rsa.PrivateKey, error) {
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

	return rsaKey, nil
}

// generateSignature creates an RSA-SHA256 signature over an encoded query string.
// Per spec the signature covers the full query string as sent (excluding sig and key),
// so callers must pass the exact string they put in the URL. Returns standard base64.
func generateSignature(query string, privateKeyPEM []byte) (string, error) {
	rsaKey, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		return "", err
	}

	// SHA256 hash
	hash := sha256.Sum256([]byte(query))

	// RSA sign
	sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}

	return base64.StdEncoding.EncodeToString(sig), nil
}

// signQuery appends key and sig to an encoded query string.
// sig is appended last (Cloudflare requirement).
func signQuery(query string, privateKeyPEM []byte, keyID string) (string, error) {
	sig, err := generateSignature(query, privateKeyPEM)
	if err != nil {
		return "", err
	}

	if keyID != "" {
		query += "&key=" + url.QueryEscape(keyID)
	}
	return query + "&sig=" + url.QueryEscape(sig), nil
}
