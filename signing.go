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
	"time"
)

// generateSignature creates RSA-SHA256 signature for Domain Connect.
// Per spec: sign the full query string excluding sig and key params.
// queryParams should be the URL-encoded query string to sign.
func generateSignature(queryParams url.Values, privateKeyPEM []byte, keyID string) (sig string, sigts string, err error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return "", "", fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return "", "", fmt.Errorf("parse private key: %w", err)
		}
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return "", "", fmt.Errorf("expected RSA private key")
	}

	// Generate timestamp
	sigts = fmt.Sprintf("%d", time.Now().Unix())

	// Clone params and add sigts
	signParams := url.Values{}
	for k, v := range queryParams {
		if k != "sig" && k != "key" {
			signParams[k] = v
		}
	}
	signParams.Set("sigts", sigts)

	// Encode produces sorted key=value pairs joined by &
	dataToSign := signParams.Encode()

	// SHA256 hash and RSA sign
	hash := sha256.Sum256([]byte(dataToSign))
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", "", fmt.Errorf("sign: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(sigBytes), sigts, nil
}
