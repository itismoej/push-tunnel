package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	nonceSize = 12 // AES-GCM standard nonce
	keySize   = 32 // AES-256
	hkdfSalt  = "push-tunnel-v1"
)

// Crypto handles AES-256-GCM encryption with HKDF-derived keys.
type Crypto struct {
	aead cipher.AEAD
	key  []byte
}

// NewCrypto derives an AES-256 key from the PSK using HKDF-SHA256 and
// returns a ready-to-use Crypto instance.
func NewCrypto(psk string) (*Crypto, error) {
	hk := hkdf.New(sha256.New, []byte(psk), []byte(hkdfSalt), nil)
	key := make([]byte, keySize)
	if _, err := io.ReadFull(hk, key); err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Crypto{aead: aead, key: key}, nil
}

// Encrypt encrypts plaintext and returns base64(nonce || ciphertext || tag).
func (c *Crypto) Encrypt(plaintext []byte) (string, error) {
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := c.aead.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decodes base64 input and decrypts it.
func (c *Crypto) Decrypt(encoded string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	if len(data) < nonceSize+c.aead.Overhead() {
		return nil, errors.New("ciphertext too short")
	}
	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}

// ComputeAuthToken generates HMAC-SHA256(deviceID, timestamp) for request auth.
func ComputeAuthToken(deviceID string, timestamp string, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(deviceID + ":" + timestamp))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// VerifyAuthToken checks HMAC-SHA256 auth token.
func VerifyAuthToken(deviceID, timestamp, token string, key []byte) bool {
	expected := ComputeAuthToken(deviceID, timestamp, key)
	return hmac.Equal([]byte(expected), []byte(token))
}
