package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const identityKeyBytes = 32

type SecretBox struct {
	aead cipher.AEAD
}

func LoadOrCreateSecretBox(path string) (*SecretBox, error) {
	key, err := loadOrCreateIdentityKey(path)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("initialize identity encryption: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize identity encryption mode: %w", err)
	}
	return &SecretBox{aead: aead}, nil
}

func (box *SecretBox) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, box.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate encryption nonce: %w", err)
	}
	return box.aead.Seal(nonce, nonce, plaintext, nil), nil
}

func (box *SecretBox) Decrypt(ciphertext []byte) ([]byte, error) {
	nonceSize := box.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("encrypted identity value is truncated")
	}
	plaintext, err := box.aead.Open(nil, ciphertext[:nonceSize], ciphertext[nonceSize:], nil)
	if err != nil {
		return nil, errors.New("encrypted identity value could not be authenticated")
	}
	return plaintext, nil
}

func loadOrCreateIdentityKey(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if err == nil {
		if len(key) != identityKeyBytes {
			return nil, fmt.Errorf("identity key must be exactly %d bytes", identityKeyBytes)
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read identity key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create identity key directory: %w", err)
	}
	key = make([]byte, identityKeyBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate identity key: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return loadOrCreateIdentityKey(path)
	}
	if err != nil {
		return nil, fmt.Errorf("create identity key: %w", err)
	}
	if _, err := file.Write(key); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("write identity key: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close identity key: %w", err)
	}
	return key, nil
}
