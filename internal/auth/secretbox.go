package auth

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

const identityKeyBytes = 32
const keyIDBytes = 8
const keyringVersion = 1

var ciphertextEnvelope = []byte("MWK1")

type keyringFile struct {
	Version  int               `json:"version"`
	ActiveID string            `json:"active_id"`
	LegacyID string            `json:"legacy_id,omitempty"`
	Keys     map[string]string `json:"keys"`
}

type SecretBox struct {
	activeID string
	legacyID string
	keys     map[string]cipher.AEAD
}

func LoadOrCreateSecretBox(path string) (*SecretBox, error) {
	data, err := loadOrCreateIdentityKey(path)
	if err != nil {
		return nil, err
	}
	if err := validateIdentityKeyPermissions(path); err != nil {
		return nil, err
	}
	return parseSecretBox(data)
}

func ValidateIdentityKeyData(data []byte) error {
	_, err := parseSecretBox(data)
	return err
}

func BeginIdentityKeyRotation(path string) (*SecretBox, error) {
	if err := validateIdentityKeyPermissions(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read identity key: %w", err)
	}
	ring, err := decodeKeyring(data)
	if err != nil {
		if len(data) != identityKeyBytes {
			return nil, err
		}
		id := identityKeyID(data)
		ring = keyringFile{Version: keyringVersion, ActiveID: id, LegacyID: id,
			Keys: map[string]string{id: base64.StdEncoding.EncodeToString(data)}}
	}
	if len(ring.Keys) == 1 {
		key := make([]byte, identityKeyBytes)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		id := identityKeyID(key)
		ring.Keys[id] = base64.StdEncoding.EncodeToString(key)
		ring.ActiveID = id
		if err := writeKeyring(path, ring, true); err != nil {
			return nil, err
		}
	}
	encoded, _ := json.Marshal(ring)
	return parseSecretBox(encoded)
}

func validateIdentityKeyPermissions(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("identity key must not grant group or other access")
	}
	return nil
}

func (box *SecretBox) FinalizeIdentityKeyRotation(path string) error {
	key := box.keys[box.activeID]
	if key == nil {
		return errors.New("active identity key is unavailable")
	}
	// The raw key is not recoverable from cipher.AEAD, so retain encoded material
	// from the on-disk keyring while pruning inactive entries.
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	ring, err := decodeKeyring(data)
	if err != nil {
		return err
	}
	encodedKey := ring.Keys[box.activeID]
	final := keyringFile{Version: keyringVersion, ActiveID: box.activeID, LegacyID: box.activeID,
		Keys: map[string]string{box.activeID: encodedKey}}
	return writeKeyring(path, final, false)
}

func (box *SecretBox) Encrypt(plaintext []byte) ([]byte, error) {
	aead := box.keys[box.activeID]
	if aead == nil {
		return nil, errors.New("active identity encryption key is unavailable")
	}
	header := append(append([]byte{}, ciphertextEnvelope...), []byte(box.activeID)...)
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate encryption nonce: %w", err)
	}
	result := append(header, nonce...)
	return aead.Seal(result, nonce, plaintext, header), nil
}

func (box *SecretBox) Decrypt(ciphertext []byte) ([]byte, error) {
	keyID, payload, associatedData := box.ciphertextKey(ciphertext)
	aead := box.keys[keyID]
	if aead == nil {
		return nil, errors.New("encrypted identity value references an unavailable key")
	}
	nonceSize := aead.NonceSize()
	if len(payload) < nonceSize {
		return nil, errors.New("encrypted identity value is truncated")
	}
	plaintext, err := aead.Open(nil, payload[:nonceSize], payload[nonceSize:], associatedData)
	if err != nil {
		return nil, errors.New("encrypted identity value could not be authenticated")
	}
	return plaintext, nil
}

func (box *SecretBox) ciphertextKey(ciphertext []byte) (string, []byte, []byte) {
	headerSize := len(ciphertextEnvelope) + keyIDBytes*2
	if len(ciphertext) >= headerSize && bytes.Equal(ciphertext[:len(ciphertextEnvelope)], ciphertextEnvelope) {
		header := ciphertext[:headerSize]
		return string(ciphertext[len(ciphertextEnvelope):headerSize]), ciphertext[headerSize:], header
	}
	return box.legacyID, ciphertext, nil
}

func parseSecretBox(data []byte) (*SecretBox, error) {
	if len(data) == identityKeyBytes {
		id := identityKeyID(data)
		aead, err := newAEAD(data)
		return &SecretBox{activeID: id, legacyID: id, keys: map[string]cipher.AEAD{id: aead}}, err
	}
	ring, err := decodeKeyring(data)
	if err != nil {
		return nil, err
	}
	box := &SecretBox{activeID: ring.ActiveID, legacyID: ring.LegacyID, keys: map[string]cipher.AEAD{}}
	for id, encoded := range ring.Keys {
		key, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(key) != identityKeyBytes || identityKeyID(key) != id {
			return nil, fmt.Errorf("identity keyring contains invalid key %q", id)
		}
		aead, err := newAEAD(key)
		if err != nil {
			return nil, err
		}
		box.keys[id] = aead
	}
	if box.keys[box.activeID] == nil || box.keys[box.legacyID] == nil {
		return nil, errors.New("identity keyring references an unavailable key")
	}
	return box, nil
}

func decodeKeyring(data []byte) (keyringFile, error) {
	var ring keyringFile
	if err := json.Unmarshal(data, &ring); err != nil || ring.Version != keyringVersion || len(ring.Keys) == 0 {
		return keyringFile{}, errors.New("identity key file is neither a legacy key nor a supported keyring")
	}
	return ring, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("initialize identity encryption: %w", err)
	}
	return cipher.NewGCM(block)
}

func identityKeyID(key []byte) string {
	digest := sha256.Sum256(key)
	return hex.EncodeToString(digest[:keyIDBytes])
}

func loadOrCreateIdentityKey(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if err == nil {
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

func writeKeyring(path string, ring keyringFile, preserveCurrent bool) error {
	data, err := json.MarshalIndent(ring, "", "  ")
	if err != nil {
		return err
	}
	if preserveCurrent {
		current, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		recovery := path + ".pre-rotation-" + ring.ActiveID
		if err := os.WriteFile(recovery, current, 0o600); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("preserve pre-rotation identity key: %w", err)
		}
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".identity-key-rotation-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}
