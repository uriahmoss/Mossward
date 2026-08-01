package auth

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"mossward/internal/store"
)

func TestSecretBoxPersistsKeyAndAuthenticatesCiphertext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.key")
	box, err := LoadOrCreateSecretBox(path)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := box.Encrypt([]byte("TOTP secret"))
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadOrCreateSecretBox(path)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := reloaded.Decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, []byte("TOTP secret")) {
		t.Fatalf("unexpected plaintext %q", plaintext)
	}
	ciphertext[len(ciphertext)-1] ^= 1
	if _, err := reloaded.Decrypt(ciphertext); err == nil {
		t.Fatal("tampered ciphertext was accepted")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("identity key permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestIdentityKeyRotationReencryptsStoredSecrets(t *testing.T) {
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "identity.key")
	repository, err := store.NewSQLiteStore(filepath.Join(directory, "mossward.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	oldBox, err := LoadOrCreateSecretBox(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewWebAuthnManager("localhost", []string{"http://localhost:8080"})
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(repository, oldBox, manager)
	if err != nil {
		t.Fatal(err)
	}
	user := completeTestBootstrap(t, service, BootstrapRequest{Email: "rotate@example.test", DisplayName: "Rotate",
		Password: "correct horse battery staple"})
	before, _, err := repository.TOTPSecret(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	rotationBox, err := BeginIdentityKeyRotation(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if plaintext, err := rotationBox.Decrypt(before); err != nil || len(plaintext) == 0 {
		t.Fatalf("rotation keyring could not read legacy ciphertext: %v", err)
	}
	if count, err := repository.RotateIdentityCiphertexts(rotationBox, time.Now().UTC()); err != nil || count < 1 {
		t.Fatalf("rotate stored ciphertexts: count=%d err=%v", count, err)
	}
	after, _, err := repository.TOTPSecret(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, after) || !bytes.HasPrefix(after, ciphertextEnvelope) {
		t.Fatal("stored secret was not moved to the versioned ciphertext envelope")
	}
	if err := rotationBox.FinalizeIdentityKeyRotation(keyPath); err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadOrCreateSecretBox(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reloaded.Decrypt(after); err != nil {
		t.Fatalf("final keyring could not decrypt rotated data: %v", err)
	}
	if _, err := reloaded.Decrypt(before); err == nil {
		t.Fatal("final keyring retained the retired key")
	}
}
