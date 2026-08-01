package auth

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
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
