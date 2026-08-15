package agentapp

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHashFilesDetectsContentChangesWithoutReturningContents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-key.pem")
	if err := os.WriteFile(path, []byte("private material"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := hashFiles(path)
	if err != nil || len(first) != 64 || first == "private material" {
		t.Fatalf("first fingerprint = %q, error = %v", first, err)
	}
	if err := os.WriteFile(path, []byte("changed material"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := hashFiles(path)
	if err != nil || second == first {
		t.Fatalf("second fingerprint = %q, first = %q, error = %v", second, first, err)
	}
}

func TestHashFileStatesStillFingerprintsMissingFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	hash, err := hashFileStates(path)
	if err == nil || len(hash) != 64 {
		t.Fatalf("missing-file fingerprint = %q, error = %v", hash, err)
	}
}
