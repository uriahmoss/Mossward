//go:build !windows

package agentupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRecoverRestoresKnownGoodAfterMissedHealthDeadline(t *testing.T) {
	root := t.TempDir()
	stateDirectory := filepath.Join(root, "updates")
	if err := os.Mkdir(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(root, "mossward-agent")
	if err := os.WriteFile(executable, []byte("unhealthy replacement"), 0o755); err != nil {
		t.Fatal(err)
	}
	knownGoodContents := []byte("known good")
	knownGoodFile := "known-good-1.0.0"
	if err := os.WriteFile(filepath.Join(stateDirectory, knownGoodFile), knownGoodContents, 0o500); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(knownGoodContents)
	now := time.Now().UTC()
	transaction := Transaction{SchemaVersion: 1, State: TransactionAwaitingHealth,
		Previous:      KnownGood{Version: "1.0.0", SHA256: hex.EncodeToString(digest[:]), Size: int64(len(knownGoodContents)), File: knownGoodFile},
		TargetVersion: "1.1.0", TargetSHA256: strings.Repeat("b", 64), TargetSize: 20,
		StartedAt: now.Add(-2 * time.Minute), HealthDeadline: now.Add(-time.Minute)}
	if err := SaveTransaction(stateDirectory, transaction); err != nil {
		t.Fatal(err)
	}
	if err := Recover(executable, stateDirectory, now); !errors.Is(err, ErrRestartRequired) {
		t.Fatalf("recovery error = %v", err)
	}
	restored, err := os.ReadFile(executable)
	if err != nil || string(restored) != string(knownGoodContents) {
		t.Fatalf("restored executable = %q, error = %v", restored, err)
	}
	loaded, err := LoadTransaction(stateDirectory)
	if err != nil || loaded.State != TransactionRolledBack {
		t.Fatalf("rollback transaction = %#v, error = %v", loaded, err)
	}
	if err := Recover(executable, stateDirectory, now.Add(time.Minute)); err != nil {
		t.Fatalf("completed rollback repeated: %v", err)
	}
}
