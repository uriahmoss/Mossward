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

func TestActivateAtomicallyReplacesExecutableAfterPersistingRollbackState(t *testing.T) {
	root := t.TempDir()
	executable := filepath.Join(root, "mossward-agent")
	candidate := filepath.Join(root, "candidate")
	if err := os.WriteFile(executable, []byte("old agent"), 0o755); err != nil {
		t.Fatal(err)
	}
	contents := []byte("new agent")
	if err := os.WriteFile(candidate, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(contents)
	now := time.Now().UTC()
	transaction := Transaction{SchemaVersion: 1, State: TransactionPrepared,
		Previous:      KnownGood{Version: "1.0.0", SHA256: strings.Repeat("a", 64), Size: 9, File: "known-good-1.0.0"},
		TargetVersion: "1.1.0", TargetSHA256: hex.EncodeToString(digest[:]), TargetSize: int64(len(contents)),
		StartedAt: now, HealthDeadline: now.Add(time.Minute)}
	stateDirectory := filepath.Join(root, "state")
	err := Activate(executable, candidate, stateDirectory, transaction)
	if !errors.Is(err, ErrRestartRequired) {
		t.Fatalf("activation error = %v", err)
	}
	installed, err := os.ReadFile(executable)
	if err != nil || string(installed) != string(contents) {
		t.Fatalf("installed executable = %q, error = %v", installed, err)
	}
	stored, err := LoadTransaction(stateDirectory)
	if err != nil || stored.State != TransactionAwaitingHealth {
		t.Fatalf("stored transaction = %#v, error = %v", stored, err)
	}
}

func TestActivateRejectsChangedCandidateWithoutReplacingExecutable(t *testing.T) {
	root := t.TempDir()
	executable := filepath.Join(root, "mossward-agent")
	candidate := filepath.Join(root, "candidate")
	if err := os.WriteFile(executable, []byte("old agent"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(candidate, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	transaction := Transaction{SchemaVersion: 1, State: TransactionPrepared,
		Previous:      KnownGood{Version: "1.0.0", SHA256: strings.Repeat("a", 64), Size: 9, File: "known-good-1.0.0"},
		TargetVersion: "1.1.0", TargetSHA256: strings.Repeat("b", 64), TargetSize: 8,
		StartedAt: now, HealthDeadline: now.Add(time.Minute)}
	if err := Activate(executable, candidate, filepath.Join(root, "state"), transaction); err == nil {
		t.Fatal("changed candidate was activated")
	}
	installed, _ := os.ReadFile(executable)
	if string(installed) != "old agent" {
		t.Fatalf("executable changed to %q", installed)
	}
}
