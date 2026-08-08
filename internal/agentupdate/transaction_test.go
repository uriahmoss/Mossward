package agentupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestPreserveKnownGoodCopiesBoundedExecutable(t *testing.T) {
	root := t.TempDir()
	executable := filepath.Join(root, "mossward-agent")
	contents := []byte("known good executable")
	if err := os.WriteFile(executable, contents, 0o700); err != nil {
		t.Fatal(err)
	}
	backupDirectory := filepath.Join(root, "updates")
	knownGood, err := PreserveKnownGood(executable, backupDirectory, "1.2.2")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(contents)
	if knownGood.SHA256 != hex.EncodeToString(digest[:]) || knownGood.Size != int64(len(contents)) {
		t.Fatalf("known-good metadata = %#v", knownGood)
	}
	stored, err := os.ReadFile(filepath.Join(backupDirectory, knownGood.File))
	if err != nil || string(stored) != string(contents) {
		t.Fatalf("known-good contents = %q, error = %v", stored, err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(backupDirectory, knownGood.File))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o500 {
			t.Fatalf("known-good mode = %v", info.Mode().Perm())
		}
	}
}

func TestTransactionRoundTripAndRollbackDeadline(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	previous := KnownGood{Version: "1.2.2", SHA256: strings.Repeat("a", 64), Size: 1024, File: "known-good-1.2.2"}
	manifest := validManifest(now)
	transaction, err := NewTransaction(previous, manifest, now)
	if err != nil {
		t.Fatal(err)
	}
	transaction.State = TransactionAwaitingHealth
	directory := filepath.Join(t.TempDir(), "updates")
	if err := SaveTransaction(directory, transaction); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadTransaction(directory)
	if err != nil || loaded.TargetVersion != manifest.Version {
		t.Fatalf("loaded transaction = %#v, error = %v", loaded, err)
	}
	if loaded.RequiresRollback(now.Add(30 * time.Second)) {
		t.Fatal("rollback was required before the health deadline")
	}
	if !loaded.RequiresRollback(loaded.HealthDeadline) {
		t.Fatal("rollback was not required at the health deadline")
	}
}

func TestTransactionRejectsPathInjectionAndUnknownFields(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	previous := KnownGood{Version: "1.2.2", SHA256: strings.Repeat("a", 64), Size: 1024, File: "../agent"}
	if _, err := NewTransaction(previous, validManifest(now), now); err == nil {
		t.Fatal("known-good path traversal was accepted")
	}
	directory := t.TempDir()
	data := `{"schema_version":1,"state":"prepared","unknown":true}`
	if err := os.WriteFile(filepath.Join(directory, transactionFileName), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTransaction(directory); err == nil {
		t.Fatal("unknown transaction field was accepted")
	}
}

func TestConfirmHealthyCommitsOnlyMatchingVersionBeforeDeadline(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	previous := KnownGood{Version: "1.2.2", SHA256: strings.Repeat("a", 64), Size: 1024, File: "known-good-1.2.2"}
	transaction, err := NewTransaction(previous, validManifest(now), now)
	if err != nil {
		t.Fatal(err)
	}
	transaction.State = TransactionAwaitingHealth
	directory := filepath.Join(t.TempDir(), "updates")
	if err := SaveTransaction(directory, transaction); err != nil {
		t.Fatal(err)
	}
	if err := ConfirmHealthy(directory, "wrong-version", now.Add(time.Second)); err == nil {
		t.Fatal("mismatched running version committed the update")
	}
	if err := ConfirmHealthy(directory, transaction.TargetVersion, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadTransaction(directory)
	if err != nil || loaded.State != TransactionCommitted {
		t.Fatalf("committed transaction = %#v, error = %v", loaded, err)
	}
}
