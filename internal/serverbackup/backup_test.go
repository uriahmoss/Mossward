package serverbackup

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"mossward/internal/store"
)

func TestBackupInspectAndRestore(t *testing.T) {
	directory := t.TempDir()
	databasePath := filepath.Join(directory, "data", "mossward.db")
	identityPath := filepath.Join(directory, "data", "identity.key")
	acmeDirectory := filepath.Join(directory, "data", "acme")
	pkiDirectory := filepath.Join(directory, "data", "agent-pki")
	writeTestFile(t, identityPath, make([]byte, 32))
	writeTestFile(t, filepath.Join(acmeDirectory, "account"), []byte("acme-account"))
	writeTestFile(t, filepath.Join(pkiDirectory, "root-key"), []byte("pki-key"))
	repository, err := store.NewSQLiteStore(databasePath, "")
	if err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(directory, "backups", "mossward.tar.gz")
	now := time.Now().UTC().Truncate(time.Microsecond)
	if err := Create(archive, repository, Source{IdentityKeyFile: identityPath,
		ACMECacheDir: acmeDirectory, AgentPKIDir: pkiDirectory}, now); err != nil {
		t.Fatal(err)
	}
	if err := repository.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(archive)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("backup archive is not owner-only: %v", err)
	}
	manifest, err := Inspect(archive)
	if err != nil || manifest.FormatVersion != FormatVersion || manifest.SchemaVersion < 1 || len(manifest.Files) != 4 {
		t.Fatalf("unexpected manifest: %#v %v", manifest, err)
	}
	writeTestFile(t, databasePath, []byte("not a database"))
	writeTestFile(t, identityPath, []byte("replacement"))
	if err := os.RemoveAll(acmeDirectory); err != nil {
		t.Fatal(err)
	}
	result, err := Restore(archive, RestoreTargets{DatabaseFile: databasePath, IdentityKeyFile: identityPath,
		ACMECacheDir: acmeDirectory, AgentPKIDir: pkiDirectory}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.RecoveryPaths) < 3 {
		t.Fatalf("expected recoverable pre-restore paths, got %#v", result.RecoveryPaths)
	}
	if _, err := store.ValidateSQLiteSnapshot(databasePath); err != nil {
		t.Fatalf("restored database is invalid: %v", err)
	}
	identity, err := os.ReadFile(identityPath)
	if err != nil || len(identity) != 32 {
		t.Fatalf("identity key was not restored: %v", err)
	}
	if value, err := os.ReadFile(filepath.Join(acmeDirectory, "account")); err != nil || string(value) != "acme-account" {
		t.Fatalf("ACME state was not restored: %q %v", value, err)
	}
}

func TestSafeArchivePathRejectsTraversal(t *testing.T) {
	for _, path := range []string{"../identity.key", "/etc/passwd", "nested/../../escape", ""} {
		if safeArchivePath(path) {
			t.Errorf("unsafe path accepted: %q", path)
		}
	}
}

func TestRestoreRejectsOverlappingDestinations(t *testing.T) {
	directory := t.TempDir()
	targets := RestoreTargets{DatabaseFile: filepath.Join(directory, "data", "mossward.db"),
		IdentityKeyFile: filepath.Join(directory, "data", "identity.key"), ACMECacheDir: filepath.Join(directory, "data")}
	if err := validateRestoreTargets(targets); err == nil {
		t.Fatal("expected overlapping restore destination rejection")
	}
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
