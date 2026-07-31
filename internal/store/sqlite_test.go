package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mossward/internal/model"
)

func openTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	repository, err := NewSQLiteStore(filepath.Join(t.TempDir(), "mossward.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := repository.Close(); err != nil {
			t.Errorf("close test database: %v", err)
		}
	})
	return repository
}

func TestSQLiteStoreRoundTrip(t *testing.T) {
	repository := openTestStore(t)
	started := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	completed := time.Now().UTC().Truncate(time.Microsecond)
	original := model.Scan{
		ID: "round-trip", Name: "Full scan", Status: model.StatusCompleted,
		Targets: []model.Target{{Name: "host.internal", Address: "127.0.0.1"}},
		Ports:   []int{80, 443}, TotalChecks: 2, DoneChecks: 2,
		CreatedAt: started, StartedAt: &started, CompletedAt: &completed,
		Observations: []model.ServiceObservation{{
			ID: "service", Target: "host.internal", Address: "127.0.0.1", Port: 80,
			Protocol: "http", Product: "nginx", Version: "1.25", Confidence: "high",
			Evidence: "HTTP 200", Metadata: map[string]string{"title": "Home"}, ObservedAt: completed,
		}},
		Findings: []model.Finding{{
			ID: "finding", CheckID: "http.cleartext", Target: "host.internal",
			Address: "127.0.0.1", Port: 80, Service: "http", Severity: "medium",
			Title: "Cleartext HTTP", Evidence: "HTTP response", Remediation: "Use HTTPS",
			ObservedAt: completed,
		}},
	}
	if err := repository.Save(original); err != nil {
		t.Fatal(err)
	}
	loaded, err := repository.Get(original.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Name != original.Name || len(loaded.Targets) != 1 || len(loaded.Ports) != 2 ||
		len(loaded.Observations) != 1 || len(loaded.Findings) != 1 ||
		loaded.Observations[0].Metadata["title"] != "Home" {
		t.Fatalf("scan did not round-trip through SQLite: %#v", loaded)
	}
	if !loaded.StartedAt.Equal(started) || !loaded.CompletedAt.Equal(completed) {
		t.Fatalf("timestamps did not round-trip: %#v", loaded)
	}
}

func TestSQLiteStoreReconcileInterrupted(t *testing.T) {
	repository := openTestStore(t)
	scan := model.Scan{
		ID: "queued-scan", Name: "queued", Status: model.StatusQueued,
		CreatedAt: time.Now().UTC(),
	}
	if err := repository.Save(scan); err != nil {
		t.Fatal(err)
	}
	if err := repository.ReconcileInterrupted(); err != nil {
		t.Fatal(err)
	}
	reconciled, err := repository.Get(scan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reconciled.Status != model.StatusFailed || reconciled.CompletedAt == nil ||
		!strings.Contains(reconciled.Error, "interrupted") {
		t.Fatalf("missing interruption state: %#v", reconciled)
	}
}

func TestSQLiteDatabaseUsesOwnerOnlyPermissions(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "mossward.db")
	repository, err := NewSQLiteStore(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600 permissions, got %o", info.Mode().Perm())
	}
}

func TestSQLiteStoreReturnsIndependentValues(t *testing.T) {
	repository := openTestStore(t)
	original := model.Scan{
		ID: "copy-test", Status: model.StatusCompleted, CreatedAt: time.Now().UTC(),
		Targets:  []model.Target{{Name: "host", Address: "127.0.0.1"}},
		Ports:    []int{80},
		Findings: []model.Finding{{ID: "finding", ObservedAt: time.Now().UTC()}},
		Observations: []model.ServiceObservation{{
			ID: "service", Metadata: map[string]string{"server": "nginx"}, ObservedAt: time.Now().UTC(),
		}},
	}
	if err := repository.Save(original); err != nil {
		t.Fatal(err)
	}
	loaded, err := repository.Get(original.ID)
	if err != nil {
		t.Fatal(err)
	}
	loaded.Targets[0].Name = "changed"
	loaded.Ports[0] = 443
	loaded.Findings[0].ID = "changed"
	loaded.Observations[0].Metadata["server"] = "changed"

	unchanged, err := repository.Get(original.ID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Targets[0].Name != "host" || unchanged.Ports[0] != 80 ||
		unchanged.Findings[0].ID != "finding" || unchanged.Observations[0].Metadata["server"] != "nginx" {
		t.Fatalf("stored scan was mutated through a returned value: %#v", unchanged)
	}
}

func TestSQLiteStoreImportsAndArchivesLegacyJSON(t *testing.T) {
	directory := t.TempDir()
	legacyPath := filepath.Join(directory, "scans.json")
	legacy := `{"legacy":{"id":"legacy","name":"old scan","status":"completed","findings":[{"id":"open","target":"host","address":"127.0.0.1","port":80,"service":"http","severity":"info","evidence":"reachable","observed_at":"2026-01-01T00:00:00Z"}],"created_at":"2026-01-01T00:00:00Z"}}`
	if err := os.WriteFile(legacyPath, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	repository, err := NewSQLiteStore(filepath.Join(directory, "mossward.db"), legacyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	scan, err := repository.Get("legacy")
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Findings) != 0 || len(scan.Observations) != 1 || scan.Observations[0].Protocol != "http" {
		t.Fatalf("legacy scan was not normalized during import: %#v", scan)
	}
	if _, err := os.Stat(legacyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected original JSON file to be archived, got %v", err)
	}
	if _, err := os.Stat(legacyPath + ".imported"); err != nil {
		t.Fatalf("expected recoverable imported archive: %v", err)
	}
}

func TestSQLiteStoreListsNewestFirst(t *testing.T) {
	repository := openTestStore(t)
	for _, scan := range []model.Scan{
		{ID: "older", Status: model.StatusCompleted, CreatedAt: time.Now().UTC().Add(-time.Hour)},
		{ID: "newer", Status: model.StatusCompleted, CreatedAt: time.Now().UTC()},
	} {
		if err := repository.Save(scan); err != nil {
			t.Fatal(err)
		}
	}
	scans, err := repository.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(scans) != 2 || scans[0].ID != "newer" {
		t.Fatalf("unexpected scan ordering: %#v", scans)
	}
}

func TestSQLiteStoreReturnsNotFound(t *testing.T) {
	repository := openTestStore(t)
	_, err := repository.Get("missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}
