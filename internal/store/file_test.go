package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mossward/internal/model"
)

func TestReconcileInterruptedMarksUnfinishedScansFailed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scans.json")
	repository, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	scan := model.Scan{
		ID: "queued-scan", Name: "queued", Status: model.StatusQueued,
		CreatedAt: time.Now().UTC(),
	}
	if err := repository.Save(scan); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.ReconcileInterrupted(); err != nil {
		t.Fatal(err)
	}
	reconciled, err := reopened.Get(scan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reconciled.Status != model.StatusFailed {
		t.Fatalf("expected failed status, got %q", reconciled.Status)
	}
	if reconciled.CompletedAt == nil || !strings.Contains(reconciled.Error, "interrupted") {
		t.Fatalf("missing interruption details: %#v", reconciled)
	}
}

func TestStorePersistsOwnerOnlyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scans.json")
	repository, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Save(model.Scan{ID: "one", Status: model.StatusCompleted}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600 permissions, got %o", info.Mode().Perm())
	}
}

func TestStoreReturnsDefensiveCopies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scans.json")
	repository, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	original := model.Scan{
		ID:       "copy-test",
		Status:   model.StatusCompleted,
		Targets:  []model.Target{{Name: "host", Address: "127.0.0.1"}},
		Ports:    []int{80},
		Findings: []model.Finding{{ID: "finding"}},
		Observations: []model.ServiceObservation{{
			ID: "service", Metadata: map[string]string{"server": "nginx"},
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
		t.Fatalf("stored scan was mutated through a returned copy: %#v", unchanged)
	}
}

func TestStoreMigratesLegacyReachabilityFindings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scans.json")
	legacy := `{"legacy":{"id":"legacy","status":"completed","findings":[{"id":"open","target":"host","address":"127.0.0.1","port":80,"service":"http","severity":"info","evidence":"reachable","observed_at":"2026-01-01T00:00:00Z"}],"created_at":"2026-01-01T00:00:00Z"}}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	repository, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	scan, err := repository.Get("legacy")
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Findings) != 0 || len(scan.Observations) != 1 || scan.Observations[0].Protocol != "http" {
		t.Fatalf("legacy reachability finding was not migrated: %#v", scan)
	}
}
