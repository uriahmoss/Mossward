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
