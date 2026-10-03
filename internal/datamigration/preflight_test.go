package datamigration

import (
	"context"
	"path/filepath"
	"testing"

	"mossward/internal/store"
)

func TestPreflightSQLiteSourceReportsIntegrityAndInventory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mossward.db")
	repository, err := store.NewSQLiteStore(path, "")
	if err != nil {
		t.Fatalf("create SQLite migration source: %v", err)
	}
	if err := repository.Close(); err != nil {
		t.Fatalf("close SQLite migration source: %v", err)
	}
	report, err := PreflightSQLiteSource(context.Background(), path)
	if err != nil {
		t.Fatalf("preflight SQLite migration source: %v", err)
	}
	if report.Path != path || report.SizeBytes == 0 || report.SchemaVersion == 0 || report.TableCount == 0 || len(report.Tables) != report.TableCount {
		t.Fatalf("unexpected SQLite migration source report: %#v", report)
	}
	foundMigrations := false
	for _, table := range report.Tables {
		if table.Name == "schema_migrations" {
			foundMigrations = true
			if table.Rows == 0 {
				t.Fatal("SQLite migration source has no recorded migrations")
			}
		}
	}
	if !foundMigrations {
		t.Fatal("SQLite migration source report omitted schema_migrations")
	}
}

func TestPreflightSQLiteSourceRejectsMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.db")
	if _, err := PreflightSQLiteSource(context.Background(), path); err == nil {
		t.Fatal("missing SQLite migration source was accepted")
	}
}
