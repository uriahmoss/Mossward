package datamigration

import (
	"context"
	"os"
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
	if report.Path != path || report.SizeBytes == 0 || report.SchemaVersion == 0 || report.TableCount == 0 ||
		len(report.Tables) != report.TableCount || len(report.CopyOrder) != report.TableCount-1 {
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
	if containsString(report.CopyOrder, "schema_migrations") || !containsString(report.Excluded, "schema_migrations") {
		t.Fatalf("SQLite migration control-table plan changed: %#v", report)
	}
	if stringIndex(report.CopyOrder, "users") > stringIndex(report.CopyOrder, "sessions") {
		t.Fatalf("SQLite migration dependency order places sessions before users: %#v", report.CopyOrder)
	}
}

func stringIndex(values []string, wanted string) int {
	for index, value := range values {
		if value == wanted {
			return index
		}
	}
	return -1
}

func TestPreflightSQLiteSourceRejectsMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.db")
	if _, err := PreflightSQLiteSource(context.Background(), path); err == nil {
		t.Fatal("missing SQLite migration source was accepted")
	}
}

func TestPreflightSQLiteSourceAcceptsRelativePath(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "relative.db")
	repository, err := store.NewSQLiteStore(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Close(); err != nil {
		t.Fatal(err)
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relativePath, err := filepath.Rel(workingDirectory, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PreflightSQLiteSource(context.Background(), relativePath); err != nil {
		t.Fatalf("preflight relative SQLite migration source: %v", err)
	}
}
