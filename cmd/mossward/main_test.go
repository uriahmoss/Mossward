package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"mossward/internal/config"
)

func TestOpenRepositoryUsesSQLiteByDefault(t *testing.T) {
	cfg := config.Config{DatabaseBackend: config.DatabaseSQLite,
		DatabaseFile: filepath.Join(t.TempDir(), "mossward.db")}
	repository, err := openRepository(context.Background(), cfg)
	if err != nil {
		t.Fatalf("open SQLite repository: %v", err)
	}
	t.Cleanup(func() {
		if err := repository.Close(); err != nil {
			t.Errorf("close SQLite repository: %v", err)
		}
	})
	if _, err := requireSQLiteMaintenanceRepository(cfg, repository); err != nil {
		t.Fatalf("authorize SQLite maintenance repository: %v", err)
	}
}

func TestOpenRepositoryRejectsUnknownBackend(t *testing.T) {
	_, err := openRepository(context.Background(), config.Config{DatabaseBackend: "unknown"})
	if err == nil || !strings.Contains(err.Error(), "unsupported database backend") {
		t.Fatalf("unknown database backend error = %v", err)
	}
}

func TestPostgreSQLMaintenanceRequiresSQLiteRepository(t *testing.T) {
	cfg := config.Config{DatabaseBackend: config.DatabasePostgreSQL}
	if _, err := requireSQLiteMaintenanceRepository(cfg, nil); err == nil ||
		!strings.Contains(err.Error(), "require the SQLite backend") {
		t.Fatalf("PostgreSQL maintenance backend error = %v", err)
	}
}

func TestDatabaseMigrationRequiresOfflineConfirmation(t *testing.T) {
	if err := runDatabaseCommand(config.Config{DatabaseBackend: config.DatabaseSQLite}, []string{"migrate-postgresql"}); err == nil {
		t.Fatal("migration accepted without offline confirmation")
	}
	if err := runDatabaseCommand(config.Config{DatabaseBackend: config.DatabasePostgreSQL}, []string{"migrate-postgresql", "--confirm-offline"}); err == nil {
		t.Fatal("migration accepted without SQLite source backend")
	}
}
