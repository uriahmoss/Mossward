package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

func migratePostgreSQLEndpointCoverage(ctx context.Context, tx *sql.Tx) error {
	statements := []string{
		`CREATE TABLE endpoint_coverage_settings (
			singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK(singleton),enabled BOOLEAN NOT NULL,
			updated_by TEXT NOT NULL DEFAULT '',updated_at TIMESTAMPTZ
		)`,
		`INSERT INTO endpoint_coverage_settings(singleton,enabled) VALUES(TRUE,FALSE)`,
		`CREATE TABLE coverage_discovery_policies (
			id TEXT PRIMARY KEY,name TEXT NOT NULL,cidrs JSONB NOT NULL,enabled BOOLEAN NOT NULL,
			created_by TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL,updated_by TEXT NOT NULL,updated_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE INDEX coverage_discovery_policy_enabled_idx ON coverage_discovery_policies(enabled,name)`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate PostgreSQL endpoint coverage: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(22,$1)`, time.Now().UTC()); err != nil {
		return fmt.Errorf("record PostgreSQL endpoint-coverage migration: %w", err)
	}
	return nil
}
