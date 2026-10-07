package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Preserve signed check trust and opt-in policy during database migration.
func migratePostgreSQLCheckCatalog(ctx context.Context, tx *sql.Tx) error {
	statements := []string{
		`CREATE TABLE check_publishers (key_id TEXT PRIMARY KEY,name TEXT NOT NULL,public_key BYTEA NOT NULL,status TEXT NOT NULL CHECK(status IN ('trusted','revoked')),added_at TIMESTAMPTZ NOT NULL,revoked_at TIMESTAMPTZ)`,
		`CREATE TABLE declarative_check_versions (check_id TEXT NOT NULL,version TEXT NOT NULL,kind TEXT NOT NULL,key_id TEXT NOT NULL REFERENCES check_publishers(key_id),envelope_json BYTEA NOT NULL,status TEXT NOT NULL CHECK(status IN ('staged','active','retired')),imported_at TIMESTAMPTZ NOT NULL,activated_at TIMESTAMPTZ,PRIMARY KEY(check_id,version))`,
		`CREATE UNIQUE INDEX declarative_checks_one_active_idx ON declarative_check_versions(check_id) WHERE status='active'`,
		`CREATE INDEX declarative_checks_publisher_idx ON declarative_check_versions(key_id,status)`,
		`CREATE TABLE intrusive_check_policy (id INTEGER PRIMARY KEY CHECK(id=1),enabled BOOLEAN NOT NULL,allowed_check_ids_json JSONB NOT NULL,updated_at TIMESTAMPTZ NOT NULL)`,
		`INSERT INTO intrusive_check_policy(id,enabled,allowed_check_ids_json,updated_at) VALUES(1,FALSE,'[]',CURRENT_TIMESTAMP)`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate PostgreSQL check catalog: %w", err)
		}
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(24,$1)`, time.Now().UTC())
	return err
}
