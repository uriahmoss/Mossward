package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

func migratePostgreSQLAgentModules(ctx context.Context, tx *sql.Tx) error {
	statements := []string{
		`ALTER TABLE endpoints ADD COLUMN asset_id TEXT REFERENCES assets(id)`,
		`CREATE INDEX endpoints_asset_idx ON endpoints(asset_id) WHERE asset_id IS NOT NULL`,
		`CREATE TABLE agent_module_publishers (
			key_id TEXT PRIMARY KEY,name TEXT NOT NULL,public_key BYTEA NOT NULL,enabled BOOLEAN NOT NULL,
			created_by TEXT NOT NULL REFERENCES users(id),created_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE TABLE agent_module_releases (
			id TEXT PRIMARY KEY,module_id TEXT NOT NULL,version TEXT NOT NULL,manifest JSONB NOT NULL,envelope BYTEA NOT NULL,
			status TEXT NOT NULL CHECK(status IN ('staged','approved','revoked')),
			created_by TEXT NOT NULL REFERENCES users(id),created_at TIMESTAMPTZ NOT NULL,
			approved_by TEXT REFERENCES users(id),approved_at TIMESTAMPTZ,revoked_by TEXT REFERENCES users(id),
			revoked_at TIMESTAMPTZ,revocation_reason TEXT NOT NULL DEFAULT '',UNIQUE(module_id,version)
		)`,
		`CREATE INDEX agent_module_release_status_idx ON agent_module_releases(status,module_id,version)`,
		`CREATE TABLE agent_module_assignments (
			id TEXT PRIMARY KEY,release_id TEXT NOT NULL REFERENCES agent_module_releases(id),
			target_type TEXT NOT NULL CHECK(target_type IN ('endpoint','group')),target_id TEXT NOT NULL,
			ring_percent INTEGER NOT NULL CHECK(ring_percent BETWEEN 1 AND 100),enabled BOOLEAN NOT NULL,
			created_by TEXT NOT NULL REFERENCES users(id),created_at TIMESTAMPTZ NOT NULL,
			UNIQUE(release_id,target_type,target_id)
		)`,
		`CREATE INDEX agent_module_assignment_target_idx ON agent_module_assignments(target_type,target_id,enabled)`,
		`CREATE TABLE agent_module_health (
			endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,module_id TEXT NOT NULL,version TEXT NOT NULL,
			healthy BOOLEAN NOT NULL,crash_count INTEGER NOT NULL CHECK(crash_count >= 0),error TEXT NOT NULL DEFAULT '',
			observed_at TIMESTAMPTZ NOT NULL,PRIMARY KEY(endpoint_id,module_id)
		)`,
		`CREATE TABLE agent_module_settings (
			singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK(singleton),enabled BOOLEAN NOT NULL
		)`,
		`INSERT INTO agent_module_settings(singleton,enabled) VALUES(TRUE,TRUE)`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate PostgreSQL endpoint modules: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(19,$1)`, time.Now().UTC()); err != nil {
		return fmt.Errorf("record PostgreSQL endpoint-module migration: %w", err)
	}
	return nil
}
