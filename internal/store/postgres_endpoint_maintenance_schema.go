package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

func migratePostgreSQLEndpointMaintenance(ctx context.Context, tx *sql.Tx) error {
	statements := []string{
		`CREATE TABLE endpoint_maintenance_windows (
			id TEXT PRIMARY KEY,name TEXT NOT NULL,target_type TEXT NOT NULL CHECK(target_type IN ('endpoint','group')),
			target_id TEXT NOT NULL,starts_at TIMESTAMPTZ NOT NULL,ends_at TIMESTAMPTZ NOT NULL,
			reason TEXT NOT NULL,created_by TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL,
			cancelled_by TEXT NOT NULL DEFAULT '',cancelled_at TIMESTAMPTZ,CHECK(ends_at > starts_at),
			CHECK((cancelled_at IS NULL AND cancelled_by='') OR (cancelled_at IS NOT NULL AND cancelled_by<>''))
		)`,
		`CREATE INDEX endpoint_maintenance_active_idx ON endpoint_maintenance_windows
			(target_type,target_id,starts_at,ends_at,cancelled_at)`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate PostgreSQL endpoint maintenance: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(21,$1)`, time.Now().UTC()); err != nil {
		return fmt.Errorf("record PostgreSQL endpoint-maintenance migration: %w", err)
	}
	return nil
}
