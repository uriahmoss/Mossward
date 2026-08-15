package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyEndpointMaintenanceMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin endpoint maintenance migration: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(`CREATE TABLE endpoint_maintenance_windows (
		id TEXT PRIMARY KEY,name TEXT NOT NULL,target_type TEXT NOT NULL CHECK(target_type IN ('endpoint','group')),target_id TEXT NOT NULL,
		starts_at TEXT NOT NULL,ends_at TEXT NOT NULL,reason TEXT NOT NULL,created_by TEXT NOT NULL,created_at TEXT NOT NULL,
		cancelled_by TEXT NOT NULL DEFAULT '',cancelled_at TEXT)`)
	if err != nil {
		return fmt.Errorf("create endpoint maintenance windows: %w", err)
	}
	if _, err := tx.Exec(`CREATE INDEX endpoint_maintenance_active_idx ON endpoint_maintenance_windows(target_type,target_id,starts_at,ends_at,cancelled_at)`); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(58,?)`, formatTime(time.Now().UTC())); err != nil {
		return err
	}
	return tx.Commit()
}
