package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyScanPolicyExecutionMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin scan-policy execution migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`ALTER TABLE reusable_scan_policies ADD COLUMN execution_mode TEXT NOT NULL DEFAULT 'local' CHECK(execution_mode IN ('local','remote'))`,
		`ALTER TABLE reusable_scan_policies ADD COLUMN worker_site_id TEXT NOT NULL DEFAULT ''`,
		`CREATE INDEX reusable_scan_policies_execution_idx ON reusable_scan_policies(execution_mode,worker_site_id,enabled)`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply scan-policy execution migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(32,?)`, formatTime(time.Now().UTC())); err != nil {
		return fmt.Errorf("record scan-policy execution migration: %w", err)
	}
	return tx.Commit()
}
