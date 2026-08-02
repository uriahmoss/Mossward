package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyScannerWorkerHeartbeatMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin scanner-worker heartbeat migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`ALTER TABLE scanner_workers ADD COLUMN software_version TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE scanner_workers ADD COLUMN operating_system TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE scanner_workers ADD COLUMN architecture TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE scanner_workers ADD COLUMN capabilities TEXT NOT NULL DEFAULT '[]'`,
		`ALTER TABLE scanner_workers ADD COLUMN available_concurrency INTEGER NOT NULL DEFAULT 0 CHECK(available_concurrency BETWEEN 0 AND 256)`,
		`ALTER TABLE scanner_workers ADD COLUMN health TEXT NOT NULL DEFAULT 'healthy' CHECK(health IN ('healthy','degraded'))`,
		`ALTER TABLE scanner_workers ADD COLUMN health_message TEXT NOT NULL DEFAULT ''`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply scanner-worker heartbeat migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(23,?)`, formatTime(time.Now().UTC())); err != nil {
		return fmt.Errorf("record scanner-worker heartbeat migration: %w", err)
	}
	return tx.Commit()
}
