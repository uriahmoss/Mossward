package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyScannerWorkerSiteMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin scanner-worker site migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`ALTER TABLE scanner_worker_enrollment_tokens ADD COLUMN site_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE scanner_workers ADD COLUMN site_id TEXT NOT NULL DEFAULT ''`,
		`CREATE INDEX scanner_workers_site_status_idx ON scanner_workers(site_id,status)`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply scanner-worker site migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(29,?)`, formatTime(time.Now().UTC())); err != nil {
		return fmt.Errorf("record scanner-worker site migration: %w", err)
	}
	return tx.Commit()
}
