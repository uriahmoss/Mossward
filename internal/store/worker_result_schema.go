package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyScannerWorkerResultMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin scanner-worker result migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`ALTER TABLE scanner_worker_jobs ADD COLUMN result_id TEXT`,
		`ALTER TABLE scanner_worker_jobs ADD COLUMN result_outcome TEXT`,
		`ALTER TABLE scanner_worker_jobs ADD COLUMN completed_at TEXT`,
		`CREATE UNIQUE INDEX scanner_worker_jobs_result_id_idx ON scanner_worker_jobs(result_id) WHERE result_id IS NOT NULL`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply scanner-worker result migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(26,?)`, formatTime(time.Now().UTC())); err != nil {
		return fmt.Errorf("record scanner-worker result migration: %w", err)
	}
	return tx.Commit()
}
