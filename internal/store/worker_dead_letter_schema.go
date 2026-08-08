package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyScannerWorkerDeadLetterMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin scanner-worker dead-letter migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`CREATE TABLE scanner_worker_job_dead_letters (job_id TEXT PRIMARY KEY REFERENCES scanner_worker_jobs(id),scan_id TEXT NOT NULL,worker_id TEXT NOT NULL REFERENCES scanner_workers(id),failure_count INTEGER NOT NULL CHECK(failure_count>0),reason TEXT NOT NULL,quarantined_at TEXT NOT NULL)`,
		`CREATE INDEX scanner_worker_dead_letters_time_idx ON scanner_worker_job_dead_letters(quarantined_at DESC)`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply scanner-worker dead-letter migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(33,?)`, formatTime(time.Now().UTC())); err != nil {
		return fmt.Errorf("record scanner-worker dead-letter migration: %w", err)
	}
	return tx.Commit()
}
