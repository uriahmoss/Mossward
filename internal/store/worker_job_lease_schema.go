package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyScannerWorkerJobLeaseMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin scanner-worker job lease migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`ALTER TABLE scanner_worker_jobs ADD COLUMN lease_token_hash BLOB`,
		`ALTER TABLE scanner_worker_jobs ADD COLUMN lease_expires_at TEXT`,
		`ALTER TABLE scanner_worker_jobs ADD COLUMN lease_attempt INTEGER NOT NULL DEFAULT 0`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply scanner-worker job lease migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(25,?)`, formatTime(time.Now().UTC())); err != nil {
		return fmt.Errorf("record scanner-worker job lease migration: %w", err)
	}
	return tx.Commit()
}
