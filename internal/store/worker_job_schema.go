package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyScannerWorkerJobMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin scanner-worker job migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`CREATE TABLE scanner_worker_jobs (id TEXT PRIMARY KEY,worker_id TEXT NOT NULL REFERENCES scanner_workers(id),scan_id TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN ('pending','leased','completed','canceled','expired')),signed_envelope TEXT NOT NULL,issued_at TEXT NOT NULL,expires_at TEXT NOT NULL,created_at TEXT NOT NULL)`,
		`CREATE INDEX scanner_worker_jobs_worker_status_idx ON scanner_worker_jobs(worker_id,status,expires_at)`,
		`CREATE INDEX scanner_worker_jobs_scan_idx ON scanner_worker_jobs(scan_id)`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply scanner-worker job migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(24,?)`, formatTime(time.Now().UTC())); err != nil {
		return fmt.Errorf("record scanner-worker job migration: %w", err)
	}
	return tx.Commit()
}
