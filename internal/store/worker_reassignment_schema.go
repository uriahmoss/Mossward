package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyScannerWorkerReassignmentMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin scanner-worker reassignment migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`CREATE TABLE scanner_worker_job_assignments (job_id TEXT NOT NULL REFERENCES scanner_worker_jobs(id),attempt INTEGER NOT NULL CHECK(attempt>0),worker_id TEXT NOT NULL REFERENCES scanner_workers(id),signed_envelope TEXT NOT NULL,assigned_at TEXT NOT NULL,reason TEXT NOT NULL,PRIMARY KEY(job_id,attempt))`,
		`CREATE INDEX scanner_worker_job_assignments_worker_idx ON scanner_worker_job_assignments(worker_id,assigned_at)`,
		`INSERT INTO scanner_worker_job_assignments(job_id,attempt,worker_id,signed_envelope,assigned_at,reason) SELECT id,1,worker_id,signed_envelope,created_at,'initial' FROM scanner_worker_jobs`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply scanner-worker reassignment migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(30,?)`, formatTime(time.Now().UTC())); err != nil {
		return fmt.Errorf("record scanner-worker reassignment migration: %w", err)
	}
	return tx.Commit()
}
