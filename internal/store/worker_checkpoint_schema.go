package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyScannerWorkerCheckpointMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin scanner-worker checkpoint migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`CREATE TABLE scanner_worker_job_checkpoints (job_id TEXT NOT NULL REFERENCES scanner_worker_jobs(id),worker_id TEXT NOT NULL REFERENCES scanner_workers(id),scan_id TEXT NOT NULL,address TEXT NOT NULL,port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),completed_at TEXT NOT NULL,batch_id TEXT NOT NULL REFERENCES scanner_worker_evidence_batches(batch_id),PRIMARY KEY(job_id,address,port))`,
		`CREATE INDEX scanner_worker_checkpoints_scan_idx ON scanner_worker_job_checkpoints(scan_id,address,port)`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply scanner-worker checkpoint migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(28,?)`, formatTime(time.Now().UTC())); err != nil {
		return fmt.Errorf("record scanner-worker checkpoint migration: %w", err)
	}
	return tx.Commit()
}
