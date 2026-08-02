package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyScannerWorkerEvidenceMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin scanner-worker evidence migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`CREATE TABLE scanner_worker_evidence_batches (batch_id TEXT PRIMARY KEY,job_id TEXT NOT NULL REFERENCES scanner_worker_jobs(id),worker_id TEXT NOT NULL REFERENCES scanner_workers(id),scan_id TEXT NOT NULL,sequence INTEGER NOT NULL CHECK(sequence>0),final INTEGER NOT NULL CHECK(final IN (0,1)),certificate_serial TEXT NOT NULL,signed_envelope TEXT NOT NULL,collected_at TEXT NOT NULL,received_at TEXT NOT NULL,UNIQUE(job_id,sequence))`,
		`CREATE INDEX scanner_worker_evidence_job_idx ON scanner_worker_evidence_batches(job_id,sequence)`,
		`CREATE INDEX scanner_worker_evidence_scan_idx ON scanner_worker_evidence_batches(scan_id,received_at)`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply scanner-worker evidence migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(27,?)`, formatTime(time.Now().UTC())); err != nil {
		return fmt.Errorf("record scanner-worker evidence migration: %w", err)
	}
	return tx.Commit()
}
