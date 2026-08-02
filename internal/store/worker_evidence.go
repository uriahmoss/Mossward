package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"mossward/internal/model"
)

func (s *SQLiteStore) RecordScannerWorkerEvidenceBatch(envelope model.SignedWorkerEvidenceBatch, receivedAt time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin scanner-worker evidence recording: %w", err)
	}
	defer tx.Rollback()
	var existing string
	err = tx.QueryRow(`SELECT batch_id FROM scanner_worker_evidence_batches WHERE batch_id=?`, envelope.Batch.ID).Scan(&existing)
	if err == nil {
		return ErrWorkerEvidenceReplay
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("check scanner-worker evidence replay: %w", err)
	}
	if err := validateEvidenceSequence(tx, envelope.Batch, receivedAt); err != nil {
		return err
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("encode scanner-worker evidence batch: %w", err)
	}
	_, err = tx.Exec(`INSERT INTO scanner_worker_evidence_batches(batch_id,job_id,worker_id,scan_id,sequence,final,certificate_serial,signed_envelope,collected_at,received_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, envelope.Batch.ID, envelope.Batch.JobID, envelope.Batch.WorkerID, envelope.Batch.ScanID, envelope.Batch.Sequence, envelope.Batch.Final, envelope.CertificateSerial, encoded, formatTime(envelope.Batch.CollectedAt), formatTime(receivedAt))
	if err != nil {
		return fmt.Errorf("record scanner-worker evidence batch: %w", err)
	}
	return tx.Commit()
}

func validateEvidenceSequence(tx *sql.Tx, batch model.WorkerEvidenceBatch, receivedAt time.Time) error {
	var workerID, scanID, status, expiresAt string
	if err := tx.QueryRow(`SELECT worker_id,scan_id,status,expires_at FROM scanner_worker_jobs WHERE id=?`, batch.JobID).Scan(&workerID, &scanID, &status, &expiresAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrInvalidWorkerJobLease
		}
		return fmt.Errorf("read scanner-worker evidence job: %w", err)
	}
	if workerID != batch.WorkerID || scanID != batch.ScanID || status != string(model.WorkerJobLeased) || expiresAt <= formatTime(receivedAt) {
		return ErrInvalidWorkerJobLease
	}
	var lastSequence uint64
	var final bool
	err := tx.QueryRow(`SELECT sequence,final FROM scanner_worker_evidence_batches WHERE job_id=? ORDER BY sequence DESC LIMIT 1`, batch.JobID).Scan(&lastSequence, &final)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read scanner-worker evidence sequence: %w", err)
	}
	if final || batch.Sequence != lastSequence+1 {
		return ErrWorkerEvidenceSequence
	}
	return nil
}
