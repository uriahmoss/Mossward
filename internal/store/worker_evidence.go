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
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("encode scanner-worker evidence batch: %w", err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin scanner-worker evidence recording: %w", err)
	}
	defer tx.Rollback()
	var existing string
	err = tx.QueryRow(`SELECT signed_envelope FROM scanner_worker_evidence_batches WHERE batch_id=?`, envelope.Batch.ID).Scan(&existing)
	if err == nil {
		if existing == string(encoded) {
			return ErrWorkerEvidenceAlreadyAccepted
		}
		return ErrWorkerEvidenceReplay
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("check scanner-worker evidence replay: %w", err)
	}
	if err := validateEvidenceSequence(tx, envelope.Batch, receivedAt); err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO scanner_worker_evidence_batches(batch_id,job_id,worker_id,scan_id,sequence,final,certificate_serial,signed_envelope,collected_at,received_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, envelope.Batch.ID, envelope.Batch.JobID, envelope.Batch.WorkerID, envelope.Batch.ScanID, envelope.Batch.Sequence, envelope.Batch.Final, envelope.CertificateSerial, encoded, formatTime(envelope.Batch.CollectedAt), formatTime(receivedAt))
	if err != nil {
		return fmt.Errorf("record scanner-worker evidence batch: %w", err)
	}
	if err := recordWorkerCheckpoints(tx, envelope.Batch); err != nil {
		return err
	}
	return tx.Commit()
}

func recordWorkerCheckpoints(tx *sql.Tx, batch model.WorkerEvidenceBatch) error {
	for _, checkpoint := range batch.Checkpoints {
		_, err := tx.Exec(`INSERT INTO scanner_worker_job_checkpoints(job_id,worker_id,scan_id,address,port,completed_at,batch_id) VALUES(?,?,?,?,?,?,?) ON CONFLICT(job_id,address,port) DO NOTHING`, batch.JobID, batch.WorkerID, batch.ScanID, checkpoint.Address, checkpoint.Port, formatTime(checkpoint.CompletedAt), batch.ID)
		if err != nil {
			return fmt.Errorf("record scanner-worker checkpoint: %w", err)
		}
	}
	return nil
}

func (s *SQLiteStore) ScannerWorkerJobCheckpoints(jobID string) ([]model.WorkerCheckpoint, error) {
	rows, err := s.db.Query(`SELECT address,port,completed_at FROM scanner_worker_job_checkpoints WHERE job_id=? ORDER BY address,port`, jobID)
	if err != nil {
		return nil, fmt.Errorf("list scanner-worker checkpoints: %w", err)
	}
	defer rows.Close()
	checkpoints := []model.WorkerCheckpoint{}
	for rows.Next() {
		var checkpoint model.WorkerCheckpoint
		var completedAt string
		if err := rows.Scan(&checkpoint.Address, &checkpoint.Port, &completedAt); err != nil {
			return nil, fmt.Errorf("scan scanner-worker checkpoint: %w", err)
		}
		checkpoint.CompletedAt, _ = parseTime(completedAt)
		checkpoints = append(checkpoints, checkpoint)
	}
	return checkpoints, rows.Err()
}

func validateEvidenceSequence(tx *sql.Tx, batch model.WorkerEvidenceBatch, receivedAt time.Time) error {
	var workerID, scanID, status, expiresAt, leaseExpiresAt string
	if err := tx.QueryRow(`SELECT worker_id,scan_id,status,expires_at,COALESCE(lease_expires_at,'') FROM scanner_worker_jobs WHERE id=?`, batch.JobID).Scan(&workerID, &scanID, &status, &expiresAt, &leaseExpiresAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrInvalidWorkerJobLease
		}
		return fmt.Errorf("read scanner-worker evidence job: %w", err)
	}
	if workerID != batch.WorkerID || scanID != batch.ScanID || status != string(model.WorkerJobLeased) ||
		expiresAt <= formatTime(receivedAt) || leaseExpiresAt <= formatTime(receivedAt) {
		return ErrInvalidWorkerJobLease
	}
	var lastSequence uint64
	var final bool
	var lastWorkerID string
	err := tx.QueryRow(`SELECT sequence,final,worker_id FROM scanner_worker_evidence_batches WHERE job_id=? ORDER BY sequence DESC LIMIT 1`, batch.JobID).Scan(&lastSequence, &final, &lastWorkerID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read scanner-worker evidence sequence: %w", err)
	}
	if final && lastWorkerID == batch.WorkerID || batch.Sequence != lastSequence+1 {
		return ErrWorkerEvidenceSequence
	}
	return nil
}
