package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"mossward/internal/model"
)

func (s *SQLiteStore) CompleteScannerWorkerJob(receipt model.WorkerJobResultReceipt, tokenHash []byte, now time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin scanner-worker job completion: %w", err)
	}
	defer tx.Rollback()
	if receipt.Outcome == model.WorkerJobResultSucceeded {
		complete, err := workerJobCheckpointsComplete(tx, receipt.JobID)
		if err != nil {
			return err
		}
		if !complete {
			return ErrInvalidWorkerJobLease
		}
	}
	var existing string
	err = tx.QueryRow(`SELECT id FROM scanner_worker_jobs WHERE result_id=?`, receipt.ResultID).Scan(&existing)
	if err == nil {
		return ErrWorkerResultReplay
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("check scanner-worker result replay: %w", err)
	}
	result, err := tx.Exec(`UPDATE scanner_worker_jobs SET status='completed',result_id=?,result_outcome=?,completed_at=?,lease_token_hash=NULL,lease_expires_at=NULL WHERE id=? AND worker_id=? AND status='leased' AND lease_token_hash=? AND lease_expires_at>? AND expires_at>? AND (?<>'succeeded' OR EXISTS(SELECT 1 FROM scanner_worker_evidence_batches WHERE job_id=? AND final=1))`, receipt.ResultID, receipt.Outcome, formatTime(receipt.CompletedAt), receipt.JobID, receipt.WorkerID, tokenHash, formatTime(now), formatTime(now), receipt.Outcome, receipt.JobID)
	if err != nil {
		return fmt.Errorf("complete scanner-worker job: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read scanner-worker completion result: %w", err)
	}
	if changed != 1 {
		return ErrInvalidWorkerJobLease
	}
	return tx.Commit()
}

func workerJobCheckpointsComplete(tx *sql.Tx, jobID string) (bool, error) {
	var encoded string
	if err := tx.QueryRow(`SELECT signed_envelope FROM scanner_worker_jobs WHERE id=?`, jobID).Scan(&encoded); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("read scanner-worker job for checkpoint completion: %w", err)
	}
	var envelope model.SignedWorkerJob
	if err := json.Unmarshal([]byte(encoded), &envelope); err != nil {
		return false, fmt.Errorf("decode scanner-worker job for checkpoint completion: %w", err)
	}
	expected := len(envelope.Job.Targets) * len(envelope.Job.Ports)
	if expected == 0 {
		return false, nil
	}
	var completed int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM scanner_worker_job_checkpoints WHERE job_id=?`, jobID).Scan(&completed); err != nil {
		return false, fmt.Errorf("count scanner-worker checkpoints: %w", err)
	}
	return completed == expected, nil
}
