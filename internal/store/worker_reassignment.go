package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"mossward/internal/model"
)

func (s *SQLiteStore) ScannerWorkerJobResumeCandidate(jobID string, now time.Time) (model.WorkerJobResumeCandidate, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return model.WorkerJobResumeCandidate{}, fmt.Errorf("begin scanner-worker resume lookup: %w", err)
	}
	defer tx.Rollback()
	var encoded, workerID string
	var leaseAttempts int
	err = tx.QueryRow(`SELECT signed_envelope,worker_id,lease_attempt FROM scanner_worker_jobs WHERE id=? AND status='leased' AND lease_expires_at<=? AND expires_at>?`, jobID, formatTime(now), formatTime(now)).Scan(&encoded, &workerID, &leaseAttempts)
	if errors.Is(err, sql.ErrNoRows) {
		return model.WorkerJobResumeCandidate{}, ErrWorkerJobNotResumable
	}
	if err != nil {
		return model.WorkerJobResumeCandidate{}, fmt.Errorf("read scanner-worker resume candidate: %w", err)
	}
	if leaseAttempts >= maximumWorkerLeaseAttempts {
		if err := quarantineRepeatedWorkerJobs(tx, workerID, now); err != nil {
			return model.WorkerJobResumeCandidate{}, err
		}
		if err := tx.Commit(); err != nil {
			return model.WorkerJobResumeCandidate{}, fmt.Errorf("commit scanner-worker resume quarantine: %w", err)
		}
		return model.WorkerJobResumeCandidate{}, ErrWorkerJobQuarantined
	}
	var envelope model.SignedWorkerJob
	if err := json.Unmarshal([]byte(encoded), &envelope); err != nil {
		return model.WorkerJobResumeCandidate{}, fmt.Errorf("decode scanner-worker resume candidate: %w", err)
	}
	completed, err := scannerWorkerCheckpoints(tx, jobID)
	if err != nil {
		return model.WorkerJobResumeCandidate{}, err
	}
	if len(completed) >= len(envelope.Job.Targets)*len(envelope.Job.Ports) {
		return model.WorkerJobResumeCandidate{}, ErrWorkerJobNotResumable
	}
	var lastSequence uint64
	err = tx.QueryRow(`SELECT sequence FROM scanner_worker_evidence_batches WHERE job_id=? ORDER BY sequence DESC LIMIT 1`, jobID).Scan(&lastSequence)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return model.WorkerJobResumeCandidate{}, fmt.Errorf("read scanner-worker resume sequence: %w", err)
	}
	return model.WorkerJobResumeCandidate{Envelope: envelope, Completed: completed, NextEvidenceSequence: lastSequence + 1}, nil
}

func scannerWorkerCheckpoints(tx *sql.Tx, jobID string) ([]model.WorkerCheckpoint, error) {
	rows, err := tx.Query(`SELECT address,port,completed_at FROM scanner_worker_job_checkpoints WHERE job_id=? ORDER BY address,port`, jobID)
	if err != nil {
		return nil, fmt.Errorf("list scanner-worker resume checkpoints: %w", err)
	}
	defer rows.Close()
	completed := []model.WorkerCheckpoint{}
	for rows.Next() {
		var checkpoint model.WorkerCheckpoint
		var completedAt string
		if err := rows.Scan(&checkpoint.Address, &checkpoint.Port, &completedAt); err != nil {
			return nil, fmt.Errorf("scan scanner-worker resume checkpoint: %w", err)
		}
		checkpoint.CompletedAt, _ = parseTime(completedAt)
		completed = append(completed, checkpoint)
	}
	return completed, rows.Err()
}

func (s *SQLiteStore) ReassignScannerWorkerJob(previousWorkerID string, envelope model.SignedWorkerJob, now time.Time) error {
	if envelope.Job.Resume == nil || envelope.Job.Resume.PreviousWorkerID != previousWorkerID {
		return ErrWorkerJobNotResumable
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("encode reassigned scanner-worker job: %w", err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin scanner-worker job reassignment: %w", err)
	}
	defer tx.Rollback()
	var lastSequence uint64
	err = tx.QueryRow(`SELECT COALESCE(MAX(sequence),0) FROM scanner_worker_evidence_batches WHERE job_id=?`, envelope.Job.ID).Scan(&lastSequence)
	if err != nil {
		return fmt.Errorf("read scanner-worker reassignment sequence: %w", err)
	}
	var checkpointCount int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM scanner_worker_job_checkpoints WHERE job_id=?`, envelope.Job.ID).Scan(&checkpointCount); err != nil {
		return fmt.Errorf("read scanner-worker reassignment checkpoints: %w", err)
	}
	if envelope.Job.Resume.NextEvidenceSequence != lastSequence+1 || len(envelope.Job.Resume.Completed) != checkpointCount {
		return ErrWorkerJobNotResumable
	}
	result, err := tx.Exec(`UPDATE scanner_worker_jobs SET worker_id=?,status='pending',signed_envelope=?,lease_token_hash=NULL,lease_expires_at=NULL WHERE id=? AND worker_id=? AND status='leased' AND lease_expires_at<=? AND expires_at>?`, envelope.Job.WorkerID, encoded, envelope.Job.ID, previousWorkerID, formatTime(now), formatTime(now))
	if err != nil {
		return fmt.Errorf("reassign scanner-worker job: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrWorkerJobNotResumable
	}
	var attempt int
	if err := tx.QueryRow(`SELECT COALESCE(MAX(attempt),0)+1 FROM scanner_worker_job_assignments WHERE job_id=?`, envelope.Job.ID).Scan(&attempt); err != nil {
		return fmt.Errorf("read scanner-worker assignment attempt: %w", err)
	}
	_, err = tx.Exec(`INSERT INTO scanner_worker_job_assignments(job_id,attempt,worker_id,signed_envelope,assigned_at,reason) VALUES(?,?,?,?,?,'expired_lease_resume')`, envelope.Job.ID, attempt, envelope.Job.WorkerID, encoded, formatTime(now))
	if err != nil {
		return fmt.Errorf("record scanner-worker job reassignment: %w", err)
	}
	return tx.Commit()
}
