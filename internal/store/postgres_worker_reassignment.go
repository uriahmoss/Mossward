package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"mossward/internal/model"
)

func (s *PostgreSQLStore) ScannerWorkerJobResumeCandidate(jobID string, now time.Time) (model.WorkerJobResumeCandidate, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return model.WorkerJobResumeCandidate{}, fmt.Errorf("begin PostgreSQL scanner-worker resume lookup: %w", err)
	}
	defer tx.Rollback()
	var encoded, workerID string
	var leaseAttempts int
	err = tx.QueryRow(`SELECT signed_envelope,worker_id,lease_attempt FROM scanner_worker_jobs
		WHERE id=$1 AND status='leased' AND lease_expires_at<=$2 AND expires_at>$2 FOR UPDATE`, jobID, now).
		Scan(&encoded, &workerID, &leaseAttempts)
	if errors.Is(err, sql.ErrNoRows) {
		return model.WorkerJobResumeCandidate{}, ErrWorkerJobNotResumable
	}
	if err != nil {
		return model.WorkerJobResumeCandidate{}, fmt.Errorf("read PostgreSQL scanner-worker resume candidate: %w", err)
	}
	if leaseAttempts >= maximumWorkerLeaseAttempts {
		if err := quarantineRepeatedPostgreSQLWorkerJobs(tx, workerID, now); err != nil {
			return model.WorkerJobResumeCandidate{}, err
		}
		if err := tx.Commit(); err != nil {
			return model.WorkerJobResumeCandidate{}, fmt.Errorf("commit PostgreSQL scanner-worker resume quarantine: %w", err)
		}
		return model.WorkerJobResumeCandidate{}, ErrWorkerJobQuarantined
	}
	envelope, err := decodePostgreSQLWorkerJob(encoded)
	if err != nil {
		return model.WorkerJobResumeCandidate{}, err
	}
	completed, err := postgreSQLScannerWorkerCheckpoints(tx, jobID)
	if err != nil {
		return model.WorkerJobResumeCandidate{}, err
	}
	if len(completed) >= len(envelope.Job.Targets)*len(envelope.Job.Ports) {
		return model.WorkerJobResumeCandidate{}, ErrWorkerJobNotResumable
	}
	var lastSequence uint64
	err = tx.QueryRow(`SELECT sequence FROM scanner_worker_evidence_batches
		WHERE job_id=$1 ORDER BY sequence DESC LIMIT 1`, jobID).Scan(&lastSequence)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return model.WorkerJobResumeCandidate{}, fmt.Errorf("read PostgreSQL scanner-worker resume sequence: %w", err)
	}
	return model.WorkerJobResumeCandidate{
		Envelope: envelope, Completed: completed, NextEvidenceSequence: lastSequence + 1,
	}, nil
}

func (s *PostgreSQLStore) ReassignScannerWorkerJob(previousWorkerID string, envelope model.SignedWorkerJob, now time.Time) error {
	if envelope.Job.Resume == nil || envelope.Job.Resume.PreviousWorkerID != previousWorkerID {
		return ErrWorkerJobNotResumable
	}
	encoded, err := encodePostgreSQLWorkerJob(envelope)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL scanner-worker job reassignment: %w", err)
	}
	defer tx.Rollback()
	var lastSequence uint64
	if err := tx.QueryRow(`SELECT COALESCE(MAX(sequence),0) FROM scanner_worker_evidence_batches WHERE job_id=$1`,
		envelope.Job.ID).Scan(&lastSequence); err != nil {
		return fmt.Errorf("read PostgreSQL scanner-worker reassignment sequence: %w", err)
	}
	var checkpointCount int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM scanner_worker_job_checkpoints WHERE job_id=$1`, envelope.Job.ID).
		Scan(&checkpointCount); err != nil {
		return fmt.Errorf("read PostgreSQL scanner-worker reassignment checkpoints: %w", err)
	}
	if envelope.Job.Resume.NextEvidenceSequence != lastSequence+1 || len(envelope.Job.Resume.Completed) != checkpointCount {
		return ErrWorkerJobNotResumable
	}
	result, err := tx.Exec(`UPDATE scanner_worker_jobs SET worker_id=$1,status='pending',signed_envelope=$2,
		lease_token_hash=NULL,lease_expires_at=NULL WHERE id=$3 AND worker_id=$4 AND status='leased'
		AND lease_expires_at<=$5 AND expires_at>$5`, envelope.Job.WorkerID, encoded, envelope.Job.ID, previousWorkerID, now)
	if err != nil {
		return fmt.Errorf("reassign PostgreSQL scanner-worker job: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrWorkerJobNotResumable
	}
	var attempt int
	if err := tx.QueryRow(`SELECT COALESCE(MAX(attempt),0)+1 FROM scanner_worker_job_assignments WHERE job_id=$1`,
		envelope.Job.ID).Scan(&attempt); err != nil {
		return fmt.Errorf("read PostgreSQL scanner-worker assignment attempt: %w", err)
	}
	_, err = tx.Exec(`INSERT INTO scanner_worker_job_assignments
		(job_id,attempt,worker_id,signed_envelope,assigned_at,reason) VALUES($1,$2,$3,$4,$5,'expired_lease_resume')`,
		envelope.Job.ID, attempt, envelope.Job.WorkerID, encoded, now)
	if err != nil {
		return fmt.Errorf("record PostgreSQL scanner-worker job reassignment: %w", err)
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) ListScannerWorkerDeadLetters() ([]model.WorkerJobDeadLetter, error) {
	rows, err := s.db.Query(`SELECT job_id,scan_id,worker_id,failure_count,reason,quarantined_at
		FROM scanner_worker_job_dead_letters ORDER BY quarantined_at DESC,job_id`)
	if err != nil {
		return nil, fmt.Errorf("list PostgreSQL scanner-worker dead letters: %w", err)
	}
	defer rows.Close()
	items := []model.WorkerJobDeadLetter{}
	for rows.Next() {
		var item model.WorkerJobDeadLetter
		if err := rows.Scan(&item.JobID, &item.ScanID, &item.WorkerID, &item.FailureCount, &item.Reason,
			&item.QuarantinedAt); err != nil {
			return nil, fmt.Errorf("read PostgreSQL scanner-worker dead letter: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func postgreSQLScannerWorkerCheckpoints(tx *sql.Tx, jobID string) ([]model.WorkerCheckpoint, error) {
	rows, err := tx.Query(`SELECT address,port,completed_at FROM scanner_worker_job_checkpoints
		WHERE job_id=$1 ORDER BY address,port`, jobID)
	if err != nil {
		return nil, fmt.Errorf("list PostgreSQL scanner-worker resume checkpoints: %w", err)
	}
	defer rows.Close()
	return scanPostgreSQLWorkerCheckpoints(rows)
}
