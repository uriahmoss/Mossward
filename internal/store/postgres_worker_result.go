package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"mossward/internal/model"
)

func (s *PostgreSQLStore) CompleteScannerWorkerJob(receipt model.WorkerJobResultReceipt, tokenHash []byte, now time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL scanner-worker job completion: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, receipt.ResultID); err != nil {
		return fmt.Errorf("lock PostgreSQL scanner-worker result identity: %w", err)
	}
	var lockedJobID string
	err = tx.QueryRow(`SELECT id FROM scanner_worker_jobs WHERE id=$1 FOR UPDATE`, receipt.JobID).Scan(&lockedJobID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrInvalidWorkerJobLease
	}
	if err != nil {
		return fmt.Errorf("lock PostgreSQL scanner-worker job completion: %w", err)
	}
	if receipt.Outcome == model.WorkerJobResultSucceeded {
		complete, err := postgreSQLWorkerJobCheckpointsComplete(tx, receipt.JobID)
		if err != nil {
			return err
		}
		if !complete {
			return ErrInvalidWorkerJobLease
		}
	}
	var jobID, workerID string
	var outcome model.WorkerJobResultOutcome
	var completedAt time.Time
	err = tx.QueryRow(`SELECT id,worker_id,result_outcome,completed_at FROM scanner_worker_jobs WHERE result_id=$1`,
		receipt.ResultID).Scan(&jobID, &workerID, &outcome, &completedAt)
	if err == nil {
		if jobID != receipt.JobID || workerID != receipt.WorkerID || outcome != receipt.Outcome || !completedAt.Equal(receipt.CompletedAt) {
			return ErrWorkerResultReplay
		}
		if err := tx.Rollback(); err != nil {
			return fmt.Errorf("close PostgreSQL scanner-worker retry transaction: %w", err)
		}
		if err := s.projectPostgreSQLScannerWorkerResult(receipt); err != nil {
			return err
		}
		return ErrWorkerResultAlreadyAccepted
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("check PostgreSQL scanner-worker result replay: %w", err)
	}
	result, err := tx.Exec(`UPDATE scanner_worker_jobs SET status='completed',result_id=$1,result_outcome=$2,
		completed_at=$3,lease_token_hash=NULL,lease_expires_at=NULL WHERE id=$4 AND worker_id=$5 AND status='leased'
		AND lease_token_hash=$6 AND lease_expires_at>$7 AND expires_at>$7
		AND ($2<>'succeeded' OR EXISTS(SELECT 1 FROM scanner_worker_evidence_batches WHERE job_id=$4 AND final=TRUE))`,
		receipt.ResultID, receipt.Outcome, receipt.CompletedAt, receipt.JobID, receipt.WorkerID, tokenHash, now)
	if err != nil {
		return fmt.Errorf("complete PostgreSQL scanner-worker job: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("count PostgreSQL scanner-worker completion: %w", err)
	}
	if changed != 1 {
		return ErrInvalidWorkerJobLease
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit PostgreSQL scanner-worker job completion: %w", err)
	}
	return s.projectPostgreSQLScannerWorkerResult(receipt)
}

func postgreSQLWorkerJobCheckpointsComplete(tx *sql.Tx, jobID string) (bool, error) {
	var encoded string
	err := tx.QueryRow(`SELECT signed_envelope FROM scanner_worker_jobs WHERE id=$1`, jobID).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read PostgreSQL scanner-worker job for checkpoint completion: %w", err)
	}
	envelope, err := decodePostgreSQLWorkerJob(encoded)
	if err != nil {
		return false, err
	}
	expected := len(envelope.Job.Targets) * len(envelope.Job.Ports)
	if expected == 0 {
		return false, nil
	}
	var completed int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM scanner_worker_job_checkpoints WHERE job_id=$1`, jobID).Scan(&completed); err != nil {
		return false, fmt.Errorf("count PostgreSQL scanner-worker checkpoints: %w", err)
	}
	return completed == expected, nil
}

func (s *PostgreSQLStore) projectPostgreSQLScannerWorkerResult(receipt model.WorkerJobResultReceipt) error {
	job, err := s.ScannerWorkerJob(receipt.JobID)
	if err != nil {
		return fmt.Errorf("load PostgreSQL scanner-worker job for projection: %w", err)
	}
	scan, err := s.Get(job.Job.ScanID)
	if err != nil {
		return fmt.Errorf("load PostgreSQL remote scan for projection: %w", err)
	}
	observations, findings, err := s.postgreSQLScannerWorkerEvidence(receipt.JobID)
	if err != nil {
		return err
	}
	checkpoints, err := s.ScannerWorkerJobCheckpoints(receipt.JobID)
	if err != nil {
		return fmt.Errorf("load PostgreSQL scanner-worker checkpoints for projection: %w", err)
	}
	scan.Observations = observations
	scan.Findings = findings
	scan.Checkpoints = workerScanCheckpoints(checkpoints)
	scan.DoneChecks = len(checkpoints)
	scan.StartedAt = workerScanStartedAt(scan.StartedAt, job.Job.IssuedAt)
	scan.CompletedAt = timePointer(receipt.CompletedAt)
	scan.Status, scan.Error = projectedScanOutcome(receipt.Outcome)
	scan.CVEMatches, err = s.matchPostgreSQLScannerWorkerObservations(observations)
	if err != nil {
		return err
	}
	if err := s.Save(scan); err != nil {
		return fmt.Errorf("save projected PostgreSQL scanner-worker scan: %w", err)
	}
	return nil
}

func (s *PostgreSQLStore) postgreSQLScannerWorkerEvidence(jobID string) ([]model.ServiceObservation, []model.Finding, error) {
	rows, err := s.db.Query(`SELECT signed_envelope FROM scanner_worker_evidence_batches WHERE job_id=$1 ORDER BY sequence`, jobID)
	if err != nil {
		return nil, nil, fmt.Errorf("list PostgreSQL scanner-worker evidence for projection: %w", err)
	}
	defer rows.Close()
	observations := []model.ServiceObservation{}
	findings := []model.Finding{}
	for rows.Next() {
		var encoded string
		if err := rows.Scan(&encoded); err != nil {
			return nil, nil, fmt.Errorf("read PostgreSQL scanner-worker evidence for projection: %w", err)
		}
		var envelope model.SignedWorkerEvidenceBatch
		if err := json.Unmarshal([]byte(encoded), &envelope); err != nil {
			return nil, nil, fmt.Errorf("decode PostgreSQL scanner-worker evidence for projection: %w", err)
		}
		observations = append(observations, envelope.Batch.Observations...)
		findings = append(findings, envelope.Batch.Findings...)
	}
	return observations, findings, rows.Err()
}

func (s *PostgreSQLStore) matchPostgreSQLScannerWorkerObservations(observations []model.ServiceObservation) ([]model.CVEMatch, error) {
	matches := []model.CVEMatch{}
	for _, observation := range observations {
		found, err := s.MatchObservation(observation)
		if err != nil {
			return nil, fmt.Errorf("match PostgreSQL scanner-worker observation to CVEs: %w", err)
		}
		matches = append(matches, found...)
	}
	return matches, nil
}
