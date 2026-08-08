package store

import (
	"encoding/json"
	"fmt"
	"time"

	"mossward/internal/model"
)

const remoteWorkerFailure = "remote scanner-worker execution failed"

func (s *SQLiteStore) projectScannerWorkerResult(receipt model.WorkerJobResultReceipt) error {
	job, err := s.ScannerWorkerJob(receipt.JobID)
	if err != nil {
		return fmt.Errorf("load scanner-worker job for projection: %w", err)
	}
	scan, err := s.Get(job.Job.ScanID)
	if err != nil {
		return fmt.Errorf("load remote scan for projection: %w", err)
	}
	observations, findings, err := s.scannerWorkerEvidence(receipt.JobID)
	if err != nil {
		return err
	}
	checkpoints, err := s.ScannerWorkerJobCheckpoints(receipt.JobID)
	if err != nil {
		return fmt.Errorf("load scanner-worker checkpoints for projection: %w", err)
	}
	scan.Observations = observations
	scan.Findings = findings
	scan.Checkpoints = workerScanCheckpoints(checkpoints)
	scan.DoneChecks = len(checkpoints)
	scan.StartedAt = workerScanStartedAt(scan.StartedAt, job.Job.IssuedAt)
	scan.CompletedAt = timePointer(receipt.CompletedAt)
	scan.Status, scan.Error = projectedScanOutcome(receipt.Outcome)
	scan.CVEMatches, err = s.matchScannerWorkerObservations(observations)
	if err != nil {
		return err
	}
	if err := s.Save(scan); err != nil {
		return fmt.Errorf("save projected scanner-worker scan: %w", err)
	}
	return nil
}

func (s *SQLiteStore) scannerWorkerEvidence(jobID string) ([]model.ServiceObservation, []model.Finding, error) {
	rows, err := s.db.Query(`SELECT signed_envelope FROM scanner_worker_evidence_batches WHERE job_id=? ORDER BY sequence`, jobID)
	if err != nil {
		return nil, nil, fmt.Errorf("list scanner-worker evidence for projection: %w", err)
	}
	defer rows.Close()
	observations := []model.ServiceObservation{}
	findings := []model.Finding{}
	for rows.Next() {
		var encoded string
		if err := rows.Scan(&encoded); err != nil {
			return nil, nil, fmt.Errorf("read scanner-worker evidence for projection: %w", err)
		}
		var envelope model.SignedWorkerEvidenceBatch
		if err := json.Unmarshal([]byte(encoded), &envelope); err != nil {
			return nil, nil, fmt.Errorf("decode scanner-worker evidence for projection: %w", err)
		}
		observations = append(observations, envelope.Batch.Observations...)
		findings = append(findings, envelope.Batch.Findings...)
	}
	return observations, findings, rows.Err()
}

func (s *SQLiteStore) matchScannerWorkerObservations(observations []model.ServiceObservation) ([]model.CVEMatch, error) {
	matches := []model.CVEMatch{}
	for _, observation := range observations {
		found, err := s.MatchObservation(observation)
		if err != nil {
			return nil, fmt.Errorf("match scanner-worker observation to CVEs: %w", err)
		}
		matches = append(matches, found...)
	}
	return matches, nil
}

func workerScanCheckpoints(checkpoints []model.WorkerCheckpoint) []model.ScanCheckpoint {
	result := make([]model.ScanCheckpoint, 0, len(checkpoints))
	for _, checkpoint := range checkpoints {
		result = append(result, model.ScanCheckpoint{Address: checkpoint.Address, Port: checkpoint.Port, CompletedAt: checkpoint.CompletedAt})
	}
	return result
}

func workerScanStartedAt(current *time.Time, issuedAt time.Time) *time.Time {
	if current != nil {
		return current
	}
	return timePointer(issuedAt)
}

func projectedScanOutcome(outcome model.WorkerJobResultOutcome) (model.ScanStatus, string) {
	switch outcome {
	case model.WorkerJobResultSucceeded:
		return model.StatusCompleted, ""
	case model.WorkerJobResultCanceled:
		return model.StatusCanceled, ""
	default:
		return model.StatusFailed, remoteWorkerFailure
	}
}

func timePointer(value time.Time) *time.Time {
	value = value.UTC()
	return &value
}
