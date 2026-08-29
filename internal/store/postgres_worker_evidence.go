package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"mossward/internal/model"
)

func (s *PostgreSQLStore) RecordScannerWorkerEvidenceBatch(envelope model.SignedWorkerEvidenceBatch, receivedAt time.Time) error {
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("encode PostgreSQL scanner-worker evidence batch: %w", err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL scanner-worker evidence recording: %w", err)
	}
	defer tx.Rollback()
	if replayErr, found, err := postgreSQLWorkerEvidenceReplay(tx, envelope.Batch.ID, string(encoded)); err != nil {
		return err
	} else if found {
		return replayErr
	}
	if err := validatePostgreSQLWorkerEvidenceSequence(tx, envelope.Batch, receivedAt); err != nil {
		return err
	}
	if replayErr, found, err := postgreSQLWorkerEvidenceReplay(tx, envelope.Batch.ID, string(encoded)); err != nil {
		return err
	} else if found {
		return replayErr
	}
	_, err = tx.Exec(`INSERT INTO scanner_worker_evidence_batches
		(batch_id,job_id,worker_id,scan_id,sequence,final,certificate_serial,signed_envelope,collected_at,received_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, envelope.Batch.ID, envelope.Batch.JobID, envelope.Batch.WorkerID,
		envelope.Batch.ScanID, envelope.Batch.Sequence, envelope.Batch.Final, envelope.CertificateSerial, string(encoded),
		envelope.Batch.CollectedAt, receivedAt)
	if err != nil {
		return fmt.Errorf("record PostgreSQL scanner-worker evidence batch: %w", err)
	}
	if err := recordPostgreSQLWorkerCheckpoints(tx, envelope.Batch); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) ScannerWorkerJobCheckpoints(jobID string) ([]model.WorkerCheckpoint, error) {
	rows, err := s.db.Query(`SELECT address,port,completed_at FROM scanner_worker_job_checkpoints
		WHERE job_id=$1 ORDER BY address,port`, jobID)
	if err != nil {
		return nil, fmt.Errorf("list PostgreSQL scanner-worker checkpoints: %w", err)
	}
	defer rows.Close()
	return scanPostgreSQLWorkerCheckpoints(rows)
}

func validatePostgreSQLWorkerEvidenceSequence(tx *sql.Tx, batch model.WorkerEvidenceBatch, receivedAt time.Time) error {
	var workerID, scanID string
	var status model.WorkerJobStatus
	var expiresAt time.Time
	var leaseExpiresAt sql.NullTime
	err := tx.QueryRow(`SELECT worker_id,scan_id,status,expires_at,lease_expires_at FROM scanner_worker_jobs
		WHERE id=$1 FOR UPDATE`, batch.JobID).Scan(&workerID, &scanID, &status, &expiresAt, &leaseExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrInvalidWorkerJobLease
	}
	if err != nil {
		return fmt.Errorf("read PostgreSQL scanner-worker evidence job: %w", err)
	}
	if workerID != batch.WorkerID || scanID != batch.ScanID || status != model.WorkerJobLeased ||
		!expiresAt.After(receivedAt) || !leaseExpiresAt.Valid || !leaseExpiresAt.Time.After(receivedAt) {
		return ErrInvalidWorkerJobLease
	}
	var lastSequence uint64
	var final bool
	var lastWorkerID string
	err = tx.QueryRow(`SELECT sequence,final,worker_id FROM scanner_worker_evidence_batches
		WHERE job_id=$1 ORDER BY sequence DESC LIMIT 1`, batch.JobID).Scan(&lastSequence, &final, &lastWorkerID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read PostgreSQL scanner-worker evidence sequence: %w", err)
	}
	if final && lastWorkerID == batch.WorkerID || batch.Sequence != lastSequence+1 {
		return ErrWorkerEvidenceSequence
	}
	return nil
}

func postgreSQLWorkerEvidenceReplay(tx *sql.Tx, batchID, encoded string) (error, bool, error) {
	var existing string
	err := tx.QueryRow(`SELECT signed_envelope FROM scanner_worker_evidence_batches WHERE batch_id=$1`, batchID).Scan(&existing)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("check PostgreSQL scanner-worker evidence replay: %w", err)
	}
	if existing == encoded {
		return ErrWorkerEvidenceAlreadyAccepted, true, nil
	}
	return ErrWorkerEvidenceReplay, true, nil
}

func recordPostgreSQLWorkerCheckpoints(tx *sql.Tx, batch model.WorkerEvidenceBatch) error {
	for _, checkpoint := range batch.Checkpoints {
		_, err := tx.Exec(`INSERT INTO scanner_worker_job_checkpoints
			(job_id,worker_id,scan_id,address,port,completed_at,batch_id) VALUES($1,$2,$3,$4,$5,$6,$7)
			ON CONFLICT(job_id,address,port) DO NOTHING`, batch.JobID, batch.WorkerID, batch.ScanID,
			checkpoint.Address, checkpoint.Port, checkpoint.CompletedAt, batch.ID)
		if err != nil {
			return fmt.Errorf("record PostgreSQL scanner-worker checkpoint: %w", err)
		}
	}
	return nil
}

type postgreSQLRows interface {
	Next() bool
	Scan(...any) error
	Err() error
}

func scanPostgreSQLWorkerCheckpoints(rows postgreSQLRows) ([]model.WorkerCheckpoint, error) {
	checkpoints := []model.WorkerCheckpoint{}
	for rows.Next() {
		var checkpoint model.WorkerCheckpoint
		if err := rows.Scan(&checkpoint.Address, &checkpoint.Port, &checkpoint.CompletedAt); err != nil {
			return nil, fmt.Errorf("read PostgreSQL scanner-worker checkpoint: %w", err)
		}
		checkpoints = append(checkpoints, checkpoint)
	}
	return checkpoints, rows.Err()
}
