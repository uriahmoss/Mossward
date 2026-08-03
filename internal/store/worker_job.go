package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"mossward/internal/model"
)

func (s *SQLiteStore) CreateScannerWorkerJob(envelope model.SignedWorkerJob, createdAt time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin scanner-worker job creation: %w", err)
	}
	defer tx.Rollback()
	var existing string
	err = tx.QueryRow(`SELECT id FROM scanner_worker_jobs WHERE id=?`, envelope.Job.ID).Scan(&existing)
	if err == nil {
		return ErrWorkerJobReplay
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("encode scanner-worker job: %w", err)
	}
	_, err = tx.Exec(`INSERT INTO scanner_worker_jobs(id,worker_id,scan_id,status,signed_envelope,issued_at,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?)`, envelope.Job.ID, envelope.Job.WorkerID, envelope.Job.ScanID, envelope.Job.Status, encoded, formatTime(envelope.Job.IssuedAt), formatTime(envelope.Job.ExpiresAt), formatTime(createdAt))
	if err != nil {
		return fmt.Errorf("create scanner-worker job: %w", err)
	}
	_, err = tx.Exec(`INSERT INTO scanner_worker_job_assignments(job_id,attempt,worker_id,signed_envelope,assigned_at,reason) VALUES(?,1,?,?,?,'initial')`, envelope.Job.ID, envelope.Job.WorkerID, encoded, formatTime(createdAt))
	if err != nil {
		return fmt.Errorf("record initial scanner-worker job assignment: %w", err)
	}
	return tx.Commit()
}

func (s *SQLiteStore) ScannerWorkerJob(id string) (model.SignedWorkerJob, error) {
	var encoded string
	err := s.db.QueryRow(`SELECT signed_envelope FROM scanner_worker_jobs WHERE id=?`, id).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return model.SignedWorkerJob{}, ErrNotFound
	}
	if err != nil {
		return model.SignedWorkerJob{}, err
	}
	var envelope model.SignedWorkerJob
	if err := json.Unmarshal([]byte(encoded), &envelope); err != nil {
		return envelope, fmt.Errorf("decode scanner-worker job: %w", err)
	}
	return envelope, nil
}

func (s *SQLiteStore) ScannerWorkerJobLoads(now time.Time) (map[string]model.WorkerJobLoad, error) {
	rows, err := s.db.Query(`SELECT worker_id,signed_envelope FROM scanner_worker_jobs WHERE status IN ('pending','leased') AND expires_at>?`, formatTime(now))
	if err != nil {
		return nil, fmt.Errorf("list active scanner-worker jobs: %w", err)
	}
	defer rows.Close()
	loads := map[string]model.WorkerJobLoad{}
	for rows.Next() {
		var workerID, encoded string
		if err := rows.Scan(&workerID, &encoded); err != nil {
			return nil, fmt.Errorf("scan active scanner-worker job: %w", err)
		}
		var envelope model.SignedWorkerJob
		if err := json.Unmarshal([]byte(encoded), &envelope); err != nil {
			return nil, fmt.Errorf("decode active scanner-worker job: %w", err)
		}
		load := loads[workerID]
		load.ActiveJobs++
		load.ReservedConcurrency += envelope.Job.MaxConcurrent
		loads[workerID] = load
	}
	return loads, rows.Err()
}
