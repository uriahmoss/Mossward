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
