package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"mossward/internal/model"
)

func (s *SQLiteStore) LeaseScannerWorkerJob(workerID string, tokenHash []byte, now, leaseExpiresAt time.Time) (model.SignedWorkerJob, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return model.SignedWorkerJob{}, fmt.Errorf("begin scanner-worker job lease: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE scanner_worker_jobs SET status='expired',lease_token_hash=NULL,lease_expires_at=NULL WHERE worker_id=? AND status IN ('pending','leased') AND expires_at<=?`, workerID, formatTime(now)); err != nil {
		return model.SignedWorkerJob{}, fmt.Errorf("expire scanner-worker jobs: %w", err)
	}
	if _, err := tx.Exec(`UPDATE scanner_worker_jobs SET status='pending',lease_token_hash=NULL,lease_expires_at=NULL WHERE worker_id=? AND status='leased' AND lease_expires_at<=? AND expires_at>?`, workerID, formatTime(now), formatTime(now)); err != nil {
		return model.SignedWorkerJob{}, fmt.Errorf("release expired scanner-worker job leases: %w", err)
	}
	var id, encoded string
	err = tx.QueryRow(`SELECT j.id,j.signed_envelope FROM scanner_worker_jobs j JOIN scanner_workers w ON w.id=j.worker_id JOIN scanner_worker_dispatch_settings d ON d.id=1 WHERE j.worker_id=? AND j.status='pending' AND j.expires_at>? AND w.dispatch_enabled=1 AND d.enabled=1 ORDER BY j.created_at,j.id LIMIT 1`, workerID, formatTime(now)).Scan(&id, &encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return model.SignedWorkerJob{}, ErrNotFound
	}
	if err != nil {
		return model.SignedWorkerJob{}, fmt.Errorf("select scanner-worker job lease: %w", err)
	}
	formattedLeaseExpiry := formatTime(leaseExpiresAt)
	result, err := tx.Exec(`UPDATE scanner_worker_jobs SET status='leased',lease_token_hash=?,lease_expires_at=CASE WHEN expires_at<? THEN expires_at ELSE ? END,lease_attempt=lease_attempt+1 WHERE id=? AND worker_id=? AND status='pending'`, tokenHash, formattedLeaseExpiry, formattedLeaseExpiry, id, workerID)
	if err != nil {
		return model.SignedWorkerJob{}, fmt.Errorf("lease scanner-worker job: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return model.SignedWorkerJob{}, fmt.Errorf("scanner-worker job lease conflict")
	}
	var envelope model.SignedWorkerJob
	if err := json.Unmarshal([]byte(encoded), &envelope); err != nil {
		return envelope, fmt.Errorf("decode leased scanner-worker job: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return envelope, fmt.Errorf("commit scanner-worker job lease: %w", err)
	}
	return envelope, nil
}
