package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

func (s *SQLiteStore) RenewScannerWorkerJobLease(workerID, jobID string, tokenHash []byte, now, requestedExpiry time.Time) (time.Time, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return time.Time{}, fmt.Errorf("begin scanner-worker lease renewal: %w", err)
	}
	defer tx.Rollback()
	formattedExpiry := formatTime(requestedExpiry)
	result, err := tx.Exec(`UPDATE scanner_worker_jobs SET lease_expires_at=CASE WHEN expires_at<? THEN expires_at WHEN lease_expires_at>? THEN lease_expires_at ELSE ? END WHERE id=? AND worker_id=? AND status='leased' AND lease_token_hash=? AND lease_expires_at>? AND expires_at>?`, formattedExpiry, formattedExpiry, formattedExpiry, jobID, workerID, tokenHash, formatTime(now), formatTime(now))
	if err != nil {
		return time.Time{}, fmt.Errorf("renew scanner-worker job lease: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return time.Time{}, ErrInvalidWorkerJobLease
	}
	var stored string
	if err := tx.QueryRow(`SELECT lease_expires_at FROM scanner_worker_jobs WHERE id=?`, jobID).Scan(&stored); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return time.Time{}, ErrInvalidWorkerJobLease
		}
		return time.Time{}, fmt.Errorf("read renewed scanner-worker lease: %w", err)
	}
	expiresAt, err := parseTime(stored)
	if err != nil {
		return time.Time{}, fmt.Errorf("decode renewed scanner-worker lease: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return time.Time{}, fmt.Errorf("commit scanner-worker lease renewal: %w", err)
	}
	return expiresAt, nil
}
