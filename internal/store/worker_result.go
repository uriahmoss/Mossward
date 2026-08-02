package store

import (
	"database/sql"
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
	var existing string
	err = tx.QueryRow(`SELECT id FROM scanner_worker_jobs WHERE result_id=?`, receipt.ResultID).Scan(&existing)
	if err == nil {
		return ErrWorkerResultReplay
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("check scanner-worker result replay: %w", err)
	}
	result, err := tx.Exec(`UPDATE scanner_worker_jobs SET status='completed',result_id=?,result_outcome=?,completed_at=?,lease_token_hash=NULL,lease_expires_at=NULL WHERE id=? AND worker_id=? AND status='leased' AND lease_token_hash=? AND lease_expires_at>? AND expires_at>?`, receipt.ResultID, receipt.Outcome, formatTime(receipt.CompletedAt), receipt.JobID, receipt.WorkerID, tokenHash, formatTime(now), formatTime(now))
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
