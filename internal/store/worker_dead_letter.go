package store

import (
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"mossward/internal/model"
)

const (
	maximumWorkerLeaseAttempts = 3
	workerLeaseFailureReason   = "maximum expired lease attempts reached"
)

func quarantineRepeatedWorkerJobs(tx *sql.Tx, workerID string, now time.Time) error {
	formattedNow := formatTime(now)
	result, err := tx.Exec(`INSERT INTO scanner_worker_job_dead_letters(job_id,scan_id,worker_id,failure_count,reason,quarantined_at)
		SELECT id,scan_id,worker_id,lease_attempt,?,? FROM scanner_worker_jobs
		WHERE worker_id=? AND status='leased' AND lease_expires_at<=? AND expires_at>? AND lease_attempt>=?
		ON CONFLICT(job_id) DO NOTHING`, workerLeaseFailureReason, formattedNow, workerID, formattedNow, formattedNow, maximumWorkerLeaseAttempts)
	if err != nil {
		return fmt.Errorf("quarantine repeatedly failing scanner-worker jobs: %w", err)
	}
	quarantined, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("count quarantined scanner-worker jobs: %w", err)
	}
	_, err = tx.Exec(`UPDATE scans SET status='failed',error=?,completed_at=? WHERE id IN
		(SELECT scan_id FROM scanner_worker_job_dead_letters WHERE worker_id=? AND quarantined_at=?)
		AND status IN ('queued','running','paused')`, workerLeaseFailureReason, formattedNow, workerID, formattedNow)
	if err != nil {
		return fmt.Errorf("fail scans for quarantined scanner-worker jobs: %w", err)
	}
	_, err = tx.Exec(`UPDATE scanner_worker_jobs SET status='canceled',lease_token_hash=NULL,lease_expires_at=NULL
		WHERE id IN (SELECT job_id FROM scanner_worker_job_dead_letters) AND status='leased'`)
	if err != nil {
		return fmt.Errorf("stop quarantined scanner-worker jobs: %w", err)
	}
	if quarantined > 0 {
		slog.Warn("Scanner-worker jobs entered dead-letter quarantine", "worker_id", workerID, "count", quarantined,
			"reason", workerLeaseFailureReason)
	}
	return nil
}

func (s *SQLiteStore) ListScannerWorkerDeadLetters() ([]model.WorkerJobDeadLetter, error) {
	rows, err := s.db.Query(`SELECT job_id,scan_id,worker_id,failure_count,reason,quarantined_at FROM scanner_worker_job_dead_letters ORDER BY quarantined_at DESC,job_id`)
	if err != nil {
		return nil, fmt.Errorf("list scanner-worker dead letters: %w", err)
	}
	defer rows.Close()
	items := []model.WorkerJobDeadLetter{}
	for rows.Next() {
		var item model.WorkerJobDeadLetter
		var quarantinedAt string
		if err := rows.Scan(&item.JobID, &item.ScanID, &item.WorkerID, &item.FailureCount, &item.Reason, &quarantinedAt); err != nil {
			return nil, fmt.Errorf("read scanner-worker dead letter: %w", err)
		}
		item.QuarantinedAt, err = parseTime(quarantinedAt)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
