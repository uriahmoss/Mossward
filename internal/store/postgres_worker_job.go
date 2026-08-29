package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"mossward/internal/model"
)

func (s *PostgreSQLStore) CreateScannerWorkerJob(envelope model.SignedWorkerJob, createdAt time.Time) error {
	encoded, err := encodePostgreSQLWorkerJob(envelope)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL scanner-worker job creation: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.Exec(`INSERT INTO scanner_worker_jobs
		(id,worker_id,scan_id,status,signed_envelope,issued_at,expires_at,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(id) DO NOTHING`, envelope.Job.ID, envelope.Job.WorkerID,
		envelope.Job.ScanID, envelope.Job.Status, encoded, envelope.Job.IssuedAt, envelope.Job.ExpiresAt, createdAt)
	if err != nil {
		return fmt.Errorf("create PostgreSQL scanner-worker job: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("count PostgreSQL scanner-worker job creation: %w", err)
	}
	if changed != 1 {
		return ErrWorkerJobReplay
	}
	_, err = tx.Exec(`INSERT INTO scanner_worker_job_assignments
		(job_id,attempt,worker_id,signed_envelope,assigned_at,reason) VALUES($1,1,$2,$3,$4,'initial')`,
		envelope.Job.ID, envelope.Job.WorkerID, encoded, createdAt)
	if err != nil {
		return fmt.Errorf("record initial PostgreSQL scanner-worker job assignment: %w", err)
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) ScannerWorkerJob(id string) (model.SignedWorkerJob, error) {
	var encoded string
	err := s.db.QueryRow(`SELECT signed_envelope FROM scanner_worker_jobs WHERE id=$1`, id).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return model.SignedWorkerJob{}, ErrNotFound
	}
	if err != nil {
		return model.SignedWorkerJob{}, fmt.Errorf("read PostgreSQL scanner-worker job: %w", err)
	}
	return decodePostgreSQLWorkerJob(encoded)
}

func (s *PostgreSQLStore) ScannerWorkerJobLoads(now time.Time) (map[string]model.WorkerJobLoad, error) {
	rows, err := s.db.Query(`SELECT worker_id,signed_envelope FROM scanner_worker_jobs
		WHERE status IN ('pending','leased') AND expires_at>$1`, now)
	if err != nil {
		return nil, fmt.Errorf("list active PostgreSQL scanner-worker jobs: %w", err)
	}
	defer rows.Close()
	loads := map[string]model.WorkerJobLoad{}
	for rows.Next() {
		var workerID, encoded string
		if err := rows.Scan(&workerID, &encoded); err != nil {
			return nil, fmt.Errorf("read active PostgreSQL scanner-worker job: %w", err)
		}
		envelope, err := decodePostgreSQLWorkerJob(encoded)
		if err != nil {
			return nil, err
		}
		load := loads[workerID]
		load.ActiveJobs++
		load.ReservedConcurrency += envelope.Job.MaxConcurrent
		loads[workerID] = load
	}
	return loads, rows.Err()
}

func (s *PostgreSQLStore) LeaseScannerWorkerJob(workerID string, tokenHash []byte, now, leaseExpiresAt time.Time) (model.SignedWorkerJob, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return model.SignedWorkerJob{}, fmt.Errorf("begin PostgreSQL scanner-worker job lease: %w", err)
	}
	defer tx.Rollback()
	if err := quarantineRepeatedPostgreSQLWorkerJobs(tx, workerID, now); err != nil {
		return model.SignedWorkerJob{}, err
	}
	if _, err := tx.Exec(`UPDATE scanner_worker_jobs SET status='expired',lease_token_hash=NULL,lease_expires_at=NULL
		WHERE worker_id=$1 AND status IN ('pending','leased') AND expires_at<=$2`, workerID, now); err != nil {
		return model.SignedWorkerJob{}, fmt.Errorf("expire PostgreSQL scanner-worker jobs: %w", err)
	}
	if _, err := tx.Exec(`UPDATE scanner_worker_jobs SET status='pending',lease_token_hash=NULL,lease_expires_at=NULL
		WHERE worker_id=$1 AND status='leased' AND lease_expires_at<=$2 AND expires_at>$2`, workerID, now); err != nil {
		return model.SignedWorkerJob{}, fmt.Errorf("release expired PostgreSQL scanner-worker job leases: %w", err)
	}
	var id, encoded string
	err = tx.QueryRow(`SELECT j.id,j.signed_envelope FROM scanner_worker_jobs j
		JOIN scanner_workers w ON w.id=j.worker_id JOIN scanner_worker_dispatch_settings d ON d.singleton=TRUE
		WHERE j.worker_id=$1 AND j.status='pending' AND j.expires_at>$2 AND w.dispatch_enabled=TRUE AND d.enabled=TRUE
		ORDER BY j.created_at,j.id LIMIT 1 FOR UPDATE OF j SKIP LOCKED`, workerID, now).Scan(&id, &encoded)
	if errors.Is(err, sql.ErrNoRows) {
		if err := tx.Commit(); err != nil {
			return model.SignedWorkerJob{}, fmt.Errorf("commit PostgreSQL scanner-worker lease maintenance: %w", err)
		}
		return model.SignedWorkerJob{}, ErrNotFound
	}
	if err != nil {
		return model.SignedWorkerJob{}, fmt.Errorf("select PostgreSQL scanner-worker job lease: %w", err)
	}
	result, err := tx.Exec(`UPDATE scanner_worker_jobs SET status='leased',lease_token_hash=$1,
		lease_expires_at=LEAST(expires_at,$2),lease_attempt=lease_attempt+1
		WHERE id=$3 AND worker_id=$4 AND status='pending'`, tokenHash, leaseExpiresAt, id, workerID)
	if err != nil {
		return model.SignedWorkerJob{}, fmt.Errorf("lease PostgreSQL scanner-worker job: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return model.SignedWorkerJob{}, errors.New("PostgreSQL scanner-worker job lease conflict")
	}
	envelope, err := decodePostgreSQLWorkerJob(encoded)
	if err != nil {
		return envelope, err
	}
	if err := tx.Commit(); err != nil {
		return envelope, fmt.Errorf("commit PostgreSQL scanner-worker job lease: %w", err)
	}
	return envelope, nil
}

func (s *PostgreSQLStore) RenewScannerWorkerJobLease(workerID, jobID string, tokenHash []byte, now, requestedExpiry time.Time) (time.Time, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return time.Time{}, fmt.Errorf("begin PostgreSQL scanner-worker lease renewal: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE scanner_worker_jobs SET lease_expires_at=LEAST(expires_at,GREATEST(lease_expires_at,$1))
		WHERE id=$2 AND worker_id=$3 AND status='leased' AND lease_token_hash=$4 AND lease_expires_at>$5 AND expires_at>$5`,
		requestedExpiry, jobID, workerID, tokenHash, now)
	if err != nil {
		return time.Time{}, fmt.Errorf("renew PostgreSQL scanner-worker job lease: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return time.Time{}, ErrInvalidWorkerJobLease
	}
	var stored time.Time
	if err := tx.QueryRow(`SELECT lease_expires_at FROM scanner_worker_jobs WHERE id=$1`, jobID).Scan(&stored); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return time.Time{}, ErrInvalidWorkerJobLease
		}
		return time.Time{}, fmt.Errorf("read renewed PostgreSQL scanner-worker lease: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return time.Time{}, fmt.Errorf("commit PostgreSQL scanner-worker lease renewal: %w", err)
	}
	return stored, nil
}

func quarantineRepeatedPostgreSQLWorkerJobs(tx *sql.Tx, workerID string, now time.Time) error {
	result, err := tx.Exec(`INSERT INTO scanner_worker_job_dead_letters
		(job_id,scan_id,worker_id,failure_count,reason,quarantined_at)
		SELECT id,scan_id,worker_id,lease_attempt,$1,$2 FROM scanner_worker_jobs
		WHERE worker_id=$3 AND status='leased' AND lease_expires_at<=$2 AND expires_at>$2 AND lease_attempt>=$4
		ON CONFLICT(job_id) DO NOTHING`, workerLeaseFailureReason, now, workerID, maximumWorkerLeaseAttempts)
	if err != nil {
		return fmt.Errorf("quarantine repeated PostgreSQL scanner-worker jobs: %w", err)
	}
	quarantined, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("count quarantined PostgreSQL scanner-worker jobs: %w", err)
	}
	_, err = tx.Exec(`UPDATE scans SET status='failed',error=$1,completed_at=$2 WHERE id IN
		(SELECT scan_id FROM scanner_worker_job_dead_letters WHERE worker_id=$3 AND quarantined_at=$2)
		AND status IN ('queued','running','paused')`, workerLeaseFailureReason, now, workerID)
	if err != nil {
		return fmt.Errorf("fail scans for quarantined PostgreSQL scanner-worker jobs: %w", err)
	}
	_, err = tx.Exec(`UPDATE scanner_worker_jobs SET status='canceled',lease_token_hash=NULL,lease_expires_at=NULL
		WHERE id IN (SELECT job_id FROM scanner_worker_job_dead_letters) AND status='leased'`)
	if err != nil {
		return fmt.Errorf("stop quarantined PostgreSQL scanner-worker jobs: %w", err)
	}
	if quarantined > 0 {
		slog.Warn("PostgreSQL scanner-worker jobs entered dead-letter quarantine", "worker_id", workerID,
			"count", quarantined, "reason", workerLeaseFailureReason)
	}
	return nil
}

func encodePostgreSQLWorkerJob(envelope model.SignedWorkerJob) (string, error) {
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return "", fmt.Errorf("encode PostgreSQL scanner-worker job: %w", err)
	}
	return string(encoded), nil
}

func decodePostgreSQLWorkerJob(encoded string) (model.SignedWorkerJob, error) {
	var envelope model.SignedWorkerJob
	if err := json.Unmarshal([]byte(encoded), &envelope); err != nil {
		return envelope, fmt.Errorf("decode PostgreSQL scanner-worker job: %w", err)
	}
	return envelope, nil
}
