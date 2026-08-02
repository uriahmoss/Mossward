package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"mossward/internal/model"
)

func (s *SQLiteStore) CreateWorkerEnrollmentToken(token model.WorkerEnrollmentToken, event model.AuditEvent) error {
	cidrs, err := json.Marshal(token.AllowedCIDRs)
	if err != nil {
		return fmt.Errorf("encode scanner-worker networks: %w", err)
	}
	ports, err := json.Marshal(token.AllowedPorts)
	if err != nil {
		return fmt.Errorf("encode scanner-worker ports: %w", err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin scanner-worker enrollment token: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO scanner_worker_enrollment_tokens(id,name,token_hash,allowed_cidrs,allowed_ports,max_concurrent,rate_limit_per_second,created_by,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, token.ID, token.Name, token.TokenHash, cidrs, ports, token.MaxConcurrent, token.RateLimitPerSecond, token.CreatedBy, formatTime(token.CreatedAt), formatTime(token.ExpiresAt))
	if err != nil {
		return fmt.Errorf("create scanner-worker enrollment token: %w", err)
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) WorkerEnrollmentToken(hash []byte, now time.Time) (model.WorkerEnrollmentToken, error) {
	var token model.WorkerEnrollmentToken
	var cidrs, ports, createdAt, expiresAt string
	err := s.db.QueryRow(`SELECT id,name,allowed_cidrs,allowed_ports,max_concurrent,rate_limit_per_second,created_by,created_at,expires_at FROM scanner_worker_enrollment_tokens WHERE token_hash=? AND used_at IS NULL AND expires_at>?`, hash, formatTime(now)).Scan(&token.ID, &token.Name, &cidrs, &ports, &token.MaxConcurrent, &token.RateLimitPerSecond, &token.CreatedBy, &createdAt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return token, ErrInvalidEnrollmentToken
	}
	if err != nil {
		return token, err
	}
	if err := json.Unmarshal([]byte(cidrs), &token.AllowedCIDRs); err != nil {
		return token, err
	}
	if err := json.Unmarshal([]byte(ports), &token.AllowedPorts); err != nil {
		return token, err
	}
	token.CreatedAt, _ = parseTime(createdAt)
	token.ExpiresAt, _ = parseTime(expiresAt)
	return token, nil
}

func (s *SQLiteStore) ConsumeWorkerEnrollmentToken(hash []byte, worker model.ScannerWorker, now time.Time, event model.AuditEvent) error {
	cidrs, err := json.Marshal(worker.AllowedCIDRs)
	if err != nil {
		return fmt.Errorf("encode scanner-worker networks: %w", err)
	}
	ports, err := json.Marshal(worker.AllowedPorts)
	if err != nil {
		return fmt.Errorf("encode scanner-worker ports: %w", err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin scanner-worker enrollment: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE scanner_worker_enrollment_tokens SET used_at=? WHERE token_hash=? AND used_at IS NULL AND expires_at>?`, formatTime(now), hash, formatTime(now))
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return ErrInvalidEnrollmentToken
	}
	_, err = tx.Exec(`INSERT INTO scanner_workers(id,name,status,certificate_serial,certificate_pem,allowed_cidrs,allowed_ports,max_concurrent,rate_limit_per_second,enrolled_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, worker.ID, worker.Name, worker.Status, worker.CertificateSerial, worker.CertificatePEM, cidrs, ports, worker.MaxConcurrent, worker.RateLimitPerSecond, formatTime(worker.EnrolledAt), formatTime(worker.ExpiresAt))
	if err != nil {
		return fmt.Errorf("create scanner-worker identity: %w", err)
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) ListScannerWorkers() ([]model.ScannerWorker, error) {
	rows, err := s.db.Query(workerSelect + ` ORDER BY name,enrolled_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	workers := []model.ScannerWorker{}
	for rows.Next() {
		worker, err := scanWorker(rows)
		if err != nil {
			return nil, err
		}
		workers = append(workers, worker)
	}
	return workers, rows.Err()
}

func (s *SQLiteStore) ScannerWorkerBySerial(serial string) (model.ScannerWorker, error) {
	worker, err := scanWorker(s.db.QueryRow(workerSelect+` WHERE certificate_serial=?`, serial))
	if errors.Is(err, sql.ErrNoRows) {
		return worker, ErrNotFound
	}
	return worker, err
}

const workerSelect = `SELECT id,name,status,certificate_serial,allowed_cidrs,allowed_ports,max_concurrent,rate_limit_per_second,enrolled_at,expires_at,last_seen_at,revoked_at,revocation_reason,software_version,operating_system,architecture,capabilities,available_concurrency,health,health_message FROM scanner_workers`

func (s *SQLiteStore) RecordScannerWorkerHeartbeat(id string, heartbeat model.WorkerHeartbeat, seenAt time.Time) error {
	capabilities, err := json.Marshal(heartbeat.Capabilities)
	if err != nil {
		return fmt.Errorf("encode scanner-worker capabilities: %w", err)
	}
	result, err := s.db.Exec(`UPDATE scanner_workers SET last_seen_at=?,software_version=?,operating_system=?,architecture=?,capabilities=?,available_concurrency=?,health=?,health_message=? WHERE id=? AND status='active'`, formatTime(seenAt), heartbeat.SoftwareVersion, heartbeat.OperatingSystem, heartbeat.Architecture, capabilities, heartbeat.AvailableConcurrency, heartbeat.Health, heartbeat.HealthMessage, id)
	if err != nil {
		return fmt.Errorf("record scanner-worker heartbeat: %w", err)
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLiteStore) RevokeScannerWorker(id, reason string, revokedAt time.Time, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE scanner_workers SET status='revoked',revoked_at=?,revocation_reason=? WHERE id=? AND status='active'`, formatTime(revokedAt), reason, id)
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return ErrNotFound
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

type workerScanner interface{ Scan(...any) error }

func scanWorker(row workerScanner) (model.ScannerWorker, error) {
	var worker model.ScannerWorker
	var cidrs, ports, enrolledAt, expiresAt, capabilities string
	var lastSeen, revokedAt sql.NullString
	if err := row.Scan(&worker.ID, &worker.Name, &worker.Status, &worker.CertificateSerial, &cidrs, &ports,
		&worker.MaxConcurrent, &worker.RateLimitPerSecond, &enrolledAt, &expiresAt, &lastSeen, &revokedAt,
		&worker.RevocationReason, &worker.SoftwareVersion, &worker.OperatingSystem, &worker.Architecture,
		&capabilities, &worker.AvailableConcurrency, &worker.Health, &worker.HealthMessage); err != nil {
		return worker, err
	}
	if err := json.Unmarshal([]byte(cidrs), &worker.AllowedCIDRs); err != nil {
		return worker, err
	}
	if err := json.Unmarshal([]byte(ports), &worker.AllowedPorts); err != nil {
		return worker, err
	}
	if err := json.Unmarshal([]byte(capabilities), &worker.Capabilities); err != nil {
		return worker, err
	}
	worker.EnrolledAt, _ = parseTime(enrolledAt)
	worker.ExpiresAt, _ = parseTime(expiresAt)
	worker.LastSeenAt = parseNullableTime(lastSeen)
	worker.RevokedAt = parseNullableTime(revokedAt)
	return worker, nil
}
