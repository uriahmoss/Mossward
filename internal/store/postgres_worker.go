package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"mossward/internal/model"
)

func (s *PostgreSQLStore) CreateWorkerEnrollmentToken(token model.WorkerEnrollmentToken, event model.AuditEvent) error {
	cidrs, ports, err := encodePostgreSQLWorkerScope(token.AllowedCIDRs, token.AllowedPorts)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL scanner-worker enrollment token: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO scanner_worker_enrollment_tokens
		(id,name,site_id,token_hash,allowed_cidrs,allowed_ports,max_concurrent,rate_limit_per_second,created_by,created_at,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, token.ID, token.Name, token.SiteID, token.TokenHash,
		cidrs, ports, token.MaxConcurrent, token.RateLimitPerSecond, token.CreatedBy, token.CreatedAt, token.ExpiresAt)
	if err != nil {
		return fmt.Errorf("create PostgreSQL scanner-worker enrollment token: %w", err)
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) WorkerEnrollmentToken(hash []byte, now time.Time) (model.WorkerEnrollmentToken, error) {
	var token model.WorkerEnrollmentToken
	var cidrs, ports string
	err := s.db.QueryRow(`SELECT id,name,site_id,allowed_cidrs,allowed_ports,max_concurrent,rate_limit_per_second,
		created_by,created_at,expires_at FROM scanner_worker_enrollment_tokens
		WHERE token_hash=$1 AND used_at IS NULL AND expires_at>$2`, hash, now).Scan(&token.ID, &token.Name, &token.SiteID,
		&cidrs, &ports, &token.MaxConcurrent, &token.RateLimitPerSecond, &token.CreatedBy, &token.CreatedAt, &token.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return token, ErrInvalidEnrollmentToken
	}
	if err != nil {
		return token, fmt.Errorf("read PostgreSQL scanner-worker enrollment token: %w", err)
	}
	if err := decodePostgreSQLWorkerScope(cidrs, ports, &token.AllowedCIDRs, &token.AllowedPorts); err != nil {
		return token, err
	}
	return token, nil
}

func (s *PostgreSQLStore) ConsumeWorkerEnrollmentToken(hash []byte, worker model.ScannerWorker, now time.Time, event model.AuditEvent) error {
	cidrs, ports, err := encodePostgreSQLWorkerScope(worker.AllowedCIDRs, worker.AllowedPorts)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL scanner-worker enrollment: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE scanner_worker_enrollment_tokens SET used_at=$1
		WHERE token_hash=$2 AND used_at IS NULL AND expires_at>$1`, now, hash)
	if err != nil {
		return fmt.Errorf("consume PostgreSQL scanner-worker enrollment token: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrInvalidEnrollmentToken
	}
	_, err = tx.Exec(`INSERT INTO scanner_workers
		(id,name,site_id,status,certificate_serial,certificate_pem,allowed_cidrs,allowed_ports,max_concurrent,rate_limit_per_second,enrolled_at,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, worker.ID, worker.Name, worker.SiteID, worker.Status,
		worker.CertificateSerial, worker.CertificatePEM, cidrs, ports, worker.MaxConcurrent, worker.RateLimitPerSecond,
		worker.EnrolledAt, worker.ExpiresAt)
	if err != nil {
		return fmt.Errorf("create PostgreSQL scanner-worker identity: %w", err)
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

const postgresWorkerSelect = `SELECT id,name,site_id,status,certificate_serial,allowed_cidrs,allowed_ports,
	max_concurrent,rate_limit_per_second,enrolled_at,expires_at,last_seen_at,revoked_at,revocation_reason,
	software_version,operating_system,architecture,capabilities,available_concurrency,health,health_message,dispatch_enabled
	FROM scanner_workers`

func (s *PostgreSQLStore) ListScannerWorkers() ([]model.ScannerWorker, error) {
	rows, err := s.db.Query(postgresWorkerSelect + ` ORDER BY name,enrolled_at`)
	if err != nil {
		return nil, fmt.Errorf("list PostgreSQL scanner workers: %w", err)
	}
	defer rows.Close()
	workers := []model.ScannerWorker{}
	for rows.Next() {
		worker, err := scanPostgreSQLWorker(rows)
		if err != nil {
			return nil, err
		}
		workers = append(workers, worker)
	}
	return workers, rows.Err()
}

func (s *PostgreSQLStore) ScannerWorkerBySerial(serial string) (model.ScannerWorker, error) {
	worker, err := scanPostgreSQLWorker(s.db.QueryRow(postgresWorkerSelect+` WHERE certificate_serial=$1`, serial))
	if errors.Is(err, sql.ErrNoRows) {
		return worker, ErrNotFound
	}
	return worker, err
}

func (s *PostgreSQLStore) RecordScannerWorkerHeartbeat(id string, heartbeat model.WorkerHeartbeat, seenAt time.Time) error {
	capabilities, err := json.Marshal(heartbeat.Capabilities)
	if err != nil {
		return fmt.Errorf("encode PostgreSQL scanner-worker capabilities: %w", err)
	}
	result, err := s.db.Exec(`UPDATE scanner_workers SET last_seen_at=$1,software_version=$2,operating_system=$3,
		architecture=$4,capabilities=$5,available_concurrency=$6,health=$7,health_message=$8
		WHERE id=$9 AND status='active'`, seenAt, heartbeat.SoftwareVersion, heartbeat.OperatingSystem,
		heartbeat.Architecture, string(capabilities), heartbeat.AvailableConcurrency, heartbeat.Health, heartbeat.HealthMessage, id)
	if err != nil {
		return fmt.Errorf("record PostgreSQL scanner-worker heartbeat: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrNotFound
	}
	return nil
}

func (s *PostgreSQLStore) RevokeScannerWorker(id, reason string, revokedAt time.Time, event model.AuditEvent) error {
	return s.updatePostgreSQLWorker(`UPDATE scanner_workers SET status='revoked',revoked_at=$1,revocation_reason=$2
		WHERE id=$3 AND status='active'`, []any{revokedAt, reason, id}, event, "revocation")
}

func (s *PostgreSQLStore) ScannerWorkerDispatchSettings() (model.WorkerDispatchSettings, error) {
	var settings model.WorkerDispatchSettings
	if err := s.db.QueryRow(`SELECT enabled FROM scanner_worker_dispatch_settings WHERE singleton=TRUE`).Scan(&settings.Enabled); err != nil {
		return settings, fmt.Errorf("read PostgreSQL scanner-worker dispatch settings: %w", err)
	}
	return settings, nil
}

func (s *PostgreSQLStore) SetScannerWorkerDispatch(enabled bool, event model.AuditEvent) error {
	return s.updatePostgreSQLWorker(`UPDATE scanner_worker_dispatch_settings SET enabled=$1 WHERE singleton=TRUE`,
		[]any{enabled}, event, "global dispatch")
}

func (s *PostgreSQLStore) SetScannerWorkerDispatchForWorker(id string, enabled bool, event model.AuditEvent) error {
	return s.updatePostgreSQLWorker(`UPDATE scanner_workers SET dispatch_enabled=$1 WHERE id=$2 AND status='active'`,
		[]any{enabled, id}, event, "worker dispatch")
}

func (s *PostgreSQLStore) updatePostgreSQLWorker(query string, arguments []any, event model.AuditEvent, operation string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL scanner-worker %s update: %w", operation, err)
	}
	defer tx.Rollback()
	result, err := tx.Exec(query, arguments...)
	if err != nil {
		return fmt.Errorf("update PostgreSQL scanner-worker %s: %w", operation, err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("count PostgreSQL scanner-worker %s update: %w", operation, err)
	}
	if changed != 1 {
		return ErrNotFound
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func scanPostgreSQLWorker(scanner interface{ Scan(...any) error }) (model.ScannerWorker, error) {
	var worker model.ScannerWorker
	var cidrs, ports, capabilities string
	var lastSeen, revokedAt sql.NullTime
	err := scanner.Scan(&worker.ID, &worker.Name, &worker.SiteID, &worker.Status, &worker.CertificateSerial, &cidrs, &ports,
		&worker.MaxConcurrent, &worker.RateLimitPerSecond, &worker.EnrolledAt, &worker.ExpiresAt, &lastSeen, &revokedAt,
		&worker.RevocationReason, &worker.SoftwareVersion, &worker.OperatingSystem, &worker.Architecture, &capabilities,
		&worker.AvailableConcurrency, &worker.Health, &worker.HealthMessage, &worker.DispatchEnabled)
	if err != nil {
		return worker, err
	}
	if err := decodePostgreSQLWorkerScope(cidrs, ports, &worker.AllowedCIDRs, &worker.AllowedPorts); err != nil {
		return worker, err
	}
	if err := json.Unmarshal([]byte(capabilities), &worker.Capabilities); err != nil {
		return worker, fmt.Errorf("decode PostgreSQL scanner-worker capabilities: %w", err)
	}
	worker.LastSeenAt = nullablePostgreSQLTime(lastSeen)
	worker.RevokedAt = nullablePostgreSQLTime(revokedAt)
	return worker, nil
}

func encodePostgreSQLWorkerScope(cidrs []string, ports []int) (string, string, error) {
	encodedCIDRs, err := json.Marshal(cidrs)
	if err != nil {
		return "", "", fmt.Errorf("encode PostgreSQL scanner-worker networks: %w", err)
	}
	encodedPorts, err := json.Marshal(ports)
	if err != nil {
		return "", "", fmt.Errorf("encode PostgreSQL scanner-worker ports: %w", err)
	}
	return string(encodedCIDRs), string(encodedPorts), nil
}

func decodePostgreSQLWorkerScope(cidrs, ports string, decodedCIDRs *[]string, decodedPorts *[]int) error {
	if err := json.Unmarshal([]byte(cidrs), decodedCIDRs); err != nil {
		return fmt.Errorf("decode PostgreSQL scanner-worker networks: %w", err)
	}
	if err := json.Unmarshal([]byte(ports), decodedPorts); err != nil {
		return fmt.Errorf("decode PostgreSQL scanner-worker ports: %w", err)
	}
	return nil
}
