package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"mossward/internal/model"
)

func (s *PostgreSQLStore) CreateAgentEnrollmentToken(token model.AgentEnrollmentToken, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL endpoint enrollment token: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO agent_enrollment_tokens(id,name,token_hash,created_by,created_at,expires_at)
		VALUES($1,$2,$3,$4,$5,$6)`, token.ID, token.Name, token.TokenHash, token.CreatedBy, token.CreatedAt, token.ExpiresAt)
	if err != nil {
		return fmt.Errorf("create PostgreSQL endpoint enrollment token: %w", err)
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) ListAgentEnrollmentTokens(now time.Time) ([]model.AgentEnrollmentToken, error) {
	rows, err := s.db.Query(`SELECT id,name,created_by,created_at,expires_at,used_at
		FROM agent_enrollment_tokens WHERE expires_at>$1 ORDER BY created_at DESC`, now)
	if err != nil {
		return nil, fmt.Errorf("list PostgreSQL endpoint enrollment tokens: %w", err)
	}
	defer rows.Close()
	tokens := []model.AgentEnrollmentToken{}
	for rows.Next() {
		var token model.AgentEnrollmentToken
		var usedAt sql.NullTime
		if err := rows.Scan(&token.ID, &token.Name, &token.CreatedBy, &token.CreatedAt, &token.ExpiresAt, &usedAt); err != nil {
			return nil, fmt.Errorf("read PostgreSQL endpoint enrollment token: %w", err)
		}
		token.UsedAt = nullablePostgreSQLTime(usedAt)
		tokens = append(tokens, token)
	}
	return tokens, rows.Err()
}

func (s *PostgreSQLStore) AgentEnrollmentTokenName(hash []byte, now time.Time) (string, error) {
	var name string
	err := s.db.QueryRow(`SELECT name FROM agent_enrollment_tokens
		WHERE token_hash=$1 AND used_at IS NULL AND expires_at>$2`, hash, now).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrInvalidEnrollmentToken
	}
	if err != nil {
		return "", fmt.Errorf("look up PostgreSQL endpoint enrollment token: %w", err)
	}
	return name, nil
}

func (s *PostgreSQLStore) ConsumeAgentEnrollmentToken(hash []byte, endpoint model.Endpoint, now time.Time, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL endpoint enrollment: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE agent_enrollment_tokens SET used_at=$1
		WHERE token_hash=$2 AND used_at IS NULL AND expires_at>$1`, now, hash)
	if err != nil {
		return fmt.Errorf("consume PostgreSQL endpoint enrollment token: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrInvalidEnrollmentToken
	}
	_, err = tx.Exec(`INSERT INTO endpoints(id,name,status,certificate_serial,certificate_pem,enrolled_at,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7)`, endpoint.ID, endpoint.Name, endpoint.Status, endpoint.CertificateSerial,
		endpoint.CertificatePEM, endpoint.EnrolledAt, endpoint.ExpiresAt)
	if err != nil {
		return fmt.Errorf("create PostgreSQL endpoint identity: %w", err)
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) ListEndpoints() ([]model.Endpoint, error) {
	rows, err := s.db.Query(postgresEndpointSelect + ` ORDER BY name,enrolled_at`)
	if err != nil {
		return nil, fmt.Errorf("list PostgreSQL endpoints: %w", err)
	}
	defer rows.Close()
	endpoints := []model.Endpoint{}
	for rows.Next() {
		endpoint, err := scanPostgreSQLEndpoint(rows)
		if err != nil {
			return nil, err
		}
		endpoints = append(endpoints, endpoint)
	}
	return endpoints, rows.Err()
}

func (s *PostgreSQLStore) EndpointBySerial(serial string) (model.Endpoint, error) {
	endpoint, err := scanPostgreSQLEndpoint(s.db.QueryRow(postgresEndpointSelect+` WHERE certificate_serial=$1`, serial))
	if errors.Is(err, sql.ErrNoRows) {
		return model.Endpoint{}, ErrNotFound
	}
	return endpoint, err
}

const postgresEndpointSelect = `SELECT id,name,status,certificate_serial,enrolled_at,expires_at,last_seen_at,
	last_heartbeat_generated_at,last_heartbeat_received_at,renewed_at,revoked_at,revocation_reason,allowed_collectors,
	network_telemetry_exclusions,software_version,operating_system,architecture FROM endpoints`

func scanPostgreSQLEndpoint(scanner interface{ Scan(...any) error }) (model.Endpoint, error) {
	var endpoint model.Endpoint
	var lastSeen, heartbeatGenerated, heartbeatReceived, renewedAt, revokedAt sql.NullTime
	var collectors, exclusions []byte
	err := scanner.Scan(&endpoint.ID, &endpoint.Name, &endpoint.Status, &endpoint.CertificateSerial, &endpoint.EnrolledAt,
		&endpoint.ExpiresAt, &lastSeen, &heartbeatGenerated, &heartbeatReceived, &renewedAt, &revokedAt,
		&endpoint.RevocationReason, &collectors, &exclusions, &endpoint.SoftwareVersion, &endpoint.OperatingSystem,
		&endpoint.Architecture)
	if err != nil {
		return endpoint, err
	}
	if err := json.Unmarshal(collectors, &endpoint.AllowedCollectors); err != nil {
		return endpoint, fmt.Errorf("decode PostgreSQL endpoint collector policy: %w", err)
	}
	if err := json.Unmarshal(exclusions, &endpoint.NetworkExclusions); err != nil {
		return endpoint, fmt.Errorf("decode PostgreSQL endpoint network exclusions: %w", err)
	}
	endpoint.LastSeenAt = nullablePostgreSQLTime(lastSeen)
	endpoint.LastHeartbeatGeneratedAt = nullablePostgreSQLTime(heartbeatGenerated)
	endpoint.LastHeartbeatReceivedAt = nullablePostgreSQLTime(heartbeatReceived)
	endpoint.RenewedAt = nullablePostgreSQLTime(renewedAt)
	endpoint.RevokedAt = nullablePostgreSQLTime(revokedAt)
	return endpoint, nil
}

func (s *PostgreSQLStore) RenewEndpointCertificate(oldSerial string, endpoint model.Endpoint, event model.AuditEvent) error {
	if endpoint.RenewedAt == nil {
		return errors.New("endpoint certificate renewal time is required")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL endpoint certificate renewal: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE endpoints SET certificate_serial=$1,certificate_pem=$2,expires_at=$3,renewed_at=$4
		WHERE id=$5 AND certificate_serial=$6 AND status='active'`, endpoint.CertificateSerial, endpoint.CertificatePEM,
		endpoint.ExpiresAt, *endpoint.RenewedAt, endpoint.ID, oldSerial)
	if err != nil {
		return fmt.Errorf("renew PostgreSQL endpoint certificate: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrEndpointCertificateChanged
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) RevokeEndpoint(id, reason string, revokedAt time.Time, event model.AuditEvent) error {
	return s.updatePostgreSQLEndpoint(`UPDATE endpoints SET status='revoked',revoked_at=$1,revocation_reason=$2
		WHERE id=$3 AND status='active'`, []any{revokedAt, reason, id}, event, "revocation")
}

func (s *PostgreSQLStore) MarkEndpointSeen(id string, seenAt time.Time) error {
	_, err := s.db.Exec(`UPDATE endpoints SET last_seen_at=$1 WHERE id=$2 AND status='active'`, seenAt, id)
	if err != nil {
		return fmt.Errorf("mark PostgreSQL endpoint seen: %w", err)
	}
	return nil
}

func (s *PostgreSQLStore) SetEndpointCollectors(id string, collectors []model.CollectorID, event model.AuditEvent) error {
	encoded, err := json.Marshal(collectors)
	if err != nil {
		return fmt.Errorf("encode PostgreSQL endpoint collectors: %w", err)
	}
	return s.updatePostgreSQLEndpoint(`UPDATE endpoints SET allowed_collectors=$1::jsonb WHERE id=$2 AND status='active'`,
		[]any{string(encoded), id}, event, "collector policy")
}

func (s *PostgreSQLStore) SetEndpointNetworkExclusions(id string, exclusions model.NetworkTelemetryExclusions, event model.AuditEvent) error {
	encoded, err := json.Marshal(exclusions)
	if err != nil {
		return fmt.Errorf("encode PostgreSQL endpoint network exclusions: %w", err)
	}
	return s.updatePostgreSQLEndpoint(
		`UPDATE endpoints SET network_telemetry_exclusions=$1::jsonb WHERE id=$2 AND status='active'`,
		[]any{string(encoded), id}, event, "network-exclusion policy")
}

func (s *PostgreSQLStore) updatePostgreSQLEndpoint(query string, arguments []any, event model.AuditEvent, operation string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL endpoint %s update: %w", operation, err)
	}
	defer tx.Rollback()
	result, err := tx.Exec(query, arguments...)
	if err != nil {
		return fmt.Errorf("update PostgreSQL endpoint %s: %w", operation, err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return ErrNotFound
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}
