package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"mossward/internal/model"
)

func (s *SQLiteStore) CreateAgentEnrollmentToken(token model.AgentEnrollmentToken, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin endpoint enrollment token: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO agent_enrollment_tokens(id, name, token_hash, created_by, created_at, expires_at)
		VALUES(?,?,?,?,?,?)`, token.ID, token.Name, token.TokenHash, token.CreatedBy, formatTime(token.CreatedAt), formatTime(token.ExpiresAt)); err != nil {
		return fmt.Errorf("create endpoint enrollment token: %w", err)
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) ListAgentEnrollmentTokens(now time.Time) ([]model.AgentEnrollmentToken, error) {
	rows, err := s.db.Query(`SELECT id, name, created_by, created_at, expires_at, used_at
		FROM agent_enrollment_tokens WHERE expires_at>? ORDER BY created_at DESC`, formatTime(now))
	if err != nil {
		return nil, fmt.Errorf("list endpoint enrollment tokens: %w", err)
	}
	defer rows.Close()
	items := []model.AgentEnrollmentToken{}
	for rows.Next() {
		var item model.AgentEnrollmentToken
		var createdAt, expiresAt string
		var usedAt sql.NullString
		if err := rows.Scan(&item.ID, &item.Name, &item.CreatedBy, &createdAt, &expiresAt, &usedAt); err != nil {
			return nil, fmt.Errorf("scan endpoint enrollment token: %w", err)
		}
		item.CreatedAt, _ = parseTime(createdAt)
		item.ExpiresAt, _ = parseTime(expiresAt)
		item.UsedAt = parseNullableTime(usedAt)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *SQLiteStore) AgentEnrollmentTokenName(hash []byte, now time.Time) (string, error) {
	var name string
	err := s.db.QueryRow(`SELECT name FROM agent_enrollment_tokens
		WHERE token_hash=? AND used_at IS NULL AND expires_at>?`, hash, formatTime(now)).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrInvalidEnrollmentToken
	}
	return name, err
}

func (s *SQLiteStore) ConsumeAgentEnrollmentToken(hash []byte, endpoint model.Endpoint, now time.Time, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin endpoint enrollment: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE agent_enrollment_tokens SET used_at=?
		WHERE token_hash=? AND used_at IS NULL AND expires_at>?`, formatTime(now), hash, formatTime(now))
	if err != nil {
		return fmt.Errorf("consume endpoint enrollment token: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrInvalidEnrollmentToken
	}
	_, err = tx.Exec(`INSERT INTO endpoints(id, name, status, certificate_serial, certificate_pem, enrolled_at, expires_at)
		VALUES(?,?,?,?,?,?,?)`, endpoint.ID, endpoint.Name, endpoint.Status, endpoint.CertificateSerial,
		endpoint.CertificatePEM, formatTime(endpoint.EnrolledAt), formatTime(endpoint.ExpiresAt))
	if err != nil {
		return fmt.Errorf("create endpoint identity: %w", err)
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) ListEndpoints() ([]model.Endpoint, error) {
	rows, err := s.db.Query(`SELECT id, name, status, certificate_serial, enrolled_at, expires_at, last_seen_at
		FROM endpoints ORDER BY name, enrolled_at`)
	if err != nil {
		return nil, fmt.Errorf("list endpoints: %w", err)
	}
	defer rows.Close()
	items := []model.Endpoint{}
	for rows.Next() {
		endpoint, err := scanEndpoint(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, endpoint)
	}
	return items, rows.Err()
}

func (s *SQLiteStore) EndpointBySerial(serial string) (model.Endpoint, error) {
	row := s.db.QueryRow(`SELECT id, name, status, certificate_serial, enrolled_at, expires_at, last_seen_at
		FROM endpoints WHERE certificate_serial=?`, serial)
	endpoint, err := scanEndpoint(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Endpoint{}, ErrNotFound
	}
	return endpoint, err
}

func (s *SQLiteStore) MarkEndpointSeen(id string, seenAt time.Time) error {
	_, err := s.db.Exec(`UPDATE endpoints SET last_seen_at=? WHERE id=? AND status='active'`, formatTime(seenAt), id)
	return err
}

type endpointScanner interface {
	Scan(...any) error
}

func scanEndpoint(row endpointScanner) (model.Endpoint, error) {
	var endpoint model.Endpoint
	var enrolledAt, expiresAt string
	var lastSeen sql.NullString
	if err := row.Scan(&endpoint.ID, &endpoint.Name, &endpoint.Status, &endpoint.CertificateSerial, &enrolledAt, &expiresAt, &lastSeen); err != nil {
		return model.Endpoint{}, err
	}
	endpoint.EnrolledAt, _ = parseTime(enrolledAt)
	endpoint.ExpiresAt, _ = parseTime(expiresAt)
	endpoint.LastSeenAt = parseNullableTime(lastSeen)
	return endpoint, nil
}

func parseNullableTime(value sql.NullString) *time.Time {
	if !value.Valid {
		return nil
	}
	parsed, err := parseTime(value.String)
	if err != nil {
		return nil
	}
	return &parsed
}
