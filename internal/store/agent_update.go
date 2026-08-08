package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"mossward/internal/model"
)

func (s *SQLiteStore) CreateAgentUpdateRelease(release model.AgentUpdateRelease, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO agent_update_releases(id,version,operating_system,architecture,artifact_sha256,artifact_size,signing_key_id,envelope,status,created_by,created_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)`, release.ID, release.Version, release.OperatingSystem, release.Architecture,
		release.ArtifactSHA256, release.ArtifactSize, release.SigningKeyID, release.Envelope, release.Status,
		release.CreatedBy, formatTime(release.CreatedAt))
	if err != nil {
		return fmt.Errorf("create agent-update release: %w", err)
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) ListAgentUpdateReleases() ([]model.AgentUpdateRelease, error) {
	rows, err := s.db.Query(`SELECT id,version,operating_system,architecture,artifact_sha256,artifact_size,signing_key_id,status,created_by,created_at,COALESCE(approved_by,''),approved_at,COALESCE(revoked_by,''),revoked_at,revocation_reason
		FROM agent_update_releases ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	releases := []model.AgentUpdateRelease{}
	for rows.Next() {
		release, err := scanAgentUpdateRelease(rows)
		if err != nil {
			return nil, err
		}
		releases = append(releases, release)
	}
	return releases, rows.Err()
}

func (s *SQLiteStore) AgentUpdateEnvelope(id string) ([]byte, error) {
	var envelope []byte
	err := s.db.QueryRow(`SELECT envelope FROM agent_update_releases WHERE id=? AND status='approved'`, id).Scan(&envelope)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return envelope, err
}

func (s *SQLiteStore) ApproveAgentUpdateRelease(id, actorID string, approvedAt time.Time, event model.AuditEvent) error {
	return s.transitionAgentUpdate(id, model.AgentUpdateStaged, model.AgentUpdateApproved, actorID, approvedAt, "", event)
}

func (s *SQLiteStore) RevokeAgentUpdateRelease(id, actorID, reason string, revokedAt time.Time, event model.AuditEvent) error {
	return s.transitionAgentUpdate(id, model.AgentUpdateApproved, model.AgentUpdateRevoked, actorID, revokedAt, reason, event)
}

func (s *SQLiteStore) transitionAgentUpdate(id string, from, to model.AgentUpdateStatus, actorID string, at time.Time, reason string, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	query := `UPDATE agent_update_releases SET status=?,approved_by=?,approved_at=? WHERE id=? AND status=?`
	arguments := []any{to, actorID, formatTime(at), id, from}
	if to == model.AgentUpdateRevoked {
		query = `UPDATE agent_update_releases SET status=?,revoked_by=?,revoked_at=?,revocation_reason=? WHERE id=? AND status=?`
		arguments = []any{to, actorID, formatTime(at), reason, id, from}
	}
	result, err := tx.Exec(query, arguments...)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrNotFound
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

type agentUpdateScanner interface {
	Scan(...any) error
}

func scanAgentUpdateRelease(row agentUpdateScanner) (model.AgentUpdateRelease, error) {
	var release model.AgentUpdateRelease
	var createdAt string
	var approvedAt, revokedAt sql.NullString
	err := row.Scan(&release.ID, &release.Version, &release.OperatingSystem, &release.Architecture,
		&release.ArtifactSHA256, &release.ArtifactSize, &release.SigningKeyID, &release.Status,
		&release.CreatedBy, &createdAt, &release.ApprovedBy, &approvedAt, &release.RevokedBy, &revokedAt, &release.RevocationReason)
	if err != nil {
		return release, err
	}
	release.CreatedAt, _ = parseTime(createdAt)
	release.ApprovedAt = parseNullableTime(approvedAt)
	release.RevokedAt = parseNullableTime(revokedAt)
	return release, nil
}
