package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"mossward/internal/model"
)

func (s *PostgreSQLStore) CreateAgentUpdateRelease(release model.AgentUpdateRelease, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL agent-update release: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO agent_update_releases(id,version,operating_system,architecture,artifact_sha256,
		artifact_size,signing_key_id,envelope,status,created_by,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		release.ID, release.Version, release.OperatingSystem, release.Architecture, release.ArtifactSHA256,
		release.ArtifactSize, release.SigningKeyID, release.Envelope, release.Status, release.CreatedBy, release.CreatedAt)
	if err != nil {
		return fmt.Errorf("create PostgreSQL agent-update release: %w", err)
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) ListAgentUpdateReleases() ([]model.AgentUpdateRelease, error) {
	rows, err := s.db.Query(`SELECT id,version,operating_system,architecture,artifact_sha256,artifact_size,
		signing_key_id,status,created_by,created_at,COALESCE(approved_by,''),approved_at,
		COALESCE(revoked_by,''),revoked_at,revocation_reason FROM agent_update_releases ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list PostgreSQL agent-update releases: %w", err)
	}
	defer rows.Close()
	releases := []model.AgentUpdateRelease{}
	for rows.Next() {
		release, err := scanPostgreSQLAgentUpdateRelease(rows)
		if err != nil {
			return nil, err
		}
		releases = append(releases, release)
	}
	return releases, rows.Err()
}

func scanPostgreSQLAgentUpdateRelease(scanner interface{ Scan(...any) error }) (model.AgentUpdateRelease, error) {
	var release model.AgentUpdateRelease
	var approvedAt, revokedAt sql.NullTime
	err := scanner.Scan(&release.ID, &release.Version, &release.OperatingSystem, &release.Architecture,
		&release.ArtifactSHA256, &release.ArtifactSize, &release.SigningKeyID, &release.Status, &release.CreatedBy,
		&release.CreatedAt, &release.ApprovedBy, &approvedAt, &release.RevokedBy, &revokedAt, &release.RevocationReason)
	if err != nil {
		return release, err
	}
	release.ApprovedAt = nullablePostgreSQLTime(approvedAt)
	release.RevokedAt = nullablePostgreSQLTime(revokedAt)
	return release, nil
}

func (s *PostgreSQLStore) AgentUpdateEnvelope(id string) ([]byte, error) {
	var envelope []byte
	err := s.db.QueryRow(`SELECT envelope FROM agent_update_releases WHERE id=$1 AND status='approved'`, id).Scan(&envelope)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load PostgreSQL agent-update envelope: %w", err)
	}
	return envelope, nil
}

func (s *PostgreSQLStore) ApproveAgentUpdateRelease(id, actorID string, approvedAt time.Time, event model.AuditEvent) error {
	return s.transitionPostgreSQLAgentUpdate(id, model.AgentUpdateStaged, model.AgentUpdateApproved, actorID, approvedAt, "", event)
}

func (s *PostgreSQLStore) RevokeAgentUpdateRelease(id, actorID, reason string, revokedAt time.Time, event model.AuditEvent) error {
	return s.transitionPostgreSQLAgentUpdate(id, model.AgentUpdateApproved, model.AgentUpdateRevoked, actorID, revokedAt, reason, event)
}

func (s *PostgreSQLStore) transitionPostgreSQLAgentUpdate(id string, from, to model.AgentUpdateStatus, actorID string,
	at time.Time, reason string, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL agent-update transition: %w", err)
	}
	defer tx.Rollback()
	query := `UPDATE agent_update_releases SET status=$1,approved_by=$2,approved_at=$3 WHERE id=$4 AND status=$5`
	arguments := []any{to, actorID, at, id, from}
	if to == model.AgentUpdateRevoked {
		query = `UPDATE agent_update_releases SET status=$1,revoked_by=$2,revoked_at=$3,revocation_reason=$4 WHERE id=$5 AND status=$6`
		arguments = []any{to, actorID, at, reason, id, from}
	}
	result, err := tx.Exec(query, arguments...)
	if err != nil {
		return fmt.Errorf("transition PostgreSQL agent-update release: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrNotFound
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) AssignAgentUpdate(endpointID, releaseID, actorID string, assignedAt time.Time, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL agent-update assignment: %w", err)
	}
	defer tx.Rollback()
	var endpointOS, endpointArchitecture string
	err = tx.QueryRow(`SELECT operating_system,architecture FROM endpoints WHERE id=$1 AND status='active' FOR UPDATE`, endpointID).
		Scan(&endpointOS, &endpointArchitecture)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("load PostgreSQL update endpoint: %w", err)
	}
	if endpointOS == "" || endpointArchitecture == "" {
		return errors.New("endpoint must check in before an update can be assigned")
	}
	var releaseOS, releaseArchitecture string
	err = tx.QueryRow(`SELECT operating_system,architecture FROM agent_update_releases
		WHERE id=$1 AND status='approved' FOR SHARE`, releaseID).Scan(&releaseOS, &releaseArchitecture)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("load PostgreSQL update release: %w", err)
	}
	if endpointOS != releaseOS || endpointArchitecture != releaseArchitecture {
		return errors.New("endpoint and update release platforms do not match")
	}
	_, err = tx.Exec(`INSERT INTO agent_update_assignments(endpoint_id,release_id,status,assigned_by,assigned_at)
		VALUES($1,$2,'assigned',$3,$4) ON CONFLICT(endpoint_id) DO UPDATE SET release_id=EXCLUDED.release_id,
		status='assigned',assigned_by=EXCLUDED.assigned_by,assigned_at=EXCLUDED.assigned_at,offered_at=NULL,installed_at=NULL`,
		endpointID, releaseID, actorID, assignedAt)
	if err != nil {
		return fmt.Errorf("assign PostgreSQL endpoint-agent update: %w", err)
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) AgentUpdateOffer(endpointID string, offeredAt time.Time) ([]byte, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("begin PostgreSQL agent-update offer: %w", err)
	}
	defer tx.Rollback()
	var envelope []byte
	err = tx.QueryRow(`SELECT r.envelope FROM agent_update_assignments a JOIN agent_update_releases r ON r.id=a.release_id
		JOIN endpoints e ON e.id=a.endpoint_id WHERE a.endpoint_id=$1 AND a.status IN ('assigned','offered')
		AND r.status='approved' AND e.status='active' AND r.operating_system=e.operating_system
		AND r.architecture=e.architecture FOR UPDATE OF a,r`, endpointID).Scan(&envelope)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load PostgreSQL agent-update offer: %w", err)
	}
	if _, err := tx.Exec(`UPDATE agent_update_assignments SET status='offered',offered_at=COALESCE(offered_at,$1)
		WHERE endpoint_id=$2`, offeredAt, endpointID); err != nil {
		return nil, fmt.Errorf("mark PostgreSQL agent update offered: %w", err)
	}
	return envelope, tx.Commit()
}
