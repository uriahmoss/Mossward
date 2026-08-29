package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"mossward/internal/agentmodule"
	"mossward/internal/model"
)

func (s *PostgreSQLStore) SaveAgentModulePublisher(publisher agentmodule.Publisher, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL module publisher update: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO agent_module_publishers(key_id,name,public_key,enabled,created_by,created_at)
		VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(key_id) DO UPDATE SET
		name=EXCLUDED.name,public_key=EXCLUDED.public_key,enabled=EXCLUDED.enabled`, publisher.KeyID, publisher.Name,
		publisher.PublicKey, publisher.Enabled, publisher.CreatedBy, publisher.CreatedAt)
	if err != nil {
		return fmt.Errorf("save PostgreSQL module publisher: %w", err)
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) AgentModulePublisher(keyID string) (agentmodule.Publisher, error) {
	var publisher agentmodule.Publisher
	err := s.db.QueryRow(`SELECT key_id,name,public_key,enabled,created_by,created_at
		FROM agent_module_publishers WHERE key_id=$1`, keyID).Scan(&publisher.KeyID, &publisher.Name, &publisher.PublicKey,
		&publisher.Enabled, &publisher.CreatedBy, &publisher.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return publisher, ErrNotFound
	}
	if err != nil {
		return publisher, fmt.Errorf("read PostgreSQL module publisher: %w", err)
	}
	return publisher, nil
}

func (s *PostgreSQLStore) ListAgentModulePublishers() ([]agentmodule.Publisher, error) {
	rows, err := s.db.Query(`SELECT key_id,name,public_key,enabled,created_by,created_at
		FROM agent_module_publishers ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list PostgreSQL module publishers: %w", err)
	}
	defer rows.Close()
	items := []agentmodule.Publisher{}
	for rows.Next() {
		var item agentmodule.Publisher
		if err := rows.Scan(&item.KeyID, &item.Name, &item.PublicKey, &item.Enabled, &item.CreatedBy, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("read PostgreSQL module publisher: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgreSQLStore) CreateAgentModuleRelease(release agentmodule.Release, event model.AuditEvent) error {
	manifest, err := json.Marshal(release.Manifest)
	if err != nil {
		return fmt.Errorf("encode PostgreSQL module manifest: %w", err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL module release: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO agent_module_releases
		(id,module_id,version,manifest,envelope,status,created_by,created_at)
		VALUES($1,$2,$3,$4::jsonb,$5,$6,$7,$8)`, release.ID, release.Manifest.ID, release.Manifest.Version,
		string(manifest), release.Envelope, release.Status, release.CreatedBy, release.CreatedAt)
	if err != nil {
		return fmt.Errorf("create PostgreSQL module release: %w", err)
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) ListAgentModuleReleases() ([]agentmodule.Release, error) {
	rows, err := s.db.Query(`SELECT id,manifest,status,created_by,created_at,COALESCE(approved_by,''),approved_at,
		COALESCE(revoked_by,''),revoked_at,revocation_reason FROM agent_module_releases ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list PostgreSQL module releases: %w", err)
	}
	defer rows.Close()
	items := []agentmodule.Release{}
	for rows.Next() {
		item, err := scanPostgreSQLModuleRelease(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgreSQLStore) TransitionAgentModuleRelease(
	id string,
	from, to agentmodule.ReleaseStatus,
	actorID, reason string,
	at time.Time,
	event model.AuditEvent,
) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL module release transition: %w", err)
	}
	defer tx.Rollback()
	query := `UPDATE agent_module_releases SET status=$1,approved_by=$2,approved_at=$3 WHERE id=$4 AND status=$5`
	arguments := []any{to, actorID, at, id, from}
	if to == agentmodule.ReleaseRevoked {
		query = `UPDATE agent_module_releases SET status=$1,revoked_by=$2,revoked_at=$3,revocation_reason=$4
			WHERE id=$5 AND status=$6`
		arguments = []any{to, actorID, at, reason, id, from}
	}
	result, err := tx.Exec(query, arguments...)
	if err != nil {
		return fmt.Errorf("transition PostgreSQL module release: %w", err)
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

func (s *PostgreSQLStore) SaveAgentModuleAssignment(assignment agentmodule.Assignment, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL module assignment: %w", err)
	}
	defer tx.Rollback()
	if err := validatePostgreSQLModuleAssignmentTarget(tx, assignment.TargetType, assignment.TargetID); err != nil {
		return err
	}
	var status agentmodule.ReleaseStatus
	err = tx.QueryRow(`SELECT status FROM agent_module_releases WHERE id=$1`, assignment.ReleaseID).Scan(&status)
	if err != nil || status != agentmodule.ReleaseApproved {
		return ErrNotFound
	}
	_, err = tx.Exec(`INSERT INTO agent_module_assignments
		(id,release_id,target_type,target_id,ring_percent,enabled,created_by,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(release_id,target_type,target_id) DO UPDATE SET
		ring_percent=EXCLUDED.ring_percent,enabled=EXCLUDED.enabled`, assignment.ID, assignment.ReleaseID,
		assignment.TargetType, assignment.TargetID, assignment.RingPercent, assignment.Enabled, assignment.CreatedBy,
		assignment.CreatedAt)
	if err != nil {
		return fmt.Errorf("save PostgreSQL module assignment: %w", err)
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) ListAgentModuleAssignments() ([]agentmodule.Assignment, error) {
	rows, err := s.db.Query(`SELECT id,release_id,target_type,target_id,ring_percent,enabled,created_by,created_at
		FROM agent_module_assignments ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list PostgreSQL module assignments: %w", err)
	}
	defer rows.Close()
	items := []agentmodule.Assignment{}
	for rows.Next() {
		var item agentmodule.Assignment
		if err := rows.Scan(&item.ID, &item.ReleaseID, &item.TargetType, &item.TargetID, &item.RingPercent,
			&item.Enabled, &item.CreatedBy, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("read PostgreSQL module assignment: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgreSQLStore) AgentModuleOffers(endpointID, agentVersion, operatingSystem, architecture string) ([]agentmodule.Offer, error) {
	var enabled bool
	if err := s.db.QueryRow(`SELECT enabled FROM agent_module_settings WHERE singleton=TRUE`).Scan(&enabled); err != nil {
		return nil, fmt.Errorf("read PostgreSQL module settings: %w", err)
	}
	if !enabled {
		return []agentmodule.Offer{{Disabled: true}}, nil
	}
	rows, err := s.db.Query(`SELECT a.id,r.id,r.manifest,r.envelope,a.ring_percent FROM agent_module_assignments a
		JOIN agent_module_releases r ON r.id=a.release_id JOIN endpoints e ON e.id=$1
		WHERE a.enabled=TRUE AND r.status='approved' AND
		(a.target_type='endpoint' AND a.target_id=e.id OR a.target_type='group' AND e.asset_id IS NOT NULL AND
		EXISTS(SELECT 1 FROM asset_group_members gm WHERE gm.group_id=a.target_id AND gm.asset_id=e.asset_id))
		ORDER BY CASE a.target_type WHEN 'endpoint' THEN 0 ELSE 1 END,a.created_at DESC`, endpointID)
	if err != nil {
		return nil, fmt.Errorf("list PostgreSQL module offers: %w", err)
	}
	defer rows.Close()
	offers := []agentmodule.Offer{}
	selected := map[string]bool{}
	for rows.Next() {
		var assignmentID, releaseID string
		var manifestJSON, envelope []byte
		var ring int
		if err := rows.Scan(&assignmentID, &releaseID, &manifestJSON, &envelope, &ring); err != nil {
			return nil, fmt.Errorf("read PostgreSQL module offer: %w", err)
		}
		var manifest agentmodule.Manifest
		if json.Unmarshal(manifestJSON, &manifest) != nil || selected[manifest.ID] ||
			!manifest.Compatible(agentVersion, operatingSystem, architecture) || !inModuleRing(endpointID, assignmentID, ring) {
			continue
		}
		selected[manifest.ID] = true
		offers = append(offers, agentmodule.Offer{ReleaseID: releaseID, Envelope: envelope})
	}
	return offers, rows.Err()
}

func (s *PostgreSQLStore) RecordAgentModuleHealth(endpointID string, reports []agentmodule.Health) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL module health update: %w", err)
	}
	defer tx.Rollback()
	for _, report := range reports {
		_, err := tx.Exec(`INSERT INTO agent_module_health
			(endpoint_id,module_id,version,healthy,crash_count,error,observed_at) VALUES($1,$2,$3,$4,$5,$6,$7)
			ON CONFLICT(endpoint_id,module_id) DO UPDATE SET version=EXCLUDED.version,healthy=EXCLUDED.healthy,
			crash_count=EXCLUDED.crash_count,error=EXCLUDED.error,observed_at=EXCLUDED.observed_at`, endpointID,
			report.ModuleID, report.Version, report.Healthy, report.CrashCount, report.Error, report.ObservedAt)
		if err != nil {
			return fmt.Errorf("record PostgreSQL module health: %w", err)
		}
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) SetAgentModulesEnabled(enabled bool, event model.AuditEvent) error {
	return s.updatePostgreSQLModule(`UPDATE agent_module_settings SET enabled=$1 WHERE singleton=TRUE`,
		[]any{enabled}, event, "global enablement")
}

func (s *PostgreSQLStore) LinkEndpointAsset(endpointID, assetID string, event model.AuditEvent) error {
	return s.updatePostgreSQLModule(`UPDATE endpoints SET asset_id=$1 WHERE id=$2 AND status='active'`,
		[]any{assetID, endpointID}, event, "endpoint asset link")
}

func scanPostgreSQLModuleRelease(scanner interface{ Scan(...any) error }) (agentmodule.Release, error) {
	var item agentmodule.Release
	var manifest []byte
	var approvedAt, revokedAt sql.NullTime
	err := scanner.Scan(&item.ID, &manifest, &item.Status, &item.CreatedBy, &item.CreatedAt, &item.ApprovedBy,
		&approvedAt, &item.RevokedBy, &revokedAt, &item.RevocationReason)
	if err != nil {
		return item, err
	}
	if err := json.Unmarshal(manifest, &item.Manifest); err != nil {
		return item, fmt.Errorf("decode PostgreSQL module manifest: %w", err)
	}
	item.ApprovedAt = nullablePostgreSQLTime(approvedAt)
	item.RevokedAt = nullablePostgreSQLTime(revokedAt)
	return item, nil
}

func validatePostgreSQLModuleAssignmentTarget(tx *sql.Tx, targetType, targetID string) error {
	query := `SELECT 1 FROM endpoints WHERE id=$1 AND status='active'`
	if targetType == "group" {
		query = `SELECT 1 FROM asset_groups WHERE id=$1`
	}
	if targetType != "endpoint" && targetType != "group" {
		return errors.New("module assignment target type is invalid")
	}
	var exists int
	if err := tx.QueryRow(query, targetID).Scan(&exists); err != nil {
		return ErrNotFound
	}
	return nil
}

func (s *PostgreSQLStore) updatePostgreSQLModule(query string, arguments []any, event model.AuditEvent, operation string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL module %s update: %w", operation, err)
	}
	defer tx.Rollback()
	result, err := tx.Exec(query, arguments...)
	if err != nil {
		return fmt.Errorf("update PostgreSQL module %s: %w", operation, err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("count PostgreSQL module %s update: %w", operation, err)
	}
	if changed != 1 {
		return ErrNotFound
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}
