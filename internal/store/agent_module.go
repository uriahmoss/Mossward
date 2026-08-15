package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"time"

	"mossward/internal/agentmodule"
	"mossward/internal/model"
)

func (s *SQLiteStore) SaveAgentModulePublisher(publisher agentmodule.Publisher, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO agent_module_publishers(key_id,name,public_key,enabled,created_by,created_at) VALUES(?,?,?,?,?,?)
		ON CONFLICT(key_id) DO UPDATE SET name=excluded.name,public_key=excluded.public_key,enabled=excluded.enabled`, publisher.KeyID,
		publisher.Name, publisher.PublicKey, publisher.Enabled, publisher.CreatedBy, formatTime(publisher.CreatedAt))
	if err != nil {
		return fmt.Errorf("save module publisher: %w", err)
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) AgentModulePublisher(keyID string) (agentmodule.Publisher, error) {
	var publisher agentmodule.Publisher
	var createdAt string
	err := s.db.QueryRow(`SELECT key_id,name,public_key,enabled,created_by,created_at FROM agent_module_publishers WHERE key_id=?`, keyID).
		Scan(&publisher.KeyID, &publisher.Name, &publisher.PublicKey, &publisher.Enabled, &publisher.CreatedBy, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return publisher, ErrNotFound
	}
	publisher.CreatedAt, _ = parseTime(createdAt)
	return publisher, err
}

func (s *SQLiteStore) ListAgentModulePublishers() ([]agentmodule.Publisher, error) {
	rows, err := s.db.Query(`SELECT key_id,name,public_key,enabled,created_by,created_at FROM agent_module_publishers ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []agentmodule.Publisher{}
	for rows.Next() {
		var item agentmodule.Publisher
		var createdAt string
		if err := rows.Scan(&item.KeyID, &item.Name, &item.PublicKey, &item.Enabled, &item.CreatedBy, &createdAt); err != nil {
			return nil, err
		}
		item.CreatedAt, _ = parseTime(createdAt)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *SQLiteStore) CreateAgentModuleRelease(release agentmodule.Release, event model.AuditEvent) error {
	manifest, err := json.Marshal(release.Manifest)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO agent_module_releases(id,module_id,version,manifest,envelope,status,created_by,created_at) VALUES(?,?,?,?,?,?,?,?)`,
		release.ID, release.Manifest.ID, release.Manifest.Version, manifest, release.Envelope, release.Status, release.CreatedBy, formatTime(release.CreatedAt))
	if err != nil {
		return fmt.Errorf("create module release: %w", err)
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) ListAgentModuleReleases() ([]agentmodule.Release, error) {
	rows, err := s.db.Query(`SELECT id,manifest,status,created_by,created_at,COALESCE(approved_by,''),approved_at,COALESCE(revoked_by,''),revoked_at,revocation_reason FROM agent_module_releases ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []agentmodule.Release{}
	for rows.Next() {
		item, err := scanModuleRelease(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func scanModuleRelease(scanner interface{ Scan(...any) error }) (agentmodule.Release, error) {
	var item agentmodule.Release
	var manifest, createdAt string
	var approvedAt, revokedAt sql.NullString
	if err := scanner.Scan(&item.ID, &manifest, &item.Status, &item.CreatedBy, &createdAt, &item.ApprovedBy, &approvedAt, &item.RevokedBy, &revokedAt, &item.RevocationReason); err != nil {
		return item, err
	}
	if err := json.Unmarshal([]byte(manifest), &item.Manifest); err != nil {
		return item, err
	}
	item.CreatedAt, _ = parseTime(createdAt)
	item.ApprovedAt, item.RevokedAt = parseNullableTime(approvedAt), parseNullableTime(revokedAt)
	return item, nil
}

func (s *SQLiteStore) TransitionAgentModuleRelease(id string, from, to agentmodule.ReleaseStatus, actorID, reason string, at time.Time, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	query := `UPDATE agent_module_releases SET status=?,approved_by=?,approved_at=? WHERE id=? AND status=?`
	args := []any{to, actorID, formatTime(at), id, from}
	if to == agentmodule.ReleaseRevoked {
		query, args = `UPDATE agent_module_releases SET status=?,revoked_by=?,revoked_at=?,revocation_reason=? WHERE id=? AND status=?`, []any{to, actorID, formatTime(at), reason, id, from}
	}
	result, err := tx.Exec(query, args...)
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

func (s *SQLiteStore) SaveAgentModuleAssignment(assignment agentmodule.Assignment, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := validateModuleAssignmentTarget(tx, assignment.TargetType, assignment.TargetID); err != nil {
		return err
	}
	var status string
	if err := tx.QueryRow(`SELECT status FROM agent_module_releases WHERE id=?`, assignment.ReleaseID).Scan(&status); err != nil || status != string(agentmodule.ReleaseApproved) {
		return ErrNotFound
	}
	_, err = tx.Exec(`INSERT INTO agent_module_assignments(id,release_id,target_type,target_id,ring_percent,enabled,created_by,created_at) VALUES(?,?,?,?,?,?,?,?)
		ON CONFLICT(release_id,target_type,target_id) DO UPDATE SET ring_percent=excluded.ring_percent,enabled=excluded.enabled`, assignment.ID,
		assignment.ReleaseID, assignment.TargetType, assignment.TargetID, assignment.RingPercent, assignment.Enabled, assignment.CreatedBy, formatTime(assignment.CreatedAt))
	if err != nil {
		return fmt.Errorf("save module assignment: %w", err)
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func validateModuleAssignmentTarget(tx *sql.Tx, targetType, targetID string) error {
	query := `SELECT 1 FROM endpoints WHERE id=? AND status='active'`
	if targetType == "group" {
		query = `SELECT 1 FROM asset_groups WHERE id=?`
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

func (s *SQLiteStore) ListAgentModuleAssignments() ([]agentmodule.Assignment, error) {
	rows, err := s.db.Query(`SELECT id,release_id,target_type,target_id,ring_percent,enabled,created_by,created_at FROM agent_module_assignments ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []agentmodule.Assignment{}
	for rows.Next() {
		var item agentmodule.Assignment
		var createdAt string
		if err := rows.Scan(&item.ID, &item.ReleaseID, &item.TargetType, &item.TargetID, &item.RingPercent, &item.Enabled, &item.CreatedBy, &createdAt); err != nil {
			return nil, err
		}
		item.CreatedAt, _ = parseTime(createdAt)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *SQLiteStore) AgentModuleOffers(endpointID, agentVersion, operatingSystem, architecture string) ([]agentmodule.Offer, error) {
	var enabled bool
	if err := s.db.QueryRow(`SELECT enabled FROM agent_module_settings WHERE singleton=1`).Scan(&enabled); err != nil {
		return nil, err
	}
	if !enabled {
		return []agentmodule.Offer{{Disabled: true}}, nil
	}
	rows, err := s.db.Query(`SELECT a.id,r.id,r.manifest,r.envelope,a.ring_percent FROM agent_module_assignments a
		JOIN agent_module_releases r ON r.id=a.release_id JOIN endpoints e ON e.id=?
		WHERE a.enabled=1 AND r.status='approved' AND (a.target_type='endpoint' AND a.target_id=e.id OR
		a.target_type='group' AND e.asset_id IS NOT NULL AND EXISTS(SELECT 1 FROM asset_group_members gm WHERE gm.group_id=a.target_id AND gm.asset_id=e.asset_id))
		ORDER BY CASE a.target_type WHEN 'endpoint' THEN 0 ELSE 1 END,a.created_at DESC`, endpointID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	offers, selected := []agentmodule.Offer{}, map[string]bool{}
	for rows.Next() {
		var assignmentID, releaseID, manifestJSON string
		var envelope []byte
		var ring int
		if err := rows.Scan(&assignmentID, &releaseID, &manifestJSON, &envelope, &ring); err != nil {
			return nil, err
		}
		var manifest agentmodule.Manifest
		if json.Unmarshal([]byte(manifestJSON), &manifest) != nil || selected[manifest.ID] || !manifest.Compatible(agentVersion, operatingSystem, architecture) || !inModuleRing(endpointID, assignmentID, ring) {
			continue
		}
		selected[manifest.ID] = true
		offers = append(offers, agentmodule.Offer{ReleaseID: releaseID, Envelope: envelope})
	}
	return offers, rows.Err()
}

func inModuleRing(endpointID, assignmentID string, percent int) bool {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(endpointID + "\x00" + assignmentID))
	return int(hash.Sum32()%100) < percent
}

func (s *SQLiteStore) RecordAgentModuleHealth(endpointID string, reports []agentmodule.Health) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, report := range reports {
		_, err := tx.Exec(`INSERT INTO agent_module_health(endpoint_id,module_id,version,healthy,crash_count,error,observed_at) VALUES(?,?,?,?,?,?,?)
			ON CONFLICT(endpoint_id,module_id) DO UPDATE SET version=excluded.version,healthy=excluded.healthy,crash_count=excluded.crash_count,error=excluded.error,observed_at=excluded.observed_at`,
			endpointID, report.ModuleID, report.Version, report.Healthy, report.CrashCount, report.Error, formatTime(report.ObservedAt))
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLiteStore) SetAgentModulesEnabled(enabled bool, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE agent_module_settings SET enabled=? WHERE singleton=1`, enabled); err != nil {
		return err
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) LinkEndpointAsset(endpointID, assetID string, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE endpoints SET asset_id=? WHERE id=? AND status='active'`, assetID, endpointID)
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
