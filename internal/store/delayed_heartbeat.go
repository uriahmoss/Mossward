package store

import (
	"database/sql"
	"errors"

	"mossward/internal/model"
	"mossward/internal/relayheartbeat"
)

func (s *SQLiteStore) UpsertDelayedHeartbeatPolicy(policy model.DelayedHeartbeatPolicy, event model.AuditEvent) error {
	if err := relayheartbeat.Validate(policy); err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if !maintenanceTargetExists(tx, policy.TargetType, policy.TargetID) {
		return ErrNotFound
	}
	_, err = tx.Exec(`INSERT INTO delayed_heartbeat_policies(target_type,target_id,allow_delayed_heartbeats,reason,updated_by,updated_at) VALUES(?,?,?,?,?,?)
		ON CONFLICT(target_type,target_id) DO UPDATE SET allow_delayed_heartbeats=excluded.allow_delayed_heartbeats,reason=excluded.reason,
		updated_by=excluded.updated_by,updated_at=excluded.updated_at`, policy.TargetType, policy.TargetID, policy.AllowDelayedHeartbeats,
		policy.Reason, policy.UpdatedBy, formatTime(policy.UpdatedAt))
	if err != nil {
		return err
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) DeleteDelayedHeartbeatPolicy(targetType model.MaintenanceTargetType, targetID string, event model.AuditEvent) error {
	if targetType != model.MaintenanceTargetEndpoint && targetType != model.MaintenanceTargetGroup {
		return errors.New("delayed-heartbeat policy target is invalid")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`DELETE FROM delayed_heartbeat_policies WHERE target_type=? AND target_id=?`, targetType, targetID)
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

func (s *SQLiteStore) ListDelayedHeartbeatPolicies() ([]model.DelayedHeartbeatPolicy, error) {
	rows, err := s.db.Query(`SELECT target_type,target_id,allow_delayed_heartbeats,reason,updated_by,updated_at FROM delayed_heartbeat_policies ORDER BY target_type,target_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanDelayedHeartbeatPolicies(rows)
}

func (s *SQLiteStore) ResolveDelayedHeartbeatPolicy(endpointID string) (model.ResolvedDelayedHeartbeatPolicy, error) {
	var exists int
	if err := s.db.QueryRow(`SELECT 1 FROM endpoints WHERE id=?`, endpointID).Scan(&exists); errors.Is(err, sql.ErrNoRows) {
		return model.ResolvedDelayedHeartbeatPolicy{}, ErrNotFound
	} else if err != nil {
		return model.ResolvedDelayedHeartbeatPolicy{}, err
	}
	rows, err := s.db.Query(`SELECT p.target_type,p.target_id,p.allow_delayed_heartbeats,p.reason,p.updated_by,p.updated_at FROM delayed_heartbeat_policies p
		WHERE (p.target_type='endpoint' AND p.target_id=?) OR (p.target_type='group' AND EXISTS (
			SELECT 1 FROM endpoints e JOIN asset_group_members m ON m.asset_id=e.asset_id WHERE e.id=? AND m.group_id=p.target_id))`, endpointID, endpointID)
	if err != nil {
		return model.ResolvedDelayedHeartbeatPolicy{}, err
	}
	defer rows.Close()
	policies, err := scanDelayedHeartbeatPolicies(rows)
	if err != nil {
		return model.ResolvedDelayedHeartbeatPolicy{}, err
	}
	return relayheartbeat.Resolve(endpointID, policies), nil
}

func scanDelayedHeartbeatPolicies(rows *sql.Rows) ([]model.DelayedHeartbeatPolicy, error) {
	policies := []model.DelayedHeartbeatPolicy{}
	for rows.Next() {
		var policy model.DelayedHeartbeatPolicy
		var updatedAt string
		if err := rows.Scan(&policy.TargetType, &policy.TargetID, &policy.AllowDelayedHeartbeats, &policy.Reason, &policy.UpdatedBy, &updatedAt); err != nil {
			return nil, err
		}
		parsedAt, err := parseTime(updatedAt)
		if err != nil {
			return nil, err
		}
		policy.UpdatedAt = parsedAt
		policies = append(policies, policy)
	}
	return policies, rows.Err()
}
