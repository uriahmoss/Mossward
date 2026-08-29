package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"mossward/internal/model"
	"mossward/internal/relayheartbeat"
	"mossward/internal/relaywindow"
)

func (s *PostgreSQLStore) UpsertRelayUploadWindow(window model.RelayUploadWindow, event model.AuditEvent) error {
	if err := relaywindow.Validate(window); err != nil {
		return err
	}
	days, err := json.Marshal(window.Days)
	if err != nil {
		return fmt.Errorf("encode PostgreSQL relay upload-window days: %w", err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL relay upload-window update: %w", err)
	}
	defer tx.Rollback()
	if !postgreSQLMaintenanceTargetExists(tx, window.TargetType, window.TargetID) {
		return ErrNotFound
	}
	_, err = tx.Exec(`INSERT INTO relay_upload_windows
		(id,name,target_type,target_id,timezone,days_json,start_minute,end_minute,enabled,reason,created_by,created_at,updated_by,updated_at)
		VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT(id) DO UPDATE SET
		name=EXCLUDED.name,target_type=EXCLUDED.target_type,target_id=EXCLUDED.target_id,timezone=EXCLUDED.timezone,
		days_json=EXCLUDED.days_json,start_minute=EXCLUDED.start_minute,end_minute=EXCLUDED.end_minute,
		enabled=EXCLUDED.enabled,reason=EXCLUDED.reason,updated_by=EXCLUDED.updated_by,updated_at=EXCLUDED.updated_at`,
		window.ID, window.Name, window.TargetType, window.TargetID, window.Timezone, string(days), window.StartMinute,
		window.EndMinute, window.Enabled, window.Reason, window.CreatedBy, window.CreatedAt, window.UpdatedBy, window.UpdatedAt)
	if err != nil {
		return fmt.Errorf("save PostgreSQL relay upload window: %w", err)
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) ListRelayUploadWindows() ([]model.RelayUploadWindow, error) {
	return s.listPostgreSQLRelayUploadWindows(`SELECT id,name,target_type,target_id,timezone,days_json,start_minute,
		end_minute,enabled,reason,created_by,created_at,updated_by,updated_at FROM relay_upload_windows ORDER BY name,id`)
}

func (s *PostgreSQLStore) RelayUploadWindowsForEndpoint(endpointID string) ([]model.RelayUploadWindow, error) {
	query := `SELECT w.id,w.name,w.target_type,w.target_id,w.timezone,w.days_json,w.start_minute,w.end_minute,w.enabled,
		w.reason,w.created_by,w.created_at,w.updated_by,w.updated_at FROM relay_upload_windows w
		WHERE (w.target_type='endpoint' AND w.target_id=$1) OR (w.target_type='group' AND EXISTS(
		SELECT 1 FROM endpoints e JOIN asset_group_members m ON m.asset_id=e.asset_id
		WHERE e.id=$1 AND m.group_id=w.target_id)) ORDER BY w.name,w.id`
	return s.listPostgreSQLRelayUploadWindows(query, endpointID)
}

func (s *PostgreSQLStore) UpsertDelayedHeartbeatPolicy(policy model.DelayedHeartbeatPolicy, event model.AuditEvent) error {
	if err := relayheartbeat.Validate(policy); err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL delayed-heartbeat policy update: %w", err)
	}
	defer tx.Rollback()
	if !postgreSQLMaintenanceTargetExists(tx, policy.TargetType, policy.TargetID) {
		return ErrNotFound
	}
	_, err = tx.Exec(`INSERT INTO delayed_heartbeat_policies
		(target_type,target_id,allow_delayed_heartbeats,post_window_grace_minutes,reason,updated_by,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(target_type,target_id) DO UPDATE SET
		allow_delayed_heartbeats=EXCLUDED.allow_delayed_heartbeats,
		post_window_grace_minutes=EXCLUDED.post_window_grace_minutes,reason=EXCLUDED.reason,
		updated_by=EXCLUDED.updated_by,updated_at=EXCLUDED.updated_at`, policy.TargetType, policy.TargetID,
		policy.AllowDelayedHeartbeats, policy.PostWindowGraceMinutes, policy.Reason, policy.UpdatedBy, policy.UpdatedAt)
	if err != nil {
		return fmt.Errorf("save PostgreSQL delayed-heartbeat policy: %w", err)
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) DeleteDelayedHeartbeatPolicy(targetType model.MaintenanceTargetType, targetID string, event model.AuditEvent) error {
	if targetType != model.MaintenanceTargetEndpoint && targetType != model.MaintenanceTargetGroup {
		return errors.New("delayed-heartbeat policy target is invalid")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL delayed-heartbeat policy deletion: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.Exec(`DELETE FROM delayed_heartbeat_policies WHERE target_type=$1 AND target_id=$2`, targetType, targetID)
	if err != nil {
		return fmt.Errorf("delete PostgreSQL delayed-heartbeat policy: %w", err)
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

func (s *PostgreSQLStore) ListDelayedHeartbeatPolicies() ([]model.DelayedHeartbeatPolicy, error) {
	rows, err := s.db.Query(`SELECT target_type,target_id,allow_delayed_heartbeats,post_window_grace_minutes,
		reason,updated_by,updated_at FROM delayed_heartbeat_policies ORDER BY target_type,target_id`)
	if err != nil {
		return nil, fmt.Errorf("list PostgreSQL delayed-heartbeat policies: %w", err)
	}
	defer rows.Close()
	return scanPostgreSQLDelayedHeartbeatPolicies(rows)
}

func (s *PostgreSQLStore) ResolveDelayedHeartbeatPolicy(endpointID string) (model.ResolvedDelayedHeartbeatPolicy, error) {
	var exists int
	err := s.db.QueryRow(`SELECT 1 FROM endpoints WHERE id=$1`, endpointID).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return model.ResolvedDelayedHeartbeatPolicy{}, ErrNotFound
	}
	if err != nil {
		return model.ResolvedDelayedHeartbeatPolicy{}, fmt.Errorf("find PostgreSQL delayed-heartbeat endpoint: %w", err)
	}
	rows, err := s.db.Query(`SELECT p.target_type,p.target_id,p.allow_delayed_heartbeats,p.post_window_grace_minutes,
		p.reason,p.updated_by,p.updated_at FROM delayed_heartbeat_policies p WHERE
		(p.target_type='endpoint' AND p.target_id=$1) OR (p.target_type='group' AND EXISTS(
		SELECT 1 FROM endpoints e JOIN asset_group_members m ON m.asset_id=e.asset_id
		WHERE e.id=$1 AND m.group_id=p.target_id))`, endpointID)
	if err != nil {
		return model.ResolvedDelayedHeartbeatPolicy{}, fmt.Errorf("resolve PostgreSQL delayed-heartbeat policies: %w", err)
	}
	defer rows.Close()
	policies, err := scanPostgreSQLDelayedHeartbeatPolicies(rows)
	if err != nil {
		return model.ResolvedDelayedHeartbeatPolicy{}, err
	}
	return relayheartbeat.Resolve(endpointID, policies), nil
}

func (s *PostgreSQLStore) listPostgreSQLRelayUploadWindows(query string, arguments ...any) ([]model.RelayUploadWindow, error) {
	rows, err := s.db.Query(query, arguments...)
	if err != nil {
		return nil, fmt.Errorf("list PostgreSQL relay upload windows: %w", err)
	}
	defer rows.Close()
	windows := []model.RelayUploadWindow{}
	for rows.Next() {
		var window model.RelayUploadWindow
		var days []byte
		if err := rows.Scan(&window.ID, &window.Name, &window.TargetType, &window.TargetID, &window.Timezone, &days,
			&window.StartMinute, &window.EndMinute, &window.Enabled, &window.Reason, &window.CreatedBy, &window.CreatedAt,
			&window.UpdatedBy, &window.UpdatedAt); err != nil {
			return nil, fmt.Errorf("read PostgreSQL relay upload window: %w", err)
		}
		if err := json.Unmarshal(days, &window.Days); err != nil {
			return nil, fmt.Errorf("decode PostgreSQL relay upload-window days: %w", err)
		}
		windows = append(windows, window)
	}
	return windows, rows.Err()
}

func scanPostgreSQLDelayedHeartbeatPolicies(rows *sql.Rows) ([]model.DelayedHeartbeatPolicy, error) {
	policies := []model.DelayedHeartbeatPolicy{}
	for rows.Next() {
		var policy model.DelayedHeartbeatPolicy
		if err := rows.Scan(&policy.TargetType, &policy.TargetID, &policy.AllowDelayedHeartbeats,
			&policy.PostWindowGraceMinutes, &policy.Reason, &policy.UpdatedBy, &policy.UpdatedAt); err != nil {
			return nil, fmt.Errorf("read PostgreSQL delayed-heartbeat policy: %w", err)
		}
		policies = append(policies, policy)
	}
	return policies, rows.Err()
}

func postgreSQLMaintenanceTargetExists(tx *sql.Tx, targetType model.MaintenanceTargetType, targetID string) bool {
	query := `SELECT 1 FROM endpoints WHERE id=$1`
	if targetType == model.MaintenanceTargetGroup {
		query = `SELECT 1 FROM asset_groups WHERE id=$1`
	}
	if targetType != model.MaintenanceTargetEndpoint && targetType != model.MaintenanceTargetGroup {
		return false
	}
	var exists int
	return tx.QueryRow(query, targetID).Scan(&exists) == nil
}
