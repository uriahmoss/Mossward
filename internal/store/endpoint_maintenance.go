package store

import (
	"database/sql"
	"errors"
	"time"

	"mossward/internal/model"
)

func (s *SQLiteStore) CreateEndpointMaintenanceWindow(window model.EndpointMaintenanceWindow, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if !maintenanceTargetExists(tx, window.TargetType, window.TargetID) {
		return ErrNotFound
	}
	_, err = tx.Exec(`INSERT INTO endpoint_maintenance_windows(id,name,target_type,target_id,starts_at,ends_at,reason,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)`,
		window.ID, window.Name, window.TargetType, window.TargetID, formatTime(window.StartsAt), formatTime(window.EndsAt), window.Reason, window.CreatedBy, formatTime(window.CreatedAt))
	if err != nil {
		return err
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func maintenanceTargetExists(tx *sql.Tx, targetType model.MaintenanceTargetType, targetID string) bool {
	query := `SELECT 1 FROM endpoints WHERE id=?`
	if targetType == model.MaintenanceTargetGroup {
		query = `SELECT 1 FROM asset_groups WHERE id=?`
	}
	var exists int
	return tx.QueryRow(query, targetID).Scan(&exists) == nil
}

func (s *SQLiteStore) CancelEndpointMaintenanceWindow(id, actorID string, now time.Time, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE endpoint_maintenance_windows SET cancelled_by=?,cancelled_at=? WHERE id=? AND cancelled_at IS NULL`, actorID, formatTime(now), id)
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

func (s *SQLiteStore) ListEndpointMaintenanceWindows() ([]model.EndpointMaintenanceWindow, error) {
	rows, err := s.db.Query(`SELECT id,name,target_type,target_id,starts_at,ends_at,reason,created_by,created_at,cancelled_by,cancelled_at FROM endpoint_maintenance_windows ORDER BY starts_at DESC,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	windows := []model.EndpointMaintenanceWindow{}
	for rows.Next() {
		var window model.EndpointMaintenanceWindow
		var startsAt, endsAt, createdAt string
		var cancelledAt sql.NullString
		if err := rows.Scan(&window.ID, &window.Name, &window.TargetType, &window.TargetID, &startsAt, &endsAt, &window.Reason, &window.CreatedBy, &createdAt, &window.CancelledBy, &cancelledAt); err != nil {
			return nil, err
		}
		window.StartsAt, _ = parseTime(startsAt)
		window.EndsAt, _ = parseTime(endsAt)
		window.CreatedAt, _ = parseTime(createdAt)
		if cancelledAt.Valid {
			value, _ := parseTime(cancelledAt.String)
			window.CancelledAt = &value
		}
		windows = append(windows, window)
	}
	return windows, rows.Err()
}

func (s *SQLiteStore) EndpointInMaintenance(endpointID string, now time.Time) (bool, error) {
	var exists int
	err := s.db.QueryRow(`SELECT 1 FROM endpoint_maintenance_windows w WHERE w.cancelled_at IS NULL AND w.starts_at<=? AND w.ends_at>?
		AND ((w.target_type='endpoint' AND w.target_id=?) OR (w.target_type='group' AND EXISTS (
			SELECT 1 FROM endpoints e JOIN asset_group_members m ON m.asset_id=e.asset_id WHERE e.id=? AND m.group_id=w.target_id))) LIMIT 1`,
		formatTime(now), formatTime(now), endpointID, endpointID).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}
