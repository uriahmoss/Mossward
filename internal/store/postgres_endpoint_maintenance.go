package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"mossward/internal/model"
)

func (s *PostgreSQLStore) CreateEndpointMaintenanceWindow(window model.EndpointMaintenanceWindow, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL endpoint maintenance-window creation: %w", err)
	}
	defer tx.Rollback()
	if !postgreSQLMaintenanceTargetExists(tx, window.TargetType, window.TargetID) {
		return ErrNotFound
	}
	_, err = tx.Exec(`INSERT INTO endpoint_maintenance_windows
		(id,name,target_type,target_id,starts_at,ends_at,reason,created_by,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, window.ID, window.Name, window.TargetType, window.TargetID,
		window.StartsAt, window.EndsAt, window.Reason, window.CreatedBy, window.CreatedAt)
	if err != nil {
		return fmt.Errorf("create PostgreSQL endpoint maintenance window: %w", err)
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) CancelEndpointMaintenanceWindow(id, actorID string, now time.Time, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL endpoint maintenance-window cancellation: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE endpoint_maintenance_windows SET cancelled_by=$1,cancelled_at=$2
		WHERE id=$3 AND cancelled_at IS NULL`, actorID, now, id)
	if err != nil {
		return fmt.Errorf("cancel PostgreSQL endpoint maintenance window: %w", err)
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

func (s *PostgreSQLStore) ListEndpointMaintenanceWindows() ([]model.EndpointMaintenanceWindow, error) {
	rows, err := s.db.Query(`SELECT id,name,target_type,target_id,starts_at,ends_at,reason,created_by,created_at,
		cancelled_by,cancelled_at FROM endpoint_maintenance_windows ORDER BY starts_at DESC,id`)
	if err != nil {
		return nil, fmt.Errorf("list PostgreSQL endpoint maintenance windows: %w", err)
	}
	defer rows.Close()
	windows := []model.EndpointMaintenanceWindow{}
	for rows.Next() {
		var window model.EndpointMaintenanceWindow
		var cancelledAt sql.NullTime
		if err := rows.Scan(&window.ID, &window.Name, &window.TargetType, &window.TargetID, &window.StartsAt,
			&window.EndsAt, &window.Reason, &window.CreatedBy, &window.CreatedAt, &window.CancelledBy,
			&cancelledAt); err != nil {
			return nil, fmt.Errorf("read PostgreSQL endpoint maintenance window: %w", err)
		}
		window.CancelledAt = nullablePostgreSQLTime(cancelledAt)
		windows = append(windows, window)
	}
	return windows, rows.Err()
}

func (s *PostgreSQLStore) EndpointInMaintenance(endpointID string, now time.Time) (bool, error) {
	var exists int
	err := s.db.QueryRow(`SELECT 1 FROM endpoint_maintenance_windows w
		WHERE w.cancelled_at IS NULL AND w.starts_at<=$1 AND w.ends_at>$1 AND
		((w.target_type='endpoint' AND w.target_id=$2) OR (w.target_type='group' AND EXISTS(
		SELECT 1 FROM endpoints e JOIN asset_group_members m ON m.asset_id=e.asset_id
		WHERE e.id=$2 AND m.group_id=w.target_id))) LIMIT 1`, now, endpointID).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("resolve PostgreSQL endpoint maintenance: %w", err)
	}
	return true, nil
}
