package store

import (
	"encoding/json"
	"time"

	"mossward/internal/model"
	"mossward/internal/relaywindow"
)

func (s *SQLiteStore) UpsertRelayUploadWindow(window model.RelayUploadWindow, event model.AuditEvent) error {
	if err := relaywindow.Validate(window); err != nil {
		return err
	}
	days, err := json.Marshal(window.Days)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if !maintenanceTargetExists(tx, window.TargetType, window.TargetID) {
		return ErrNotFound
	}
	_, err = tx.Exec(`INSERT INTO relay_upload_windows(id,name,target_type,target_id,timezone,days_json,start_minute,end_minute,enabled,reason,created_by,created_at,updated_by,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,target_type=excluded.target_type,target_id=excluded.target_id,
		timezone=excluded.timezone,days_json=excluded.days_json,start_minute=excluded.start_minute,end_minute=excluded.end_minute,enabled=excluded.enabled,
		reason=excluded.reason,updated_by=excluded.updated_by,updated_at=excluded.updated_at`, window.ID, window.Name, window.TargetType, window.TargetID,
		window.Timezone, days, window.StartMinute, window.EndMinute, window.Enabled, window.Reason, window.CreatedBy, formatTime(window.CreatedAt), window.UpdatedBy, formatTime(window.UpdatedAt))
	if err != nil {
		return err
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) ListRelayUploadWindows() ([]model.RelayUploadWindow, error) {
	rows, err := s.db.Query(`SELECT id,name,target_type,target_id,timezone,days_json,start_minute,end_minute,enabled,reason,created_by,created_at,updated_by,updated_at FROM relay_upload_windows ORDER BY name,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	windows := []model.RelayUploadWindow{}
	for rows.Next() {
		window, err := scanRelayUploadWindow(rows)
		if err != nil {
			return nil, err
		}
		windows = append(windows, window)
	}
	return windows, rows.Err()
}

func scanRelayUploadWindow(scanner interface{ Scan(...any) error }) (model.RelayUploadWindow, error) {
	var window model.RelayUploadWindow
	var days, createdAt, updatedAt string
	var enabled bool
	err := scanner.Scan(&window.ID, &window.Name, &window.TargetType, &window.TargetID, &window.Timezone, &days, &window.StartMinute,
		&window.EndMinute, &enabled, &window.Reason, &window.CreatedBy, &createdAt, &window.UpdatedBy, &updatedAt)
	if err != nil {
		return window, err
	}
	window.Enabled = enabled
	if err := json.Unmarshal([]byte(days), &window.Days); err != nil {
		return window, err
	}
	window.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return window, err
	}
	window.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAt)
	return window, err
}
