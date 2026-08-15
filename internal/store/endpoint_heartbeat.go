package store

import "mossward/internal/model"

func (s *SQLiteStore) EndpointHeartbeatSettings() (model.EndpointHeartbeatSettings, error) {
	var settings model.EndpointHeartbeatSettings
	var updatedAt string
	err := s.db.QueryRow(`SELECT enabled,missed_after_minutes,stale_after_minutes,updated_by,updated_at FROM endpoint_heartbeat_settings WHERE singleton=1`).
		Scan(&settings.Enabled, &settings.MissedAfterMinutes, &settings.StaleAfterMinutes, &settings.UpdatedBy, &updatedAt)
	if updatedAt != "" {
		settings.UpdatedAt, _ = parseTime(updatedAt)
	}
	return settings, err
}

func (s *SQLiteStore) SetEndpointHeartbeatSettings(settings model.EndpointHeartbeatSettings, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`UPDATE endpoint_heartbeat_settings SET enabled=?,missed_after_minutes=?,stale_after_minutes=?,updated_by=?,updated_at=? WHERE singleton=1`,
		settings.Enabled, settings.MissedAfterMinutes, settings.StaleAfterMinutes, settings.UpdatedBy, formatTime(settings.UpdatedAt))
	if err != nil {
		return err
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}
