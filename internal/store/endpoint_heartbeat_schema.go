package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyEndpointHeartbeatSettingsMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin endpoint heartbeat-settings migration: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(`CREATE TABLE endpoint_heartbeat_settings (
		singleton INTEGER PRIMARY KEY CHECK(singleton=1),enabled INTEGER NOT NULL,
		missed_after_minutes INTEGER NOT NULL,stale_after_minutes INTEGER NOT NULL,
		updated_by TEXT NOT NULL DEFAULT '',updated_at TEXT NOT NULL DEFAULT '')`)
	if err != nil {
		return fmt.Errorf("create endpoint heartbeat settings: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO endpoint_heartbeat_settings(singleton,enabled,missed_after_minutes,stale_after_minutes) VALUES(1,1,5,30)`); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(55,?)`, formatTime(time.Now().UTC())); err != nil {
		return err
	}
	return tx.Commit()
}
