package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyDelayedHeartbeatGraceMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin delayed-heartbeat grace migration: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`ALTER TABLE delayed_heartbeat_policies ADD COLUMN post_window_grace_minutes INTEGER NOT NULL DEFAULT 0`); err != nil {
		return fmt.Errorf("add delayed-heartbeat grace: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(64,?)`, formatTime(time.Now().UTC())); err != nil {
		return err
	}
	return tx.Commit()
}
