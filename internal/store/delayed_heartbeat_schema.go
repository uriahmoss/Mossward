package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyDelayedHeartbeatPolicyMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin delayed-heartbeat policy migration: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(`CREATE TABLE delayed_heartbeat_policies (
		target_type TEXT NOT NULL CHECK(target_type IN ('endpoint','group')),target_id TEXT NOT NULL,allow_delayed_heartbeats INTEGER NOT NULL,
		reason TEXT NOT NULL,updated_by TEXT NOT NULL,updated_at TEXT NOT NULL,PRIMARY KEY(target_type,target_id))`)
	if err != nil {
		return fmt.Errorf("create delayed-heartbeat policies: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(62,?)`, formatTime(time.Now().UTC())); err != nil {
		return err
	}
	return tx.Commit()
}
