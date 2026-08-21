package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyEndpointHeartbeatTimestampMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin endpoint heartbeat-timestamp migration: %w", err)
	}
	defer tx.Rollback()
	for _, statement := range []string{
		`ALTER TABLE endpoints ADD COLUMN last_heartbeat_generated_at TEXT`,
		`ALTER TABLE endpoints ADD COLUMN last_heartbeat_received_at TEXT`,
		`UPDATE endpoints SET last_heartbeat_received_at=last_seen_at WHERE last_seen_at IS NOT NULL`,
	} {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply endpoint heartbeat-timestamp migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(63,?)`, formatTime(time.Now().UTC())); err != nil {
		return err
	}
	return tx.Commit()
}
