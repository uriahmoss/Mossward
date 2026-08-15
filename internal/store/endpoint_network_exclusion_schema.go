package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyEndpointNetworkExclusionMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin endpoint network-exclusion migration: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`ALTER TABLE endpoints ADD COLUMN network_telemetry_exclusions TEXT NOT NULL DEFAULT '{"applications":[],"destinations":[]}'`); err != nil {
		return fmt.Errorf("add endpoint network-exclusion policy: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(51,?)`, formatTime(time.Now().UTC())); err != nil {
		return err
	}
	return tx.Commit()
}
