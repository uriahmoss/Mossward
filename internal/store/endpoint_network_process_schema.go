package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyEndpointNetworkProcessMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin endpoint network process migration: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`ALTER TABLE endpoint_network_connections ADD COLUMN executable TEXT NOT NULL DEFAULT ''`); err != nil {
		return fmt.Errorf("apply endpoint network process migration: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(48,?)`, formatTime(time.Now().UTC())); err != nil {
		return err
	}
	return tx.Commit()
}
