package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyEndpointCollectorPolicyMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin endpoint collector-policy migration: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`ALTER TABLE endpoints ADD COLUMN allowed_collectors TEXT NOT NULL DEFAULT '[]'`); err != nil {
		return fmt.Errorf("add endpoint collector policy: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(38,?)`, formatTime(time.Now().UTC())); err != nil {
		return fmt.Errorf("record endpoint collector-policy migration: %w", err)
	}
	return tx.Commit()
}
