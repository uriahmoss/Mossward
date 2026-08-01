package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyOIDCControlsMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin OIDC controls migration: %w", err)
	}
	defer tx.Rollback()
	for _, statement := range []string{
		`ALTER TABLE oidc_providers ADD COLUMN redirect_url TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE oidc_providers ADD COLUMN tested_at TEXT`,
	} {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply OIDC controls migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES(7, ?)`, formatTime(time.Now().UTC())); err != nil {
		return fmt.Errorf("record OIDC controls migration: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit OIDC controls migration: %w", err)
	}
	return nil
}
