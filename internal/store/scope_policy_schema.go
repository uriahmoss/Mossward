package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyScopePolicyControlsMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin scope-policy controls migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`ALTER TABLE scope_policies ADD COLUMN max_concurrent INTEGER NOT NULL DEFAULT 1`,
		`ALTER TABLE scans ADD COLUMN scope_policy_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE scans ADD COLUMN max_concurrent INTEGER NOT NULL DEFAULT 1`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply scope-policy controls migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES(8, ?)`, formatTime(time.Now().UTC())); err != nil {
		return fmt.Errorf("record scope-policy controls migration: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit scope-policy controls migration: %w", err)
	}
	return nil
}
