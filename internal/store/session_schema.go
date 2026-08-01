package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applySessionControlsMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin session controls migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`ALTER TABLE sessions ADD COLUMN public_id TEXT NOT NULL DEFAULT ''`,
		`UPDATE sessions SET public_id=lower(hex(randomblob(12))) WHERE public_id=''`,
		`CREATE UNIQUE INDEX sessions_public_id_idx ON sessions(public_id)`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply session controls migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES(4, ?)`, formatTime(time.Now().UTC())); err != nil {
		return fmt.Errorf("record session controls migration: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit session controls migration: %w", err)
	}
	return nil
}
