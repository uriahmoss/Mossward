package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyEndpointIntegritySequenceMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin endpoint integrity-sequence migration: %w", err)
	}
	defer tx.Rollback()
	for _, statement := range []string{
		`ALTER TABLE endpoint_integrity_snapshots ADD COLUMN sequence INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE endpoint_integrity_snapshots ADD COLUMN signature TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE endpoint_integrity_events ADD COLUMN sequence INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE endpoint_integrity_events ADD COLUMN signature TEXT NOT NULL DEFAULT ''`,
	} {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply endpoint integrity-sequence migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(57,?)`, formatTime(time.Now().UTC())); err != nil {
		return err
	}
	return tx.Commit()
}
