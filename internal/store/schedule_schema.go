package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyResumableScanMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin resumable scan migration: %w", err)
	}
	defer tx.Rollback()
	for _, statement := range []string{`ALTER TABLE scans ADD COLUMN active_seconds INTEGER NOT NULL DEFAULT 0`, `ALTER TABLE scans ADD COLUMN window_end TEXT`, `CREATE TABLE scan_checkpoints (scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,address TEXT NOT NULL,port INTEGER NOT NULL,completed_at TEXT NOT NULL,PRIMARY KEY(scan_id,address,port))`} {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply resumable scan migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(15,?)`, formatTime(time.Now().UTC())); err != nil {
		return err
	}
	return tx.Commit()
}
