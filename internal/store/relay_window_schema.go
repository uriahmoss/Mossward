package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyRelayUploadWindowMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin relay upload-window migration: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(`CREATE TABLE relay_upload_windows (
		id TEXT PRIMARY KEY,name TEXT NOT NULL,target_type TEXT NOT NULL CHECK(target_type IN ('endpoint','group')),target_id TEXT NOT NULL,
		timezone TEXT NOT NULL,days_json TEXT NOT NULL,start_minute INTEGER NOT NULL,end_minute INTEGER NOT NULL,enabled INTEGER NOT NULL,
		reason TEXT NOT NULL,created_by TEXT NOT NULL,created_at TEXT NOT NULL,updated_by TEXT NOT NULL,updated_at TEXT NOT NULL)`)
	if err != nil {
		return fmt.Errorf("create relay upload windows: %w", err)
	}
	if _, err := tx.Exec(`CREATE INDEX relay_upload_windows_target_idx ON relay_upload_windows(target_type,target_id,enabled)`); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(61,?)`, formatTime(time.Now().UTC())); err != nil {
		return err
	}
	return tx.Commit()
}
