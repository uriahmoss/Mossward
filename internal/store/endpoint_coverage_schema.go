package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyEndpointCoverageMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin endpoint coverage migration: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(`CREATE TABLE endpoint_coverage_settings (
		singleton INTEGER PRIMARY KEY CHECK(singleton=1), enabled INTEGER NOT NULL,
		updated_by TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL DEFAULT '')`)
	if err != nil {
		return fmt.Errorf("create endpoint coverage settings: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO endpoint_coverage_settings(singleton,enabled) VALUES(1,0)`); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(52,?)`, formatTime(time.Now().UTC())); err != nil {
		return err
	}
	return tx.Commit()
}
