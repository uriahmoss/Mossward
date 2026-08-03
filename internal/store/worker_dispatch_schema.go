package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyScannerWorkerDispatchMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin scanner-worker dispatch migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`ALTER TABLE scanner_workers ADD COLUMN dispatch_enabled INTEGER NOT NULL DEFAULT 1 CHECK(dispatch_enabled IN (0,1))`,
		`CREATE TABLE scanner_worker_dispatch_settings (id INTEGER PRIMARY KEY CHECK(id=1),enabled INTEGER NOT NULL CHECK(enabled IN (0,1)))`,
		`INSERT INTO scanner_worker_dispatch_settings(id,enabled) VALUES(1,1)`,
		`CREATE INDEX scanner_workers_dispatch_idx ON scanner_workers(status,dispatch_enabled)`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply scanner-worker dispatch migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(31,?)`, formatTime(time.Now().UTC())); err != nil {
		return fmt.Errorf("record scanner-worker dispatch migration: %w", err)
	}
	return tx.Commit()
}
