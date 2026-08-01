package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyAssetLifecycleMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin asset lifecycle migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`ALTER TABLE assets ADD COLUMN lifecycle_status TEXT NOT NULL DEFAULT 'active' CHECK(lifecycle_status IN ('active','retired'))`,
		`ALTER TABLE assets ADD COLUMN retired_at TEXT`,
		`ALTER TABLE assets ADD COLUMN retired_by TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE assets ADD COLUMN retirement_reason TEXT NOT NULL DEFAULT ''`,
		`CREATE INDEX assets_lifecycle_last_seen_idx ON assets(lifecycle_status,last_seen DESC)`,
		`CREATE TABLE asset_aging_settings (singleton INTEGER PRIMARY KEY CHECK(singleton=1),stale_after_days INTEGER NOT NULL CHECK(stale_after_days BETWEEN 1 AND 3650))`,
		`INSERT INTO asset_aging_settings(singleton,stale_after_days) VALUES(1,30)`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply asset lifecycle migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(20,?)`, formatTime(time.Now().UTC())); err != nil {
		return fmt.Errorf("record asset lifecycle migration: %w", err)
	}
	return tx.Commit()
}
