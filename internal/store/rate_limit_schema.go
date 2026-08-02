package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyRateLimitMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin scan rate-limit migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`ALTER TABLE reusable_scan_policies ADD COLUMN rate_limit_per_second INTEGER NOT NULL DEFAULT 0 CHECK(rate_limit_per_second BETWEEN 0 AND 1000)`,
		`ALTER TABLE scans ADD COLUMN rate_limit_per_second INTEGER NOT NULL DEFAULT 0 CHECK(rate_limit_per_second BETWEEN 0 AND 1000)`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply scan rate-limit migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(21,?)`, formatTime(time.Now().UTC())); err != nil {
		return fmt.Errorf("record scan rate-limit migration: %w", err)
	}
	return tx.Commit()
}
