package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyPolicyScheduleMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin policy schedule migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`ALTER TABLE reusable_scan_policies ADD COLUMN schedule_kind TEXT NOT NULL DEFAULT 'manual'`,
		`ALTER TABLE reusable_scan_policies ADD COLUMN schedule_expression TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE reusable_scan_policies ADD COLUMN schedule_timezone TEXT NOT NULL DEFAULT 'UTC'`,
		`ALTER TABLE reusable_scan_policies ADD COLUMN window_start TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE reusable_scan_policies ADD COLUMN window_end TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE reusable_scan_policies ADD COLUMN run_missed INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE reusable_scan_policies ADD COLUMN long_run_alert_seconds INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE reusable_scan_policies ADD COLUMN next_run_at TEXT`,
		`ALTER TABLE reusable_scan_policies ADD COLUMN last_scheduled_at TEXT`,
		`ALTER TABLE scans ADD COLUMN long_alert_sent INTEGER NOT NULL DEFAULT 0`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply policy schedule migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(16,?)`, formatTime(time.Now().UTC())); err != nil {
		return err
	}
	return tx.Commit()
}
