package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyCoverageDiscoveryPolicyMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin coverage discovery-policy migration: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(`CREATE TABLE coverage_discovery_policies (
		id TEXT PRIMARY KEY,name TEXT NOT NULL,cidrs TEXT NOT NULL,enabled INTEGER NOT NULL,
		created_by TEXT NOT NULL,created_at TEXT NOT NULL,updated_by TEXT NOT NULL,updated_at TEXT NOT NULL)`)
	if err != nil {
		return fmt.Errorf("create coverage discovery policies: %w", err)
	}
	if _, err := tx.Exec(`CREATE INDEX coverage_discovery_policy_enabled_idx ON coverage_discovery_policies(enabled,name)`); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(53,?)`, formatTime(time.Now().UTC())); err != nil {
		return err
	}
	return tx.Commit()
}
