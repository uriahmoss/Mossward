package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyAssetGroupPolicyMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin asset group policy migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`CREATE TABLE asset_groups (id TEXT PRIMARY KEY,name TEXT NOT NULL UNIQUE,description TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL,updated_at TEXT NOT NULL)`,
		`CREATE TABLE asset_group_members (group_id TEXT NOT NULL REFERENCES asset_groups(id) ON DELETE CASCADE,asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,added_at TEXT NOT NULL,added_by TEXT NOT NULL REFERENCES users(id),PRIMARY KEY(group_id,asset_id))`,
		`CREATE INDEX asset_group_members_asset_idx ON asset_group_members(asset_id,group_id)`,
		`CREATE TABLE reusable_scan_policies (id TEXT PRIMARY KEY,name TEXT NOT NULL UNIQUE,scope_policy_id TEXT NOT NULL REFERENCES scope_policies(id),ports TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL,updated_at TEXT NOT NULL)`,
		`CREATE TABLE reusable_scan_policy_groups (scan_policy_id TEXT NOT NULL REFERENCES reusable_scan_policies(id) ON DELETE CASCADE,group_id TEXT NOT NULL REFERENCES asset_groups(id) ON DELETE RESTRICT,ordinal INTEGER NOT NULL,PRIMARY KEY(scan_policy_id,group_id))`,
		`ALTER TABLE scans ADD COLUMN scan_policy_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE scan_targets ADD COLUMN group_ids TEXT NOT NULL DEFAULT '[]'`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply asset group policy migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(14,?)`, formatTime(time.Now().UTC())); err != nil {
		return err
	}
	return tx.Commit()
}
