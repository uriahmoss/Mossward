package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyAgentModuleMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin endpoint-module migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`ALTER TABLE endpoints ADD COLUMN asset_id TEXT REFERENCES assets(id)`,
		`CREATE TABLE agent_module_publishers (key_id TEXT PRIMARY KEY,name TEXT NOT NULL,public_key BLOB NOT NULL,enabled INTEGER NOT NULL,created_by TEXT NOT NULL REFERENCES users(id),created_at TEXT NOT NULL)`,
		`CREATE TABLE agent_module_releases (id TEXT PRIMARY KEY,module_id TEXT NOT NULL,version TEXT NOT NULL,manifest TEXT NOT NULL,envelope BLOB NOT NULL,status TEXT NOT NULL CHECK(status IN ('staged','approved','revoked')),created_by TEXT NOT NULL REFERENCES users(id),created_at TEXT NOT NULL,approved_by TEXT,approved_at TEXT,revoked_by TEXT,revoked_at TEXT,revocation_reason TEXT NOT NULL DEFAULT '',UNIQUE(module_id,version))`,
		`CREATE INDEX agent_module_release_status_idx ON agent_module_releases(status,module_id,version)`,
		`CREATE TABLE agent_module_assignments (id TEXT PRIMARY KEY,release_id TEXT NOT NULL REFERENCES agent_module_releases(id),target_type TEXT NOT NULL CHECK(target_type IN ('endpoint','group')),target_id TEXT NOT NULL,ring_percent INTEGER NOT NULL CHECK(ring_percent BETWEEN 1 AND 100),enabled INTEGER NOT NULL,created_by TEXT NOT NULL REFERENCES users(id),created_at TEXT NOT NULL,UNIQUE(release_id,target_type,target_id))`,
		`CREATE INDEX agent_module_assignment_target_idx ON agent_module_assignments(target_type,target_id,enabled)`,
		`CREATE TABLE agent_module_health (endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,module_id TEXT NOT NULL,version TEXT NOT NULL,healthy INTEGER NOT NULL,crash_count INTEGER NOT NULL,error TEXT NOT NULL DEFAULT '',observed_at TEXT NOT NULL,PRIMARY KEY(endpoint_id,module_id))`,
		`CREATE TABLE agent_module_settings (singleton INTEGER PRIMARY KEY CHECK(singleton=1),enabled INTEGER NOT NULL)`,
		`INSERT INTO agent_module_settings(singleton,enabled) VALUES(1,1)`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply endpoint-module migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(41,?)`, formatTime(time.Now().UTC())); err != nil {
		return err
	}
	return tx.Commit()
}
