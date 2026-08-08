package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyAgentUpdateAssignmentMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin agent-update assignment migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`ALTER TABLE endpoints ADD COLUMN software_version TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE endpoints ADD COLUMN operating_system TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE endpoints ADD COLUMN architecture TEXT NOT NULL DEFAULT ''`,
		`CREATE TABLE agent_update_assignments (
			endpoint_id TEXT PRIMARY KEY REFERENCES endpoints(id) ON DELETE CASCADE,
			release_id TEXT NOT NULL REFERENCES agent_update_releases(id),
			status TEXT NOT NULL CHECK(status IN ('assigned','offered','installed')),
			assigned_by TEXT NOT NULL REFERENCES users(id), assigned_at TEXT NOT NULL,
			offered_at TEXT, installed_at TEXT
		)`,
		`CREATE INDEX agent_update_assignments_release_idx ON agent_update_assignments(release_id,status)`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply agent-update assignment migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(40,?)`, formatTime(time.Now().UTC())); err != nil {
		return err
	}
	return tx.Commit()
}
