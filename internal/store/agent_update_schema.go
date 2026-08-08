package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyAgentUpdateCatalogMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin agent-update catalog migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`CREATE TABLE agent_update_releases (
			id TEXT PRIMARY KEY, version TEXT NOT NULL, operating_system TEXT NOT NULL,
			architecture TEXT NOT NULL, artifact_sha256 TEXT NOT NULL, artifact_size INTEGER NOT NULL,
			signing_key_id TEXT NOT NULL, envelope BLOB NOT NULL,
			status TEXT NOT NULL CHECK(status IN ('staged','approved','revoked')),
			created_by TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL,
			approved_by TEXT REFERENCES users(id), approved_at TEXT,
			revoked_by TEXT REFERENCES users(id), revoked_at TEXT, revocation_reason TEXT NOT NULL DEFAULT '',
			UNIQUE(version, operating_system, architecture)
		)`,
		`CREATE INDEX agent_update_releases_status_idx ON agent_update_releases(status, operating_system, architecture, created_at DESC)`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply agent-update catalog migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(39,?)`, formatTime(time.Now().UTC())); err != nil {
		return err
	}
	return tx.Commit()
}
