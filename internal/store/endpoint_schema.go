package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyEndpointIdentityMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin endpoint identity migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`CREATE TABLE agent_enrollment_tokens (
			id TEXT PRIMARY KEY, name TEXT NOT NULL, token_hash BLOB NOT NULL UNIQUE,
			created_by TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL,
			expires_at TEXT NOT NULL, used_at TEXT
		)`,
		`CREATE INDEX agent_enrollment_tokens_expiry_idx ON agent_enrollment_tokens(expires_at, used_at)`,
		`CREATE TABLE endpoints (
			id TEXT PRIMARY KEY, name TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('active','revoked')),
			certificate_serial TEXT NOT NULL UNIQUE, certificate_pem TEXT NOT NULL,
			enrolled_at TEXT NOT NULL, expires_at TEXT NOT NULL, last_seen_at TEXT
		)`,
		`CREATE INDEX endpoints_status_idx ON endpoints(status, name)`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply endpoint identity migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES(9, ?)`, formatTime(time.Now().UTC())); err != nil {
		return fmt.Errorf("record endpoint identity migration: %w", err)
	}
	return tx.Commit()
}

func (s *SQLiteStore) applyEndpointLifecycleMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin endpoint lifecycle migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`ALTER TABLE endpoints ADD COLUMN renewed_at TEXT`,
		`ALTER TABLE endpoints ADD COLUMN revoked_at TEXT`,
		`ALTER TABLE endpoints ADD COLUMN revocation_reason TEXT NOT NULL DEFAULT ''`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply endpoint lifecycle migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES(10, ?)`, formatTime(time.Now().UTC())); err != nil {
		return fmt.Errorf("record endpoint lifecycle migration: %w", err)
	}
	return tx.Commit()
}
