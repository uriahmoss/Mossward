package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyCheckCatalogMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin check-catalog migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`CREATE TABLE check_publishers (key_id TEXT PRIMARY KEY,name TEXT NOT NULL,public_key BLOB NOT NULL,status TEXT NOT NULL CHECK(status IN ('trusted','revoked')),added_at TEXT NOT NULL,revoked_at TEXT)`,
		`CREATE TABLE declarative_check_versions (check_id TEXT NOT NULL,version TEXT NOT NULL,kind TEXT NOT NULL,key_id TEXT NOT NULL,envelope_json BLOB NOT NULL,status TEXT NOT NULL CHECK(status IN ('staged','active','retired')),imported_at TEXT NOT NULL,activated_at TEXT,PRIMARY KEY(check_id,version),FOREIGN KEY(key_id) REFERENCES check_publishers(key_id))`,
		`CREATE UNIQUE INDEX declarative_checks_one_active_idx ON declarative_check_versions(check_id) WHERE status='active'`,
		`CREATE INDEX declarative_checks_publisher_idx ON declarative_check_versions(key_id,status)`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply check-catalog migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(34,?)`, formatTime(time.Now().UTC())); err != nil {
		return fmt.Errorf("record check-catalog migration: %w", err)
	}
	return tx.Commit()
}
