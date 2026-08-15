package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyEndpointIntegrityMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin endpoint integrity migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`CREATE TABLE endpoint_integrity_snapshots (endpoint_id TEXT PRIMARY KEY REFERENCES endpoints(id) ON DELETE CASCADE,executable_sha256 TEXT NOT NULL,configuration_sha256 TEXT NOT NULL,identity_sha256 TEXT NOT NULL,observed_at TEXT NOT NULL,received_at TEXT NOT NULL)`,
		`CREATE TABLE endpoint_integrity_events (id INTEGER PRIMARY KEY AUTOINCREMENT,endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,component TEXT NOT NULL CHECK(component IN ('executable','configuration','identity')),previous_sha256 TEXT NOT NULL,current_sha256 TEXT NOT NULL,observed_at TEXT NOT NULL,received_at TEXT NOT NULL)`,
		`CREATE INDEX endpoint_integrity_events_endpoint_idx ON endpoint_integrity_events(endpoint_id,received_at DESC,id DESC)`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply endpoint integrity migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(56,?)`, formatTime(time.Now().UTC())); err != nil {
		return err
	}
	return tx.Commit()
}
