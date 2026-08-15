package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyEndpointSoftwareInventoryMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin endpoint software inventory migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`CREATE TABLE endpoint_software_inventory (endpoint_id TEXT PRIMARY KEY REFERENCES endpoints(id) ON DELETE CASCADE,collected_at TEXT NOT NULL,received_at TEXT NOT NULL)`,
		`CREATE TABLE endpoint_installed_software (endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,ordinal INTEGER NOT NULL,name TEXT NOT NULL,version TEXT NOT NULL,publisher TEXT NOT NULL,architecture TEXT NOT NULL,source TEXT NOT NULL,PRIMARY KEY(endpoint_id,ordinal))`,
		`CREATE INDEX endpoint_installed_software_lookup_idx ON endpoint_installed_software(name,version)`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply endpoint software inventory migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(43,?)`, formatTime(time.Now().UTC())); err != nil {
		return err
	}
	return tx.Commit()
}
