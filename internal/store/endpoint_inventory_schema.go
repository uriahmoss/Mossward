package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyEndpointOSInventoryMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin endpoint OS inventory migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`CREATE TABLE endpoint_os_inventory (endpoint_id TEXT PRIMARY KEY REFERENCES endpoints(id) ON DELETE CASCADE,family TEXT NOT NULL,name TEXT NOT NULL,version TEXT NOT NULL,build TEXT NOT NULL,kernel TEXT NOT NULL,architecture TEXT NOT NULL,collected_at TEXT NOT NULL,received_at TEXT NOT NULL)`,
		`CREATE TABLE endpoint_os_patches (endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,patch_id TEXT NOT NULL,description TEXT NOT NULL,installed_at TEXT,PRIMARY KEY(endpoint_id,patch_id))`,
		`CREATE INDEX endpoint_os_inventory_received_idx ON endpoint_os_inventory(received_at DESC)`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply endpoint OS inventory migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(42,?)`, formatTime(time.Now().UTC())); err != nil {
		return err
	}
	return tx.Commit()
}
