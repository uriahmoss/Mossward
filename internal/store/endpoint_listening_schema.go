package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyEndpointListeningInventoryMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin endpoint listening inventory migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`CREATE TABLE endpoint_listening_inventory (endpoint_id TEXT PRIMARY KEY REFERENCES endpoints(id) ON DELETE CASCADE,collected_at TEXT NOT NULL,received_at TEXT NOT NULL)`,
		`CREATE TABLE endpoint_listening_services (endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,ordinal INTEGER NOT NULL,protocol TEXT NOT NULL,address TEXT NOT NULL,port INTEGER NOT NULL,process_id INTEGER NOT NULL,process_name TEXT NOT NULL,executable TEXT NOT NULL,PRIMARY KEY(endpoint_id,ordinal))`,
		`CREATE INDEX endpoint_listening_service_lookup_idx ON endpoint_listening_services(protocol,port,process_name)`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply endpoint listening inventory migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(44,?)`, formatTime(time.Now().UTC())); err != nil {
		return err
	}
	return tx.Commit()
}
