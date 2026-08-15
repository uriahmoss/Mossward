package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyEndpointNetworkMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin endpoint network metadata migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`CREATE TABLE endpoint_network_inventory (endpoint_id TEXT PRIMARY KEY REFERENCES endpoints(id) ON DELETE CASCADE,collected_at TEXT NOT NULL,received_at TEXT NOT NULL)`,
		`CREATE TABLE endpoint_network_connections (endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,ordinal INTEGER NOT NULL,protocol TEXT NOT NULL,local_address TEXT NOT NULL,local_port INTEGER NOT NULL,remote_address TEXT NOT NULL,remote_port INTEGER NOT NULL,process_id INTEGER NOT NULL,process_name TEXT NOT NULL,direction TEXT NOT NULL,PRIMARY KEY(endpoint_id,ordinal))`,
		`CREATE INDEX endpoint_network_remote_idx ON endpoint_network_connections(remote_address,remote_port)`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply endpoint network metadata migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(47,?)`, formatTime(time.Now().UTC())); err != nil {
		return err
	}
	return tx.Commit()
}
