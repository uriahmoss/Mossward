package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyEndpointNetworkContextMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin endpoint network context migration: %w", err)
	}
	defer tx.Rollback()
	for _, statement := range []string{
		`ALTER TABLE endpoint_network_connections ADD COLUMN remote_hostname TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE endpoint_network_connections ADD COLUMN hostname_source TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE endpoint_network_connections ADD COLUMN tls_server_name TEXT NOT NULL DEFAULT ''`,
	} {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("apply endpoint network context migration: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(49,?)`, formatTime(time.Now().UTC())); err != nil {
		return err
	}
	return tx.Commit()
}
