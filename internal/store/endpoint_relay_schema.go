package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyEndpointRelayAuthorizationMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin endpoint relay-authorization migration: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(`CREATE TABLE endpoint_relay_authorizations (
		id TEXT PRIMARY KEY,endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,status TEXT NOT NULL CHECK(status IN ('active','revoked')),
		promotion_reason TEXT NOT NULL,promoted_by TEXT NOT NULL,promoted_at TEXT NOT NULL,
		revocation_reason TEXT NOT NULL DEFAULT '',revoked_by TEXT NOT NULL DEFAULT '',revoked_at TEXT)`)
	if err != nil {
		return fmt.Errorf("create endpoint relay authorizations: %w", err)
	}
	if _, err := tx.Exec(`CREATE UNIQUE INDEX endpoint_relay_one_active_idx ON endpoint_relay_authorizations(endpoint_id) WHERE status='active'`); err != nil {
		return err
	}
	if _, err := tx.Exec(`CREATE INDEX endpoint_relay_history_idx ON endpoint_relay_authorizations(endpoint_id,promoted_at DESC)`); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(59,?)`, formatTime(time.Now().UTC())); err != nil {
		return err
	}
	return tx.Commit()
}
