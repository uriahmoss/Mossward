package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyRelayDownstreamAuthorizationMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin relay downstream-authorization migration: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(`CREATE TABLE relay_downstream_authorizations (
		id TEXT PRIMARY KEY,relay_endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
		downstream_endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,status TEXT NOT NULL CHECK(status IN ('active','revoked')),
		authorization_reason TEXT NOT NULL,authorized_by TEXT NOT NULL,authorized_at TEXT NOT NULL,
		revocation_reason TEXT NOT NULL DEFAULT '',revoked_by TEXT NOT NULL DEFAULT '',revoked_at TEXT)`)
	if err != nil {
		return fmt.Errorf("create relay downstream authorizations: %w", err)
	}
	for _, statement := range []string{
		`CREATE UNIQUE INDEX relay_downstream_one_active_relay_idx ON relay_downstream_authorizations(downstream_endpoint_id) WHERE status='active'`,
		`CREATE INDEX relay_downstream_relay_history_idx ON relay_downstream_authorizations(relay_endpoint_id,authorized_at DESC)`,
	} {
		if _, err := tx.Exec(statement); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(60,?)`, formatTime(time.Now().UTC())); err != nil {
		return err
	}
	return tx.Commit()
}
