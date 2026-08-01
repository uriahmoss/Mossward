package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyInvitationControlsMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin invitation controls migration: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`ALTER TABLE invitations ADD COLUMN identity_kind TEXT NOT NULL DEFAULT 'local'
		CHECK(identity_kind IN ('local','sso'))`); err != nil {
		return fmt.Errorf("add invitation identity kind: %w", err)
	}
	if _, err := tx.Exec(`CREATE UNIQUE INDEX invitations_pending_email_idx ON invitations(email)
		WHERE accepted_at IS NULL`); err != nil {
		return fmt.Errorf("index pending invitations: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES(6, ?)`, formatTime(time.Now().UTC())); err != nil {
		return fmt.Errorf("record invitation controls migration: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit invitation controls migration: %w", err)
	}
	return nil
}
