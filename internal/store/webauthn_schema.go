package store

import (
	"fmt"
	"time"
)

func (s *SQLiteStore) applyWebAuthnCredentialMigration() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin WebAuthn credential migration: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`ALTER TABLE webauthn_credentials ADD COLUMN credential_ciphertext BLOB`); err != nil {
		return fmt.Errorf("add encrypted WebAuthn credential storage: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES(5, ?)`, formatTime(time.Now().UTC())); err != nil {
		return fmt.Errorf("record WebAuthn credential migration: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit WebAuthn credential migration: %w", err)
	}
	return nil
}
