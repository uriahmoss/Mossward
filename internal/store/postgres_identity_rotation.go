package store

import (
	"fmt"
	"time"

	"mossward/internal/model"
)

var postgresIdentityEncryptedColumns = []encryptedColumn{
	{table: "totp_credentials", keyColumn: "user_id", value: "secret_ciphertext"},
	{table: "webauthn_credentials", keyColumn: "credential_id", value: "credential_ciphertext"},
	{table: "authentication_ceremonies", keyColumn: "id_hash", value: "state_ciphertext"},
	{table: "oidc_providers", keyColumn: "id", value: "client_secret_ciphertext"},
	{table: "smtp_settings", keyColumn: "id", value: "password_ciphertext"},
}

func (s *PostgreSQLStore) RotateIdentityCiphertexts(cipher IdentityCipher, now time.Time) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("begin PostgreSQL identity-key rotation: %w", err)
	}
	defer tx.Rollback()
	rotated := 0
	for _, column := range postgresIdentityEncryptedColumns {
		count, err := rotateEncryptedColumn(tx, cipher, column, dialectPostgreSQL)
		if err != nil {
			return 0, err
		}
		rotated += count
	}
	event := model.AuditEvent{OccurredAt: now.UTC(), Action: "identity.encryption_key.rotated", Severity: model.AuditWarning,
		TargetType: "identity_key", Details: fmt.Sprintf(`{"ciphertexts":%d}`, rotated)}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit PostgreSQL identity-key rotation: %w", err)
	}
	return rotated, nil
}
