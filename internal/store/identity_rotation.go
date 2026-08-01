package store

import (
	"database/sql"
	"fmt"
	"time"

	"mossward/internal/model"
)

type IdentityCipher interface {
	Encrypt([]byte) ([]byte, error)
	Decrypt([]byte) ([]byte, error)
}

type encryptedColumn struct {
	table     string
	keyColumn string
	value     string
}

var identityEncryptedColumns = []encryptedColumn{
	{table: "totp_credentials", keyColumn: "user_id", value: "secret_ciphertext"},
	{table: "webauthn_credentials", keyColumn: "credential_id", value: "credential_ciphertext"},
	{table: "authentication_ceremonies", keyColumn: "id_hash", value: "state_ciphertext"},
	{table: "oidc_providers", keyColumn: "id", value: "client_secret_ciphertext"},
}

func (s *SQLiteStore) RotateIdentityCiphertexts(cipher IdentityCipher, now time.Time) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("begin identity-key rotation: %w", err)
	}
	defer tx.Rollback()
	rotated := 0
	for _, column := range identityEncryptedColumns {
		count, err := rotateEncryptedColumn(tx, cipher, column)
		if err != nil {
			return 0, err
		}
		rotated += count
	}
	event := model.AuditEvent{OccurredAt: now, Action: "identity.encryption_key.rotated", Severity: model.AuditWarning,
		TargetType: "identity_key", Details: fmt.Sprintf(`{"ciphertexts":%d}`, rotated)}
	if err := insertAuditEvent(tx, event); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit identity-key rotation: %w", err)
	}
	return rotated, nil
}

func rotateEncryptedColumn(tx *sql.Tx, cipher IdentityCipher, column encryptedColumn) (int, error) {
	query := fmt.Sprintf("SELECT %s, %s FROM %s WHERE %s IS NOT NULL AND length(%s)>0",
		column.keyColumn, column.value, column.table, column.value, column.value)
	rows, err := tx.Query(query)
	if err != nil {
		return 0, fmt.Errorf("read %s for identity-key rotation: %w", column.table, err)
	}
	type record struct {
		key        any
		ciphertext []byte
	}
	records := []record{}
	for rows.Next() {
		var item record
		if err := rows.Scan(&item.key, &item.ciphertext); err != nil {
			_ = rows.Close()
			return 0, err
		}
		records = append(records, item)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	update := fmt.Sprintf("UPDATE %s SET %s=? WHERE %s=?", column.table, column.value, column.keyColumn)
	for _, item := range records {
		plaintext, err := cipher.Decrypt(item.ciphertext)
		if err != nil {
			return 0, fmt.Errorf("decrypt %s during identity-key rotation: %w", column.table, err)
		}
		ciphertext, err := cipher.Encrypt(plaintext)
		if err != nil {
			return 0, fmt.Errorf("encrypt %s during identity-key rotation: %w", column.table, err)
		}
		if _, err := tx.Exec(update, ciphertext, item.key); err != nil {
			return 0, fmt.Errorf("update %s during identity-key rotation: %w", column.table, err)
		}
	}
	return len(records), nil
}
