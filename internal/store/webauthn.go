package store

import (
	"database/sql"
	"errors"
	"fmt"

	"mossward/internal/model"
)

func (s *SQLiteStore) CreateWebAuthnCredential(credential model.WebAuthnCredential) error {
	_, err := s.db.Exec(`INSERT INTO webauthn_credentials(
		credential_id, user_id, public_key, name, created_at, credential_ciphertext
	) VALUES(?, ?, ?, ?, ?, ?)`, credential.ID, credential.UserID, []byte{}, credential.Name,
		formatTime(credential.CreatedAt), credential.CredentialCiphertext)
	if err != nil {
		return fmt.Errorf("create WebAuthn credential: %w", err)
	}
	return nil
}

func (s *SQLiteStore) ListWebAuthnCredentials(userID string) ([]model.WebAuthnCredential, error) {
	rows, err := s.db.Query(`SELECT credential_id, user_id, name, credential_ciphertext, created_at, last_used_at
		FROM webauthn_credentials WHERE user_id=? ORDER BY created_at, name`, userID)
	if err != nil {
		return nil, fmt.Errorf("list WebAuthn credentials: %w", err)
	}
	defer rows.Close()
	credentials := []model.WebAuthnCredential{}
	for rows.Next() {
		credential, err := scanWebAuthnCredential(rows)
		if err != nil {
			return nil, err
		}
		credentials = append(credentials, credential)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate WebAuthn credentials: %w", err)
	}
	return credentials, nil
}

func (s *SQLiteStore) DeleteWebAuthnCredential(userID string, credentialID []byte) (bool, error) {
	result, err := s.db.Exec(`DELETE FROM webauthn_credentials WHERE user_id=? AND credential_id=?`, userID, credentialID)
	if err != nil {
		return false, fmt.Errorf("delete WebAuthn credential: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("read WebAuthn credential deletion result: %w", err)
	}
	return changed > 0, nil
}

func (s *SQLiteStore) UpdateWebAuthnCredential(credential model.WebAuthnCredential) error {
	result, err := s.db.Exec(`UPDATE webauthn_credentials SET credential_ciphertext=?, sign_count=?, backup_eligible=?,
		backup_state=?, last_used_at=? WHERE user_id=? AND credential_id=?`, credential.CredentialCiphertext,
		credential.SignCount, credential.BackupEligible, credential.BackupState, formatOptionalTime(credential.LastUsedAt),
		credential.UserID, credential.ID)
	if err != nil {
		return fmt.Errorf("update WebAuthn credential: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read WebAuthn credential update result: %w", err)
	}
	if changed == 0 {
		return ErrIdentityNotFound
	}
	return nil
}

func scanWebAuthnCredential(scanner interface{ Scan(...any) error }) (model.WebAuthnCredential, error) {
	var credential model.WebAuthnCredential
	var created string
	var lastUsed sql.NullString
	if err := scanner.Scan(&credential.ID, &credential.UserID, &credential.Name,
		&credential.CredentialCiphertext, &created, &lastUsed); err != nil {
		return model.WebAuthnCredential{}, fmt.Errorf("scan WebAuthn credential: %w", err)
	}
	if len(credential.CredentialCiphertext) == 0 {
		return model.WebAuthnCredential{}, errors.New("WebAuthn credential is missing encrypted data")
	}
	var err error
	if credential.CreatedAt, err = parseTime(created); err != nil {
		return model.WebAuthnCredential{}, err
	}
	if credential.LastUsedAt, err = parseOptionalTime(lastUsed); err != nil {
		return model.WebAuthnCredential{}, err
	}
	return credential, nil
}
