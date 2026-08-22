package store

import (
	"database/sql"
	"errors"
	"fmt"

	"mossward/internal/model"
)

func (s *PostgreSQLStore) CreateAuthenticationCeremony(ceremony model.AuthenticationCeremony) error {
	var userID any
	if ceremony.UserID != "" {
		userID = ceremony.UserID
	}
	_, err := s.db.Exec(`INSERT INTO authentication_ceremonies(id_hash,user_id,kind,state_ciphertext,expires_at,created_at)
		VALUES($1,$2,$3,$4,$5,$6)`, ceremony.IDHash, userID, ceremony.Kind, ceremony.StateCiphertext,
		ceremony.ExpiresAt.UTC(), ceremony.CreatedAt.UTC())
	if err != nil {
		return fmt.Errorf("create PostgreSQL authentication ceremony: %w", err)
	}
	return nil
}

func (s *PostgreSQLStore) ConsumeAuthenticationCeremony(idHash []byte, kind model.AuthenticationCeremonyKind) (model.AuthenticationCeremony, error) {
	var ceremony model.AuthenticationCeremony
	var userID sql.NullString
	err := s.db.QueryRow(`DELETE FROM authentication_ceremonies WHERE id_hash=$1 AND kind=$2
		RETURNING id_hash,user_id,kind,state_ciphertext,expires_at,created_at`, idHash, kind).Scan(
		&ceremony.IDHash, &userID, &ceremony.Kind, &ceremony.StateCiphertext, &ceremony.ExpiresAt, &ceremony.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.AuthenticationCeremony{}, ErrCeremonyNotFound
	}
	if err != nil {
		return model.AuthenticationCeremony{}, fmt.Errorf("consume PostgreSQL authentication ceremony: %w", err)
	}
	ceremony.UserID = userID.String
	ceremony.ExpiresAt = ceremony.ExpiresAt.UTC()
	ceremony.CreatedAt = ceremony.CreatedAt.UTC()
	return ceremony, nil
}

func (s *PostgreSQLStore) CreateWebAuthnCredential(credential model.WebAuthnCredential) error {
	_, err := s.db.Exec(`INSERT INTO webauthn_credentials(credential_id,user_id,public_key,name,created_at,credential_ciphertext)
		VALUES($1,$2,$3,$4,$5,$6)`, credential.ID, credential.UserID, []byte{}, credential.Name,
		credential.CreatedAt.UTC(), credential.CredentialCiphertext)
	if err != nil {
		return fmt.Errorf("create PostgreSQL WebAuthn credential: %w", err)
	}
	return nil
}

func (s *PostgreSQLStore) ListWebAuthnCredentials(userID string) ([]model.WebAuthnCredential, error) {
	rows, err := s.db.Query(`SELECT credential_id,user_id,name,credential_ciphertext,created_at,last_used_at
		FROM webauthn_credentials WHERE user_id=$1 ORDER BY created_at,name`, userID)
	if err != nil {
		return nil, fmt.Errorf("list PostgreSQL WebAuthn credentials: %w", err)
	}
	defer rows.Close()
	credentials := []model.WebAuthnCredential{}
	for rows.Next() {
		credential, err := scanPostgreSQLWebAuthnCredential(rows)
		if err != nil {
			return nil, err
		}
		credentials = append(credentials, credential)
	}
	return credentials, rows.Err()
}

func (s *PostgreSQLStore) DeleteWebAuthnCredential(userID string, credentialID []byte) (bool, error) {
	result, err := s.db.Exec(`DELETE FROM webauthn_credentials WHERE user_id=$1 AND credential_id=$2`, userID, credentialID)
	if err != nil {
		return false, fmt.Errorf("delete PostgreSQL WebAuthn credential: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("read PostgreSQL WebAuthn credential deletion result: %w", err)
	}
	return changed > 0, nil
}

func (s *PostgreSQLStore) UpdateWebAuthnCredential(credential model.WebAuthnCredential) error {
	result, err := s.db.Exec(`UPDATE webauthn_credentials SET credential_ciphertext=$1,sign_count=$2,backup_eligible=$3,
		backup_state=$4,last_used_at=$5 WHERE user_id=$6 AND credential_id=$7`, credential.CredentialCiphertext,
		credential.SignCount, credential.BackupEligible, credential.BackupState, credential.LastUsedAt, credential.UserID, credential.ID)
	if err != nil {
		return fmt.Errorf("update PostgreSQL WebAuthn credential: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrIdentityNotFound
	}
	return nil
}

func scanPostgreSQLWebAuthnCredential(scanner interface{ Scan(...any) error }) (model.WebAuthnCredential, error) {
	var credential model.WebAuthnCredential
	var lastUsed sql.NullTime
	if err := scanner.Scan(&credential.ID, &credential.UserID, &credential.Name, &credential.CredentialCiphertext,
		&credential.CreatedAt, &lastUsed); err != nil {
		return credential, fmt.Errorf("scan PostgreSQL WebAuthn credential: %w", err)
	}
	if len(credential.CredentialCiphertext) == 0 {
		return model.WebAuthnCredential{}, errors.New("WebAuthn credential is missing encrypted data")
	}
	credential.CreatedAt = credential.CreatedAt.UTC()
	if lastUsed.Valid {
		value := lastUsed.Time.UTC()
		credential.LastUsedAt = &value
	}
	return credential, nil
}
