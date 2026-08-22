package store

import (
	"database/sql"
	"errors"
	"fmt"

	"mossward/internal/model"
)

const postgresBootstrapLockID = 713_677_282

func (s *PostgreSQLStore) IdentityInitialized() (bool, error) {
	var exists bool
	if err := s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM users)`).Scan(&exists); err != nil {
		return false, fmt.Errorf("check PostgreSQL identity initialization: %w", err)
	}
	return exists, nil
}

func (s *PostgreSQLStore) BootstrapAdministrator(user model.User, passwordHash string, mfa model.BootstrapMFA, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL administrator bootstrap: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock($1)`, postgresBootstrapLockID); err != nil {
		return fmt.Errorf("lock PostgreSQL administrator bootstrap: %w", err)
	}
	var exists bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM users)`).Scan(&exists); err != nil {
		return fmt.Errorf("check PostgreSQL administrator bootstrap state: %w", err)
	}
	if exists {
		return ErrAlreadyInitialized
	}
	_, err = tx.Exec(`INSERT INTO users(id,email,display_name,role,status,password_hash,mfa_required,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, user.ID, normalizeEmail(user.Email), user.DisplayName, user.Role,
		user.Status, passwordHash, user.MFARequired, user.CreatedAt.UTC(), user.UpdatedAt.UTC())
	if err != nil {
		return fmt.Errorf("create PostgreSQL bootstrap administrator: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO totp_credentials(user_id,secret_ciphertext,created_at,verified_at) VALUES($1,$2,$3,$3)`,
		user.ID, mfa.TOTPSecretCiphertext, user.CreatedAt.UTC()); err != nil {
		return fmt.Errorf("create PostgreSQL bootstrap TOTP credential: %w", err)
	}
	for _, codeHash := range mfa.RecoveryCodeHashes {
		if _, err := tx.Exec(`INSERT INTO recovery_codes(user_id,code_hash,created_at) VALUES($1,$2,$3)`,
			user.ID, codeHash, user.CreatedAt.UTC()); err != nil {
			return fmt.Errorf("create PostgreSQL bootstrap recovery code: %w", err)
		}
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit PostgreSQL administrator bootstrap: %w", err)
	}
	return nil
}

func (s *PostgreSQLStore) LocalIdentityByEmail(email string) (model.LocalIdentity, error) {
	return s.localIdentity(`LOWER(email)=LOWER($1)`, normalizeEmail(email))
}

func (s *PostgreSQLStore) LocalIdentityByID(userID string) (model.LocalIdentity, error) {
	return s.localIdentity(`id=$1`, userID)
}

func (s *PostgreSQLStore) localIdentity(predicate string, value any) (model.LocalIdentity, error) {
	var identity model.LocalIdentity
	var lastLogin sql.NullTime
	err := s.db.QueryRow(`SELECT id,email,display_name,role,status,mfa_required,created_at,updated_at,last_login_at,password_hash
		FROM users WHERE `+predicate, value).Scan(&identity.User.ID, &identity.User.Email, &identity.User.DisplayName,
		&identity.User.Role, &identity.User.Status, &identity.User.MFARequired, &identity.User.CreatedAt,
		&identity.User.UpdatedAt, &lastLogin, &identity.PasswordHash)
	if errors.Is(err, sql.ErrNoRows) {
		return model.LocalIdentity{}, ErrIdentityNotFound
	}
	if err != nil {
		return model.LocalIdentity{}, fmt.Errorf("load PostgreSQL local identity: %w", err)
	}
	identity.User.CreatedAt = identity.User.CreatedAt.UTC()
	identity.User.UpdatedAt = identity.User.UpdatedAt.UTC()
	if lastLogin.Valid {
		value := lastLogin.Time.UTC()
		identity.User.LastLoginAt = &value
	}
	return identity, nil
}
