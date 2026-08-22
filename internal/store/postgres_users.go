package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"mossward/internal/model"
)

func (s *PostgreSQLStore) ListUsers() ([]model.User, error) {
	rows, err := s.db.Query(`SELECT id,email,display_name,role,status,mfa_required,created_at,updated_at,last_login_at FROM users ORDER BY email`)
	if err != nil {
		return nil, fmt.Errorf("list PostgreSQL users: %w", err)
	}
	defer rows.Close()
	users := []model.User{}
	for rows.Next() {
		user, err := scanPostgreSQLUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

func (s *PostgreSQLStore) UpdateUserAccess(userID string, role model.UserRole, status model.UserStatus, now time.Time, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL user access update: %w", err)
	}
	defer tx.Rollback()
	localAdministratorCount, err := lockPostgreSQLLocalAdministrators(tx)
	if err != nil {
		return err
	}
	var currentRole model.UserRole
	var currentStatus model.UserStatus
	var passwordHash string
	err = tx.QueryRow(`SELECT role,status,password_hash FROM users WHERE id=$1 FOR UPDATE`, userID).Scan(&currentRole, &currentStatus, &passwordHash)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrIdentityNotFound
	}
	if err != nil {
		return fmt.Errorf("load PostgreSQL user access: %w", err)
	}
	removesLocalAdmin := currentRole == model.RoleAdministrator && currentStatus == model.UserActive && passwordHash != "" &&
		(role != model.RoleAdministrator || status != model.UserActive)
	if removesLocalAdmin && localAdministratorCount <= 1 {
		return ErrFinalAdministrator
	}
	if _, err := tx.Exec(`UPDATE users SET role=$1,status=$2,updated_at=$3 WHERE id=$4`, role, status, now.UTC(), userID); err != nil {
		return fmt.Errorf("update PostgreSQL user access: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM sessions WHERE user_id=$1`, userID); err != nil {
		return fmt.Errorf("revoke changed PostgreSQL user sessions: %w", err)
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func lockPostgreSQLLocalAdministrators(tx *sql.Tx) (int, error) {
	rows, err := tx.Query(`SELECT id FROM users WHERE role='administrator' AND status='active' AND password_hash<>'' FOR UPDATE`)
	if err != nil {
		return 0, fmt.Errorf("lock PostgreSQL local administrators: %w", err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
	}
	return count, rows.Err()
}

func (s *PostgreSQLStore) CreateInvitation(invitation model.Invitation, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL invitation creation: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO invitations(id,email,role,token_hash,invited_by,expires_at,created_at,identity_kind)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, invitation.ID, normalizeEmail(invitation.Email), invitation.Role,
		invitation.TokenHash, invitation.InvitedBy, invitation.ExpiresAt.UTC(), invitation.CreatedAt.UTC(), invitation.IdentityKind)
	if err != nil {
		return fmt.Errorf("create PostgreSQL invitation: %w", err)
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) ListInvitations(now time.Time) ([]model.Invitation, error) {
	rows, err := s.db.Query(`SELECT id,email,role,identity_kind,invited_by,expires_at,accepted_at,created_at
		FROM invitations WHERE accepted_at IS NULL AND expires_at>$1 ORDER BY created_at DESC`, now.UTC())
	if err != nil {
		return nil, fmt.Errorf("list PostgreSQL invitations: %w", err)
	}
	defer rows.Close()
	items := []model.Invitation{}
	for rows.Next() {
		item, err := scanPostgreSQLInvitation(rows, true)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgreSQLStore) InvitationByTokenHash(tokenHash []byte, now time.Time) (model.Invitation, error) {
	row := s.db.QueryRow(`SELECT id,email,role,identity_kind,invited_by,expires_at,created_at
		FROM invitations WHERE token_hash=$1 AND accepted_at IS NULL AND expires_at>$2`, tokenHash, now.UTC())
	item, err := scanPostgreSQLInvitation(row, false)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Invitation{}, ErrIdentityNotFound
	}
	if err != nil {
		return model.Invitation{}, err
	}
	item.TokenHash = append([]byte(nil), tokenHash...)
	return item, nil
}

func (s *PostgreSQLStore) AcceptLocalInvitation(invitation model.Invitation, user model.User, passwordHash string,
	mfa model.BootstrapMFA, now time.Time, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL invitation acceptance: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE invitations SET accepted_at=$1 WHERE id=$2 AND token_hash=$3 AND accepted_at IS NULL AND expires_at>$1`,
		now.UTC(), invitation.ID, invitation.TokenHash)
	if err != nil {
		return fmt.Errorf("consume PostgreSQL invitation: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrIdentityNotFound
	}
	_, err = tx.Exec(`INSERT INTO users(id,email,display_name,role,status,password_hash,mfa_required,created_at,updated_at)
		VALUES($1,$2,$3,$4,'active',$5,TRUE,$6,$6)`, user.ID, normalizeEmail(user.Email), user.DisplayName, user.Role, passwordHash, now.UTC())
	if err != nil {
		return fmt.Errorf("create invited PostgreSQL local user: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO totp_credentials(user_id,secret_ciphertext,created_at,verified_at) VALUES($1,$2,$3,$3)`,
		user.ID, mfa.TOTPSecretCiphertext, now.UTC()); err != nil {
		return fmt.Errorf("create invited PostgreSQL user TOTP: %w", err)
	}
	for _, hash := range mfa.RecoveryCodeHashes {
		if _, err := tx.Exec(`INSERT INTO recovery_codes(user_id,code_hash,created_at) VALUES($1,$2,$3)`, user.ID, hash, now.UTC()); err != nil {
			return fmt.Errorf("create invited PostgreSQL recovery code: %w", err)
		}
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func scanPostgreSQLUser(scanner interface{ Scan(...any) error }) (model.User, error) {
	var user model.User
	var lastLogin sql.NullTime
	if err := scanner.Scan(&user.ID, &user.Email, &user.DisplayName, &user.Role, &user.Status, &user.MFARequired,
		&user.CreatedAt, &user.UpdatedAt, &lastLogin); err != nil {
		return user, err
	}
	if lastLogin.Valid {
		value := lastLogin.Time.UTC()
		user.LastLoginAt = &value
	}
	user.CreatedAt = user.CreatedAt.UTC()
	user.UpdatedAt = user.UpdatedAt.UTC()
	return user, nil
}

func scanPostgreSQLInvitation(scanner interface{ Scan(...any) error }, includeAccepted bool) (model.Invitation, error) {
	var item model.Invitation
	if !includeAccepted {
		err := scanner.Scan(&item.ID, &item.Email, &item.Role, &item.IdentityKind, &item.InvitedBy, &item.ExpiresAt, &item.CreatedAt)
		item.ExpiresAt = item.ExpiresAt.UTC()
		item.CreatedAt = item.CreatedAt.UTC()
		return item, err
	}
	var accepted sql.NullTime
	err := scanner.Scan(&item.ID, &item.Email, &item.Role, &item.IdentityKind, &item.InvitedBy, &item.ExpiresAt, &accepted, &item.CreatedAt)
	if accepted.Valid {
		value := accepted.Time.UTC()
		item.AcceptedAt = &value
	}
	item.ExpiresAt = item.ExpiresAt.UTC()
	item.CreatedAt = item.CreatedAt.UTC()
	return item, err
}
