package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"mossward/internal/model"
)

func (s *SQLiteStore) ListUsers() ([]model.User, error) {
	rows, err := s.db.Query(`SELECT id, email, display_name, role, status, mfa_required, created_at, updated_at, last_login_at
		FROM users ORDER BY email`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()
	users := []model.User{}
	for rows.Next() {
		var user model.User
		var created, updated string
		var lastLogin sql.NullString
		if err := rows.Scan(&user.ID, &user.Email, &user.DisplayName, &user.Role, &user.Status,
			&user.MFARequired, &created, &updated, &lastLogin); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		if user.CreatedAt, err = parseTime(created); err != nil {
			return nil, err
		}
		if user.UpdatedAt, err = parseTime(updated); err != nil {
			return nil, err
		}
		if user.LastLoginAt, err = parseOptionalTime(lastLogin); err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

func (s *SQLiteStore) UpdateUserAccess(userID string, role model.UserRole, status model.UserStatus, now time.Time, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin user access update: %w", err)
	}
	defer tx.Rollback()
	var currentRole model.UserRole
	var currentStatus model.UserStatus
	var passwordHash string
	if err := tx.QueryRow(`SELECT role, status, password_hash FROM users WHERE id=?`, userID).Scan(&currentRole, &currentStatus, &passwordHash); errors.Is(err, sql.ErrNoRows) {
		return ErrIdentityNotFound
	} else if err != nil {
		return fmt.Errorf("load user access: %w", err)
	}
	removesLocalAdmin := currentRole == model.RoleAdministrator && currentStatus == model.UserActive && passwordHash != "" &&
		(role != model.RoleAdministrator || status != model.UserActive)
	if removesLocalAdmin {
		var count int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM users WHERE role='administrator' AND status='active' AND password_hash<>''`).Scan(&count); err != nil {
			return fmt.Errorf("count local administrators: %w", err)
		}
		if count <= 1 {
			return ErrFinalAdministrator
		}
	}
	if _, err := tx.Exec(`UPDATE users SET role=?, status=?, updated_at=? WHERE id=?`, role, status, formatTime(now), userID); err != nil {
		return fmt.Errorf("update user access: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM sessions WHERE user_id=?`, userID); err != nil {
		return fmt.Errorf("revoke changed user sessions: %w", err)
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit user access update: %w", err)
	}
	return nil
}

func (s *SQLiteStore) CreateInvitation(invitation model.Invitation, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin invitation creation: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO invitations(id, email, role, token_hash, invited_by, expires_at, created_at, identity_kind)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?)`, invitation.ID, normalizeEmail(invitation.Email), invitation.Role,
		invitation.TokenHash, invitation.InvitedBy, formatTime(invitation.ExpiresAt), formatTime(invitation.CreatedAt), invitation.IdentityKind)
	if err != nil {
		return fmt.Errorf("create invitation: %w", err)
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit invitation creation: %w", err)
	}
	return nil
}

func (s *SQLiteStore) ListInvitations(now time.Time) ([]model.Invitation, error) {
	rows, err := s.db.Query(`SELECT id, email, role, identity_kind, invited_by, expires_at, accepted_at, created_at
		FROM invitations WHERE accepted_at IS NULL AND expires_at>? ORDER BY created_at DESC`, formatTime(now))
	if err != nil {
		return nil, fmt.Errorf("list invitations: %w", err)
	}
	defer rows.Close()
	items := []model.Invitation{}
	for rows.Next() {
		var item model.Invitation
		var expiresAt, createdAt string
		var acceptedAt sql.NullString
		if err := rows.Scan(&item.ID, &item.Email, &item.Role, &item.IdentityKind, &item.InvitedBy,
			&expiresAt, &acceptedAt, &createdAt); err != nil {
			return nil, fmt.Errorf("scan invitation: %w", err)
		}
		if item.ExpiresAt, err = parseTime(expiresAt); err != nil {
			return nil, err
		}
		if item.CreatedAt, err = parseTime(createdAt); err != nil {
			return nil, err
		}
		if item.AcceptedAt, err = parseOptionalTime(acceptedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *SQLiteStore) InvitationByTokenHash(tokenHash []byte, now time.Time) (model.Invitation, error) {
	var item model.Invitation
	var expiresAt, createdAt string
	err := s.db.QueryRow(`SELECT id, email, role, identity_kind, invited_by, expires_at, created_at
		FROM invitations WHERE token_hash=? AND accepted_at IS NULL AND expires_at>?`, tokenHash, formatTime(now)).Scan(
		&item.ID, &item.Email, &item.Role, &item.IdentityKind, &item.InvitedBy, &expiresAt, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Invitation{}, ErrIdentityNotFound
	}
	if err != nil {
		return model.Invitation{}, fmt.Errorf("load invitation: %w", err)
	}
	item.TokenHash = tokenHash
	if item.ExpiresAt, err = parseTime(expiresAt); err != nil {
		return model.Invitation{}, err
	}
	if item.CreatedAt, err = parseTime(createdAt); err != nil {
		return model.Invitation{}, err
	}
	return item, nil
}

func (s *SQLiteStore) AcceptLocalInvitation(invitation model.Invitation, user model.User, passwordHash string,
	mfa model.BootstrapMFA, now time.Time, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin invitation acceptance: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE invitations SET accepted_at=? WHERE id=? AND token_hash=? AND accepted_at IS NULL AND expires_at>?`,
		formatTime(now), invitation.ID, invitation.TokenHash, formatTime(now))
	if err != nil {
		return fmt.Errorf("consume invitation: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrIdentityNotFound
	}
	_, err = tx.Exec(`INSERT INTO users(id, email, display_name, role, status, password_hash, mfa_required, created_at, updated_at)
		VALUES(?, ?, ?, ?, 'active', ?, 1, ?, ?)`, user.ID, normalizeEmail(user.Email), user.DisplayName, user.Role,
		passwordHash, formatTime(now), formatTime(now))
	if err != nil {
		return fmt.Errorf("create invited local user: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO totp_credentials(user_id, secret_ciphertext, created_at, verified_at) VALUES(?, ?, ?, ?)`,
		user.ID, mfa.TOTPSecretCiphertext, formatTime(now), formatTime(now)); err != nil {
		return fmt.Errorf("create invited user TOTP: %w", err)
	}
	for _, hash := range mfa.RecoveryCodeHashes {
		if _, err := tx.Exec(`INSERT INTO recovery_codes(user_id, code_hash, created_at) VALUES(?, ?, ?)`, user.ID, hash, formatTime(now)); err != nil {
			return fmt.Errorf("create invited user recovery code: %w", err)
		}
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit invitation acceptance: %w", err)
	}
	return nil
}
