package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"mossward/internal/model"
)

func (s *SQLiteStore) UpsertOIDCProvider(record model.OIDCProviderRecord, event model.AuditEvent) error {
	provider := record.Provider
	domains, err := json.Marshal(provider.AllowedEmailDomains)
	if err != nil {
		return fmt.Errorf("encode allowed OIDC email domains: %w", err)
	}
	groups, err := json.Marshal(provider.AllowedGroups)
	if err != nil {
		return fmt.Errorf("encode allowed OIDC groups: %w", err)
	}
	mappings, err := json.Marshal(provider.RoleMappings)
	if err != nil {
		return fmt.Errorf("encode OIDC role mappings: %w", err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin OIDC provider update: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO oidc_providers(id, name, issuer_url, client_id, client_secret_ciphertext,
		provisioning_mode, allowed_tenant_id, allowed_email_domains, allowed_groups, role_mappings, default_role,
		enabled, redirect_url, tested_at, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name, issuer_url=excluded.issuer_url, client_id=excluded.client_id,
		client_secret_ciphertext=excluded.client_secret_ciphertext, provisioning_mode=excluded.provisioning_mode,
		allowed_tenant_id=excluded.allowed_tenant_id, allowed_email_domains=excluded.allowed_email_domains,
		allowed_groups=excluded.allowed_groups, role_mappings=excluded.role_mappings, default_role=excluded.default_role,
		redirect_url=excluded.redirect_url, tested_at=NULL, enabled=0, updated_at=excluded.updated_at`, provider.ID,
		provider.Name, provider.IssuerURL, provider.ClientID, record.ClientSecretCiphertext, provider.ProvisioningMode,
		provider.AllowedTenantID, domains, groups, mappings, provider.DefaultRole, false, provider.RedirectURL, nil,
		formatTime(provider.CreatedAt), formatTime(provider.UpdatedAt))
	if err != nil {
		return fmt.Errorf("store OIDC provider: %w", err)
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit OIDC provider update: %w", err)
	}
	return nil
}

func (s *SQLiteStore) ListOIDCProviders() ([]model.OIDCProviderRecord, error) {
	rows, err := s.db.Query(oidcProviderSelect + ` ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list OIDC providers: %w", err)
	}
	defer rows.Close()
	items := []model.OIDCProviderRecord{}
	for rows.Next() {
		item, err := scanOIDCProvider(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *SQLiteStore) OIDCProvider(id string) (model.OIDCProviderRecord, error) {
	record, err := scanOIDCProvider(s.db.QueryRow(oidcProviderSelect+` WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return model.OIDCProviderRecord{}, ErrIdentityNotFound
	}
	return record, err
}

const oidcProviderSelect = `SELECT id, name, issuer_url, client_id, client_secret_ciphertext, provisioning_mode,
	allowed_tenant_id, allowed_email_domains, allowed_groups, role_mappings, default_role, enabled, redirect_url,
	tested_at, created_at, updated_at FROM oidc_providers`

func scanOIDCProvider(scanner interface{ Scan(...any) error }) (model.OIDCProviderRecord, error) {
	var record model.OIDCProviderRecord
	var domains, groups, mappings, createdAt, updatedAt string
	var testedAt sql.NullString
	p := &record.Provider
	err := scanner.Scan(&p.ID, &p.Name, &p.IssuerURL, &p.ClientID, &record.ClientSecretCiphertext,
		&p.ProvisioningMode, &p.AllowedTenantID, &domains, &groups, &mappings, &p.DefaultRole, &p.Enabled,
		&p.RedirectURL, &testedAt, &createdAt, &updatedAt)
	if err != nil {
		return model.OIDCProviderRecord{}, err
	}
	if err := json.Unmarshal([]byte(domains), &p.AllowedEmailDomains); err != nil {
		return record, err
	}
	if err := json.Unmarshal([]byte(groups), &p.AllowedGroups); err != nil {
		return record, err
	}
	if err := json.Unmarshal([]byte(mappings), &p.RoleMappings); err != nil {
		return record, err
	}
	if p.CreatedAt, err = parseTime(createdAt); err != nil {
		return record, err
	}
	if p.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return record, err
	}
	if p.TestedAt, err = parseOptionalTime(testedAt); err != nil {
		return record, err
	}
	return record, nil
}

func (s *SQLiteStore) MarkOIDCProviderTested(id string, now time.Time, event model.AuditEvent) error {
	return s.updateOIDCProviderState(`UPDATE oidc_providers SET tested_at=?, updated_at=? WHERE id=?`, []any{formatTime(now), formatTime(now), id}, event)
}

func (s *SQLiteStore) SetOIDCProviderEnabled(id string, enabled bool, now time.Time, event model.AuditEvent) error {
	query := `UPDATE oidc_providers SET enabled=?, updated_at=? WHERE id=? AND (?=0 OR tested_at IS NOT NULL)`
	return s.updateOIDCProviderState(query, []any{enabled, formatTime(now), id, enabled}, event)
}

func (s *SQLiteStore) updateOIDCProviderState(query string, args []any, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec(query, args...)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return errors.New("OIDC provider must be tested before it can be enabled")
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) ResolveOIDCUser(provider model.OIDCProvider, claims model.OIDCClaims, role model.UserRole,
	now time.Time, event model.AuditEvent) (model.User, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return model.User{}, fmt.Errorf("begin OIDC identity resolution: %w", err)
	}
	defer tx.Rollback()
	user, found, err := linkedOIDCUser(tx, provider.ID, claims.Subject)
	if err != nil {
		return model.User{}, err
	}
	if found {
		return updateLinkedOIDCUser(tx, provider, claims, user, role, now, event)
	}
	user, err = provisionOIDCUser(tx, provider, claims, role, now)
	if err != nil {
		return model.User{}, err
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return model.User{}, err
	}
	if err := tx.Commit(); err != nil {
		return model.User{}, err
	}
	return user, nil
}

func updateLinkedOIDCUser(tx *sql.Tx, provider model.OIDCProvider, claims model.OIDCClaims, user model.User,
	role model.UserRole, now time.Time, event model.AuditEvent) (model.User, error) {
	if user.Status != model.UserActive {
		return model.User{}, ErrIdentityNotFound
	}
	if provider.ProvisioningMode == model.ProvisionJIT && user.Role != role {
		if _, err := tx.Exec(`UPDATE users SET role=?, updated_at=? WHERE id=?`, role, formatTime(now), user.ID); err != nil {
			return model.User{}, fmt.Errorf("update group-derived role: %w", err)
		}
		user.Role = role
	}
	if _, err := tx.Exec(`UPDATE external_identities SET last_login_at=?, tenant_id=?, email=?
		WHERE provider_id=? AND subject=?`, formatTime(now), claims.TenantID, normalizeEmail(claims.Email), provider.ID, claims.Subject); err != nil {
		return model.User{}, fmt.Errorf("update external identity login: %w", err)
	}
	if err := insertAuditEvent(tx, event); err != nil {
		return model.User{}, err
	}
	if err := tx.Commit(); err != nil {
		return model.User{}, err
	}
	return user, nil
}

func linkedOIDCUser(tx *sql.Tx, providerID, subject string) (model.User, bool, error) {
	var user model.User
	var createdAt, updatedAt string
	err := tx.QueryRow(`SELECT u.id, u.email, u.display_name, u.role, u.status, u.mfa_required, u.created_at, u.updated_at
		FROM external_identities e JOIN users u ON u.id=e.user_id WHERE e.provider_id=? AND e.subject=?`,
		providerID, subject).Scan(&user.ID, &user.Email, &user.DisplayName, &user.Role, &user.Status,
		&user.MFARequired, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.User{}, false, nil
	}
	if err != nil {
		return model.User{}, false, fmt.Errorf("load external identity: %w", err)
	}
	if user.CreatedAt, err = parseTime(createdAt); err != nil {
		return model.User{}, false, err
	}
	if user.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return model.User{}, false, err
	}
	return user, true, nil
}

func provisionOIDCUser(tx *sql.Tx, provider model.OIDCProvider, claims model.OIDCClaims, role model.UserRole, now time.Time) (model.User, error) {
	if provider.ProvisioningMode == model.ProvisionInviteOnly {
		var invitedRole model.UserRole
		var invitationID string
		err := tx.QueryRow(`SELECT id, role FROM invitations WHERE email=? AND identity_kind='sso' AND accepted_at IS NULL AND expires_at>?`,
			normalizeEmail(claims.Email), formatTime(now)).Scan(&invitationID, &invitedRole)
		if errors.Is(err, sql.ErrNoRows) {
			return model.User{}, ErrIdentityNotFound
		}
		if err != nil {
			return model.User{}, err
		}
		role = invitedRole
		if _, err := tx.Exec(`UPDATE invitations SET accepted_at=? WHERE id=?`, formatTime(now), invitationID); err != nil {
			return model.User{}, err
		}
	}
	if claims.UserID == "" {
		return model.User{}, errors.New("OIDC provisioning user ID is required")
	}
	user := model.User{ID: claims.UserID, Email: normalizeEmail(claims.Email), DisplayName: claims.Name, Role: role,
		Status: model.UserActive, MFARequired: true, CreatedAt: now, UpdatedAt: now}
	_, err := tx.Exec(`INSERT INTO users(id, email, display_name, role, status, password_hash, mfa_required, created_at, updated_at)
		VALUES(?, ?, ?, ?, 'active', '', 1, ?, ?)`, user.ID, user.Email, user.DisplayName, user.Role, formatTime(now), formatTime(now))
	if err != nil {
		return model.User{}, fmt.Errorf("create SSO user: %w", err)
	}
	_, err = tx.Exec(`INSERT INTO external_identities(provider_id, subject, user_id, tenant_id, email, created_at, last_login_at)
		VALUES(?, ?, ?, ?, ?, ?, ?)`, provider.ID, claims.Subject, user.ID, claims.TenantID, user.Email, formatTime(now), formatTime(now))
	if err != nil {
		return model.User{}, fmt.Errorf("link external identity: %w", err)
	}
	return user, nil
}
