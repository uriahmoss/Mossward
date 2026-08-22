package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"mossward/internal/model"
)

func (s *PostgreSQLStore) UpsertOIDCProvider(record model.OIDCProviderRecord, event model.AuditEvent) error {
	provider := record.Provider
	domains, groups, mappings, err := encodePostgreSQLOIDCPolicy(provider)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL OIDC provider update: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO oidc_providers(id,name,issuer_url,client_id,client_secret_ciphertext,provisioning_mode,
		allowed_tenant_id,allowed_email_domains,allowed_groups,role_mappings,default_role,enabled,redirect_url,tested_at,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9::jsonb,$10::jsonb,$11,FALSE,$12,NULL,$13,$14)
		ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,issuer_url=EXCLUDED.issuer_url,client_id=EXCLUDED.client_id,
		client_secret_ciphertext=EXCLUDED.client_secret_ciphertext,provisioning_mode=EXCLUDED.provisioning_mode,
		allowed_tenant_id=EXCLUDED.allowed_tenant_id,allowed_email_domains=EXCLUDED.allowed_email_domains,
		allowed_groups=EXCLUDED.allowed_groups,role_mappings=EXCLUDED.role_mappings,default_role=EXCLUDED.default_role,
		redirect_url=EXCLUDED.redirect_url,tested_at=NULL,enabled=FALSE,updated_at=EXCLUDED.updated_at`, provider.ID,
		provider.Name, provider.IssuerURL, provider.ClientID, record.ClientSecretCiphertext, provider.ProvisioningMode,
		provider.AllowedTenantID, domains, groups, mappings, provider.DefaultRole, provider.RedirectURL,
		provider.CreatedAt.UTC(), provider.UpdatedAt.UTC())
	if err != nil {
		return fmt.Errorf("store PostgreSQL OIDC provider: %w", err)
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func encodePostgreSQLOIDCPolicy(provider model.OIDCProvider) (string, string, string, error) {
	domains, err := json.Marshal(provider.AllowedEmailDomains)
	if err != nil {
		return "", "", "", fmt.Errorf("encode allowed OIDC email domains: %w", err)
	}
	groups, err := json.Marshal(provider.AllowedGroups)
	if err != nil {
		return "", "", "", fmt.Errorf("encode allowed OIDC groups: %w", err)
	}
	mappings, err := json.Marshal(provider.RoleMappings)
	if err != nil {
		return "", "", "", fmt.Errorf("encode OIDC role mappings: %w", err)
	}
	return string(domains), string(groups), string(mappings), nil
}

func (s *PostgreSQLStore) ListOIDCProviders() ([]model.OIDCProviderRecord, error) {
	rows, err := s.db.Query(postgresOIDCProviderSelect + ` ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list PostgreSQL OIDC providers: %w", err)
	}
	defer rows.Close()
	items := []model.OIDCProviderRecord{}
	for rows.Next() {
		item, err := scanPostgreSQLOIDCProvider(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgreSQLStore) OIDCProvider(id string) (model.OIDCProviderRecord, error) {
	record, err := scanPostgreSQLOIDCProvider(s.db.QueryRow(postgresOIDCProviderSelect+` WHERE id=$1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return model.OIDCProviderRecord{}, ErrIdentityNotFound
	}
	return record, err
}

const postgresOIDCProviderSelect = `SELECT id,name,issuer_url,client_id,client_secret_ciphertext,provisioning_mode,
	allowed_tenant_id,allowed_email_domains,allowed_groups,role_mappings,default_role,enabled,redirect_url,
	tested_at,created_at,updated_at FROM oidc_providers`

func scanPostgreSQLOIDCProvider(scanner interface{ Scan(...any) error }) (model.OIDCProviderRecord, error) {
	var record model.OIDCProviderRecord
	var domains, groups, mappings []byte
	var testedAt sql.NullTime
	provider := &record.Provider
	err := scanner.Scan(&provider.ID, &provider.Name, &provider.IssuerURL, &provider.ClientID, &record.ClientSecretCiphertext,
		&provider.ProvisioningMode, &provider.AllowedTenantID, &domains, &groups, &mappings, &provider.DefaultRole,
		&provider.Enabled, &provider.RedirectURL, &testedAt, &provider.CreatedAt, &provider.UpdatedAt)
	if err != nil {
		return record, err
	}
	if err := json.Unmarshal(domains, &provider.AllowedEmailDomains); err != nil {
		return record, err
	}
	if err := json.Unmarshal(groups, &provider.AllowedGroups); err != nil {
		return record, err
	}
	if err := json.Unmarshal(mappings, &provider.RoleMappings); err != nil {
		return record, err
	}
	provider.CreatedAt = provider.CreatedAt.UTC()
	provider.UpdatedAt = provider.UpdatedAt.UTC()
	if testedAt.Valid {
		value := testedAt.Time.UTC()
		provider.TestedAt = &value
	}
	return record, nil
}

func (s *PostgreSQLStore) MarkOIDCProviderTested(id string, now time.Time, event model.AuditEvent) error {
	return s.updateOIDCProviderState(`UPDATE oidc_providers SET tested_at=$1,updated_at=$1 WHERE id=$2`, []any{now.UTC(), id}, event)
}

func (s *PostgreSQLStore) SetOIDCProviderEnabled(id string, enabled bool, now time.Time, event model.AuditEvent) error {
	query := `UPDATE oidc_providers SET enabled=$1,updated_at=$2 WHERE id=$3 AND ($1=FALSE OR tested_at IS NOT NULL)`
	return s.updateOIDCProviderState(query, []any{enabled, now.UTC(), id}, event)
}

func (s *PostgreSQLStore) updateOIDCProviderState(query string, arguments []any, event model.AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL OIDC provider state update: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.Exec(query, arguments...)
	if err != nil {
		return fmt.Errorf("update PostgreSQL OIDC provider state: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return errors.New("OIDC provider must be tested before it can be enabled")
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgreSQLStore) ResolveOIDCUser(provider model.OIDCProvider, claims model.OIDCClaims, role model.UserRole,
	now time.Time, event model.AuditEvent) (model.User, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return model.User{}, fmt.Errorf("begin PostgreSQL OIDC identity resolution: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtextextended($1,hashtextextended($2,0)))`, provider.ID, claims.Subject); err != nil {
		return model.User{}, fmt.Errorf("lock PostgreSQL OIDC identity: %w", err)
	}
	user, found, err := linkedPostgreSQLOIDCUser(tx, provider.ID, claims.Subject)
	if err != nil {
		return model.User{}, err
	}
	if found {
		return updateLinkedPostgreSQLOIDCUser(tx, provider, claims, user, role, now, event)
	}
	user, err = provisionPostgreSQLOIDCUser(tx, provider, claims, role, now)
	if err != nil {
		return model.User{}, err
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return model.User{}, err
	}
	if err := tx.Commit(); err != nil {
		return model.User{}, fmt.Errorf("commit PostgreSQL OIDC identity resolution: %w", err)
	}
	return user, nil
}

func linkedPostgreSQLOIDCUser(tx *sql.Tx, providerID, subject string) (model.User, bool, error) {
	var user model.User
	err := tx.QueryRow(`SELECT u.id,u.email,u.display_name,u.role,u.status,u.mfa_required,u.created_at,u.updated_at
		FROM external_identities e JOIN users u ON u.id=e.user_id WHERE e.provider_id=$1 AND e.subject=$2 FOR UPDATE OF e,u`,
		providerID, subject).Scan(&user.ID, &user.Email, &user.DisplayName, &user.Role, &user.Status,
		&user.MFARequired, &user.CreatedAt, &user.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.User{}, false, nil
	}
	if err != nil {
		return model.User{}, false, fmt.Errorf("load PostgreSQL external identity: %w", err)
	}
	user.CreatedAt = user.CreatedAt.UTC()
	user.UpdatedAt = user.UpdatedAt.UTC()
	return user, true, nil
}

func updateLinkedPostgreSQLOIDCUser(tx *sql.Tx, provider model.OIDCProvider, claims model.OIDCClaims, user model.User,
	role model.UserRole, now time.Time, event model.AuditEvent) (model.User, error) {
	if user.Status != model.UserActive {
		return model.User{}, ErrIdentityNotFound
	}
	if provider.ProvisioningMode == model.ProvisionJIT && user.Role != role {
		if _, err := tx.Exec(`UPDATE users SET role=$1,updated_at=$2 WHERE id=$3`, role, now.UTC(), user.ID); err != nil {
			return model.User{}, fmt.Errorf("update PostgreSQL group-derived role: %w", err)
		}
		user.Role = role
	}
	if _, err := tx.Exec(`UPDATE external_identities SET last_login_at=$1,tenant_id=$2,email=$3 WHERE provider_id=$4 AND subject=$5`,
		now.UTC(), claims.TenantID, normalizeEmail(claims.Email), provider.ID, claims.Subject); err != nil {
		return model.User{}, fmt.Errorf("update PostgreSQL external identity login: %w", err)
	}
	if err := insertPostgreSQLAuditEvent(tx, event); err != nil {
		return model.User{}, err
	}
	if err := tx.Commit(); err != nil {
		return model.User{}, fmt.Errorf("commit PostgreSQL linked OIDC user: %w", err)
	}
	return user, nil
}

func provisionPostgreSQLOIDCUser(tx *sql.Tx, provider model.OIDCProvider, claims model.OIDCClaims, role model.UserRole, now time.Time) (model.User, error) {
	if provider.ProvisioningMode == model.ProvisionInviteOnly {
		var invitationID string
		err := tx.QueryRow(`SELECT id,role FROM invitations WHERE LOWER(email)=LOWER($1) AND identity_kind='sso'
			AND accepted_at IS NULL AND expires_at>$2 FOR UPDATE`, normalizeEmail(claims.Email), now.UTC()).Scan(&invitationID, &role)
		if errors.Is(err, sql.ErrNoRows) {
			return model.User{}, ErrIdentityNotFound
		}
		if err != nil {
			return model.User{}, fmt.Errorf("load PostgreSQL SSO invitation: %w", err)
		}
		if _, err := tx.Exec(`UPDATE invitations SET accepted_at=$1 WHERE id=$2`, now.UTC(), invitationID); err != nil {
			return model.User{}, fmt.Errorf("consume PostgreSQL SSO invitation: %w", err)
		}
	}
	if claims.UserID == "" {
		return model.User{}, errors.New("OIDC provisioning user ID is required")
	}
	user := model.User{ID: claims.UserID, Email: normalizeEmail(claims.Email), DisplayName: claims.Name, Role: role,
		Status: model.UserActive, MFARequired: true, CreatedAt: now.UTC(), UpdatedAt: now.UTC()}
	_, err := tx.Exec(`INSERT INTO users(id,email,display_name,role,status,password_hash,mfa_required,created_at,updated_at)
		VALUES($1,$2,$3,$4,'active','',TRUE,$5,$5)`, user.ID, user.Email, user.DisplayName, user.Role, now.UTC())
	if err != nil {
		return model.User{}, fmt.Errorf("create PostgreSQL SSO user: %w", err)
	}
	_, err = tx.Exec(`INSERT INTO external_identities(provider_id,subject,user_id,tenant_id,email,created_at,last_login_at)
		VALUES($1,$2,$3,$4,$5,$6,$6)`, provider.ID, claims.Subject, user.ID, claims.TenantID, user.Email, now.UTC())
	if err != nil {
		return model.User{}, fmt.Errorf("link PostgreSQL external identity: %w", err)
	}
	return user, nil
}
