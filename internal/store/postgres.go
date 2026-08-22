package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

const (
	postgresFoundationSchemaVersion = 5
	minimumPostgreSQLMajorVersion   = 14
	postgresMigrationLockID         = 713_677_281
)

type PostgreSQLStore struct {
	db *sql.DB
}

func OpenPostgreSQL(ctx context.Context, dataSourceName string) (*PostgreSQLStore, error) {
	if ctx == nil || strings.TrimSpace(dataSourceName) == "" {
		return nil, errors.New("PostgreSQL context and data source are required")
	}
	database, err := sql.Open("pgx", dataSourceName)
	if err != nil {
		return nil, fmt.Errorf("open PostgreSQL: %w", err)
	}
	database.SetMaxOpenConns(20)
	database.SetMaxIdleConns(5)
	database.SetConnMaxLifetime(30 * time.Minute)
	store := &PostgreSQLStore{db: database}
	if err := store.initialize(ctx); err != nil {
		_ = database.Close()
		return nil, err
	}
	return store, nil
}

func (s *PostgreSQLStore) Close() error { return s.db.Close() }

func (s *PostgreSQLStore) Ping(ctx context.Context) error {
	if err := s.db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping PostgreSQL: %w", err)
	}
	return nil
}

func (s *PostgreSQLStore) initialize(ctx context.Context) error {
	if err := s.Ping(ctx); err != nil {
		return err
	}
	var versionText string
	if err := s.db.QueryRowContext(ctx, `SHOW server_version_num`).Scan(&versionText); err != nil {
		return fmt.Errorf("read PostgreSQL version: %w", err)
	}
	version, err := strconv.Atoi(versionText)
	if err != nil || version/10000 < minimumPostgreSQLMajorVersion {
		return fmt.Errorf("PostgreSQL %d or newer is required", minimumPostgreSQLMajorVersion)
	}
	return s.migrate(ctx)
}

func (s *PostgreSQLStore) migrate(ctx context.Context) error {
	organizationID, err := newOrganizationID()
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin PostgreSQL foundation migration: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`SELECT pg_advisory_xact_lock($1)`,
		`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY,applied_at TIMESTAMPTZ NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS installation_organization (singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK(singleton),id TEXT NOT NULL UNIQUE,name TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL)`,
		`CREATE OR REPLACE FUNCTION protect_installation_organization() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'organization identity is immutable'; END $$`,
		`DROP TRIGGER IF EXISTS installation_organization_immutable ON installation_organization`,
		`CREATE TRIGGER installation_organization_immutable BEFORE UPDATE OF id OR DELETE ON installation_organization FOR EACH ROW EXECUTE FUNCTION protect_installation_organization()`,
		`INSERT INTO installation_organization(singleton,id,name,created_at) VALUES(TRUE,$1,$2,$3) ON CONFLICT(singleton) DO NOTHING`,
		`INSERT INTO schema_migrations(version,applied_at) VALUES(1,$1) ON CONFLICT(version) DO NOTHING`,
	}
	if _, err := tx.ExecContext(ctx, statements[0], postgresMigrationLockID); err != nil {
		return fmt.Errorf("lock PostgreSQL migrations: %w", err)
	}
	for _, statement := range statements[1:6] {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("create PostgreSQL foundation schema: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, statements[6], organizationID, defaultOrganizationName, time.Now().UTC()); err != nil {
		return fmt.Errorf("initialize PostgreSQL organization: %w", err)
	}
	if _, err := tx.ExecContext(ctx, statements[7], time.Now().UTC()); err != nil {
		return fmt.Errorf("record PostgreSQL foundation migration: %w", err)
	}
	var version int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&version); err != nil || version > postgresFoundationSchemaVersion {
		return errors.New("PostgreSQL foundation schema is newer than this Mossward build")
	}
	if version < 2 {
		if err := migratePostgreSQLScopePolicies(ctx, tx); err != nil {
			return err
		}
	}
	if version < 3 {
		if err := migratePostgreSQLIdentityAudit(ctx, tx); err != nil {
			return err
		}
	}
	if version < 4 {
		if err := migratePostgreSQLAuthenticationSchema(ctx, tx); err != nil {
			return err
		}
	}
	if version < 5 {
		if err := migratePostgreSQLAuditRetention(ctx, tx); err != nil {
			return err
		}
	}
	var organizations int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM installation_organization`).Scan(&organizations); err != nil || organizations != 1 {
		return errors.New("PostgreSQL installation organization boundary is invalid")
	}
	return tx.Commit()
}

func migratePostgreSQLAuditRetention(ctx context.Context, tx *sql.Tx) error {
	statements := []string{
		`CREATE OR REPLACE FUNCTION protect_audit_events() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF TG_OP='DELETE' AND current_setting('mossward.audit_retention',TRUE)='enabled' THEN RETURN OLD; END IF;
			RAISE EXCEPTION 'audit events are append-only';
		END $$`,
		`CREATE OR REPLACE FUNCTION apply_audit_retention(cutoff TIMESTAMPTZ) RETURNS BIGINT LANGUAGE plpgsql AS $$
		DECLARE removed BIGINT;
		BEGIN
			PERFORM set_config('mossward.audit_retention','enabled',TRUE);
			DELETE FROM audit_events WHERE occurred_at<cutoff;
			GET DIAGNOSTICS removed=ROW_COUNT;
			RETURN removed;
		END $$`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate PostgreSQL audit retention: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(5,$1)`, time.Now().UTC()); err != nil {
		return fmt.Errorf("record PostgreSQL audit-retention migration: %w", err)
	}
	return nil
}

func migratePostgreSQLAuthenticationSchema(ctx context.Context, tx *sql.Tx) error {
	statements := []string{
		`CREATE TABLE invitations (
			id TEXT PRIMARY KEY,email TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('administrator','analyst','viewer')),
			token_hash BYTEA NOT NULL UNIQUE,invited_by TEXT NOT NULL REFERENCES users(id),expires_at TIMESTAMPTZ NOT NULL,
			accepted_at TIMESTAMPTZ,created_at TIMESTAMPTZ NOT NULL,identity_kind TEXT NOT NULL DEFAULT 'local' CHECK(identity_kind IN ('local','sso'))
		)`,
		`CREATE INDEX invitations_email_idx ON invitations(LOWER(email),accepted_at)`,
		`CREATE UNIQUE INDEX invitations_pending_email_idx ON invitations(LOWER(email)) WHERE accepted_at IS NULL`,
		`CREATE TABLE sessions (
			id_hash BYTEA PRIMARY KEY,public_id TEXT NOT NULL UNIQUE,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			created_at TIMESTAMPTZ NOT NULL,expires_at TIMESTAMPTZ NOT NULL,last_seen_at TIMESTAMPTZ NOT NULL,
			mfa_verified_at TIMESTAMPTZ,source_ip TEXT NOT NULL DEFAULT '',user_agent_hash BYTEA
		)`,
		`CREATE INDEX sessions_user_idx ON sessions(user_id,expires_at)`,
		`CREATE TABLE login_attempts (
			key_hash BYTEA PRIMARY KEY,failures INTEGER NOT NULL DEFAULT 0 CHECK(failures>=0),
			window_started_at TIMESTAMPTZ NOT NULL,blocked_until TIMESTAMPTZ
		)`,
		`CREATE TABLE totp_credentials (
			user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,secret_ciphertext BYTEA NOT NULL,
			created_at TIMESTAMPTZ NOT NULL,verified_at TIMESTAMPTZ NOT NULL,last_counter BIGINT NOT NULL DEFAULT -1
		)`,
		`CREATE TABLE recovery_codes (
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,code_hash BYTEA NOT NULL,
			used_at TIMESTAMPTZ,created_at TIMESTAMPTZ NOT NULL,PRIMARY KEY(user_id,code_hash)
		)`,
		`CREATE TABLE webauthn_credentials (
			credential_id BYTEA PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			public_key BYTEA NOT NULL,credential_ciphertext BYTEA,attestation_type TEXT NOT NULL DEFAULT '',
			transports JSONB NOT NULL DEFAULT '[]'::jsonb,sign_count BIGINT NOT NULL DEFAULT 0 CHECK(sign_count>=0),
			backup_eligible BOOLEAN NOT NULL DEFAULT FALSE,backup_state BOOLEAN NOT NULL DEFAULT FALSE,
			name TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL,last_used_at TIMESTAMPTZ
		)`,
		`CREATE INDEX webauthn_credentials_user_idx ON webauthn_credentials(user_id)`,
		`CREATE TABLE authentication_ceremonies (
			id_hash BYTEA PRIMARY KEY,user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
			kind TEXT NOT NULL CHECK(kind IN ('webauthn_register','webauthn_login','oidc')),
			state_ciphertext BYTEA NOT NULL,expires_at TIMESTAMPTZ NOT NULL,created_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE TABLE oidc_providers (
			id TEXT PRIMARY KEY,name TEXT NOT NULL,issuer_url TEXT NOT NULL UNIQUE,client_id TEXT NOT NULL,
			client_secret_ciphertext BYTEA NOT NULL,provisioning_mode TEXT NOT NULL CHECK(provisioning_mode IN ('invite_only','jit')),
			allowed_tenant_id TEXT NOT NULL DEFAULT '',allowed_email_domains JSONB NOT NULL DEFAULT '[]'::jsonb,
			allowed_groups JSONB NOT NULL DEFAULT '[]'::jsonb,role_mappings JSONB NOT NULL DEFAULT '{}'::jsonb,
			default_role TEXT NOT NULL DEFAULT 'viewer' CHECK(default_role IN ('administrator','analyst','viewer')),
			enabled BOOLEAN NOT NULL DEFAULT FALSE,redirect_url TEXT NOT NULL DEFAULT '',tested_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL,updated_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE TABLE external_identities (
			provider_id TEXT NOT NULL REFERENCES oidc_providers(id) ON DELETE CASCADE,subject TEXT NOT NULL,
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,tenant_id TEXT NOT NULL DEFAULT '',
			email TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL,last_login_at TIMESTAMPTZ,
			PRIMARY KEY(provider_id,subject),UNIQUE(provider_id,user_id)
		)`,
		`CREATE INDEX external_identities_email_idx ON external_identities(LOWER(email))`,
		`CREATE TABLE app_metadata (key TEXT PRIMARY KEY,value TEXT NOT NULL)`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate PostgreSQL authentication schema: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(4,$1)`, time.Now().UTC()); err != nil {
		return fmt.Errorf("record PostgreSQL authentication migration: %w", err)
	}
	return nil
}

func migratePostgreSQLIdentityAudit(ctx context.Context, tx *sql.Tx) error {
	statements := []string{
		`CREATE TABLE users (
			id TEXT PRIMARY KEY,email TEXT NOT NULL,display_name TEXT NOT NULL,
			role TEXT NOT NULL CHECK(role IN ('administrator','analyst','viewer')),
			status TEXT NOT NULL CHECK(status IN ('invited','active','disabled')),
			password_hash TEXT NOT NULL DEFAULT '',mfa_required BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMPTZ NOT NULL,updated_at TIMESTAMPTZ NOT NULL,last_login_at TIMESTAMPTZ
		)`,
		`CREATE UNIQUE INDEX users_email_normalized_idx ON users(LOWER(email))`,
		`CREATE TABLE audit_events (
			id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,occurred_at TIMESTAMPTZ NOT NULL,
			actor_id TEXT REFERENCES users(id) ON DELETE SET NULL,action TEXT NOT NULL,
			severity TEXT NOT NULL CHECK(severity IN ('info','warning','error')),
			target_type TEXT NOT NULL DEFAULT '',target_id TEXT NOT NULL DEFAULT '',
			source_ip TEXT NOT NULL DEFAULT '',details JSONB NOT NULL DEFAULT '{}'::jsonb
		)`,
		`CREATE INDEX audit_events_time_idx ON audit_events(occurred_at DESC)`,
		`CREATE OR REPLACE FUNCTION protect_audit_events() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit events are append-only'; END $$`,
		`CREATE TRIGGER audit_events_append_only BEFORE UPDATE OR DELETE ON audit_events FOR EACH ROW EXECUTE FUNCTION protect_audit_events()`,
		`ALTER TABLE scope_policies ADD CONSTRAINT scope_policies_created_by_fk FOREIGN KEY(created_by) REFERENCES users(id)`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate PostgreSQL identity and audit schema: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(3,$1)`, time.Now().UTC()); err != nil {
		return fmt.Errorf("record PostgreSQL identity and audit migration: %w", err)
	}
	return nil
}

func migratePostgreSQLScopePolicies(ctx context.Context, tx *sql.Tx) error {
	statements := []string{
		`CREATE TABLE scope_policies (
			id TEXT PRIMARY KEY,
			organization_id TEXT NOT NULL REFERENCES installation_organization(id),
			name TEXT NOT NULL,
			allowed_cidrs JSONB NOT NULL,
			allowed_ports JSONB NOT NULL,
			max_targets INTEGER NOT NULL CHECK(max_targets>0),
			max_concurrent INTEGER NOT NULL CHECK(max_concurrent>0),
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			created_by TEXT,
			created_at TIMESTAMPTZ NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL,
			UNIQUE(organization_id,name)
		)`,
		`CREATE INDEX scope_policies_organization_idx ON scope_policies(organization_id,name)`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate PostgreSQL scope policies: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(2,$1)`, time.Now().UTC()); err != nil {
		return fmt.Errorf("record PostgreSQL scope-policy migration: %w", err)
	}
	return nil
}
