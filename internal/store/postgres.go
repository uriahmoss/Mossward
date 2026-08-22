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
	postgresFoundationSchemaVersion = 9
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
	if version < 6 {
		if err := migratePostgreSQLNotifications(ctx, tx); err != nil {
			return err
		}
	}
	if version < 7 {
		if err := migratePostgreSQLScanFoundation(ctx, tx); err != nil {
			return err
		}
	}
	if version < 8 {
		if err := migratePostgreSQLIntelligence(ctx, tx); err != nil {
			return err
		}
	}
	if version < 9 {
		if err := migratePostgreSQLAssetFoundation(ctx, tx); err != nil {
			return err
		}
	}
	var organizations int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM installation_organization`).Scan(&organizations); err != nil || organizations != 1 {
		return errors.New("PostgreSQL installation organization boundary is invalid")
	}
	return tx.Commit()
}

func migratePostgreSQLAssetFoundation(ctx context.Context, tx *sql.Tx) error {
	statements := []string{
		`CREATE TABLE assets (
			id TEXT PRIMARY KEY,name TEXT NOT NULL,address TEXT NOT NULL UNIQUE,first_seen TIMESTAMPTZ NOT NULL,
			last_seen TIMESTAMPTZ NOT NULL,last_scan_id TEXT NOT NULL,owner TEXT NOT NULL DEFAULT '',
			environment TEXT NOT NULL DEFAULT '',classification TEXT NOT NULL DEFAULT '',
			lifecycle_status TEXT NOT NULL DEFAULT 'active' CHECK(lifecycle_status IN ('active','retired')),
			retired_at TIMESTAMPTZ,retired_by TEXT NOT NULL DEFAULT '',retirement_reason TEXT NOT NULL DEFAULT '',
			agent_eligibility TEXT NOT NULL DEFAULT 'unknown' CHECK(agent_eligibility IN ('unknown','eligible','ineligible')),
			agent_eligibility_reason TEXT NOT NULL DEFAULT '',agent_eligibility_updated_by TEXT NOT NULL DEFAULT '',
			agent_eligibility_updated_at TIMESTAMPTZ
		)`,
		`CREATE INDEX assets_last_seen_idx ON assets(last_seen DESC)`,
		`CREATE INDEX assets_lifecycle_last_seen_idx ON assets(lifecycle_status,last_seen DESC)`,
		`CREATE TABLE asset_addresses (
			asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,address TEXT NOT NULL UNIQUE,
			first_seen TIMESTAMPTZ NOT NULL,last_seen TIMESTAMPTZ NOT NULL,last_scan_id TEXT NOT NULL,
			PRIMARY KEY(asset_id,address)
		)`,
		`CREATE INDEX asset_addresses_asset_idx ON asset_addresses(asset_id,last_seen DESC)`,
		`CREATE TABLE asset_names (
			asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,name TEXT NOT NULL,normalized_name TEXT NOT NULL UNIQUE,
			PRIMARY KEY(asset_id,normalized_name)
		)`,
		`CREATE INDEX asset_names_asset_idx ON asset_names(asset_id,name)`,
		`CREATE TABLE asset_services (
			asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,address TEXT NOT NULL,
			port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),protocol TEXT NOT NULL,product TEXT NOT NULL DEFAULT '',
			version TEXT NOT NULL DEFAULT '',confidence TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('observed','not_observed')),
			first_seen TIMESTAMPTZ NOT NULL,last_seen TIMESTAMPTZ NOT NULL,last_checked TIMESTAMPTZ NOT NULL,
			last_scan_id TEXT NOT NULL,observation_count INTEGER NOT NULL CHECK(observation_count >= 0),
			PRIMARY KEY(asset_id,address,port,protocol)
		)`,
		`CREATE INDEX asset_services_asset_state_idx ON asset_services(asset_id,state,last_seen DESC)`,
		`CREATE TABLE asset_service_events (
			observation_id TEXT PRIMARY KEY,asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
			scan_id TEXT NOT NULL,address TEXT NOT NULL,port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
			protocol TEXT NOT NULL,product TEXT NOT NULL DEFAULT '',version TEXT NOT NULL DEFAULT '',confidence TEXT NOT NULL,
			observed_at TIMESTAMPTZ NOT NULL,finding_ids JSONB NOT NULL DEFAULT '[]'::jsonb,cve_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
			source_type TEXT NOT NULL DEFAULT 'scanner' CHECK(source_type IN ('scanner','endpoint')),
			source_id TEXT NOT NULL DEFAULT 'scanner/local'
		)`,
		`CREATE INDEX asset_service_events_lookup_idx ON asset_service_events(asset_id,address,port,protocol,observed_at DESC)`,
		`CREATE TABLE asset_evidence (
			id TEXT PRIMARY KEY,asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
			source_type TEXT NOT NULL CHECK(source_type IN ('scanner','endpoint')),source_id TEXT NOT NULL,
			record_type TEXT NOT NULL,record_id TEXT NOT NULL,scan_id TEXT NOT NULL DEFAULT '',address TEXT NOT NULL DEFAULT '',
			summary TEXT NOT NULL,collected_at TIMESTAMPTZ NOT NULL,UNIQUE(source_type,source_id,record_type,record_id)
		)`,
		`CREATE INDEX asset_evidence_asset_time_idx ON asset_evidence(asset_id,collected_at DESC)`,
		`CREATE TABLE asset_aging_settings (
			singleton SMALLINT PRIMARY KEY CHECK(singleton=1),
			stale_after_days INTEGER NOT NULL CHECK(stale_after_days BETWEEN 1 AND 3650)
		)`,
		`INSERT INTO asset_aging_settings(singleton,stale_after_days) VALUES(1,30)`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate PostgreSQL asset foundation: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(9,$1)`, time.Now().UTC()); err != nil {
		return fmt.Errorf("record PostgreSQL asset-foundation migration: %w", err)
	}
	return nil
}

func migratePostgreSQLIntelligence(ctx context.Context, tx *sql.Tx) error {
	statements := []string{
		`CREATE TABLE cves (
			id TEXT PRIMARY KEY,description TEXT NOT NULL,published_at TIMESTAMPTZ NOT NULL,modified_at TIMESTAMPTZ NOT NULL,
			cvss_score DOUBLE PRECISION NOT NULL DEFAULT 0,cvss_vector TEXT NOT NULL DEFAULT '',severity TEXT NOT NULL,
			known_exploited BOOLEAN NOT NULL DEFAULT FALSE,source_url TEXT NOT NULL
		)`,
		`CREATE INDEX cves_news_idx ON cves(severity,known_exploited,published_at DESC)`,
		`CREATE TABLE cve_products (
			cve_id TEXT NOT NULL REFERENCES cves(id) ON DELETE CASCADE,ordinal INTEGER NOT NULL,cpe23 TEXT NOT NULL,
			part TEXT NOT NULL,vendor TEXT NOT NULL,product TEXT NOT NULL,version TEXT NOT NULL DEFAULT '',
			version_start_including TEXT NOT NULL DEFAULT '',version_start_excluding TEXT NOT NULL DEFAULT '',
			version_end_including TEXT NOT NULL DEFAULT '',version_end_excluding TEXT NOT NULL DEFAULT '',
			vulnerable BOOLEAN NOT NULL,PRIMARY KEY(cve_id,ordinal)
		)`,
		`CREATE INDEX cve_products_lookup_idx ON cve_products(vendor,product,vulnerable)`,
		`CREATE TABLE cve_references (
			cve_id TEXT NOT NULL REFERENCES cves(id) ON DELETE CASCADE,ordinal INTEGER NOT NULL,
			url TEXT NOT NULL,source TEXT NOT NULL DEFAULT '',PRIMARY KEY(cve_id,ordinal)
		)`,
		`CREATE TABLE cve_matches (
			scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
			observation_id TEXT NOT NULL REFERENCES service_observations(id) ON DELETE CASCADE,
			cve_id TEXT NOT NULL REFERENCES cves(id) ON DELETE CASCADE,ordinal INTEGER NOT NULL,target TEXT NOT NULL,
			address TEXT NOT NULL,port INTEGER NOT NULL,product TEXT NOT NULL,version TEXT NOT NULL,
			confidence TEXT NOT NULL,evidence TEXT NOT NULL,matched_at TIMESTAMPTZ NOT NULL,
			PRIMARY KEY(scan_id,observation_id,cve_id)
		)`,
		`CREATE INDEX cve_matches_cve_idx ON cve_matches(cve_id)`,
		`CREATE TABLE feed_sync_status (
			source TEXT PRIMARY KEY,status TEXT NOT NULL,last_started TIMESTAMPTZ,last_success TIMESTAMPTZ,
			records INTEGER NOT NULL DEFAULT 0,error TEXT NOT NULL DEFAULT ''
		)`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate PostgreSQL intelligence: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(8,$1)`, time.Now().UTC()); err != nil {
		return fmt.Errorf("record PostgreSQL intelligence migration: %w", err)
	}
	return nil
}

func migratePostgreSQLScanFoundation(ctx context.Context, tx *sql.Tx) error {
	statements := []string{
		`CREATE TABLE scans (
			id TEXT PRIMARY KEY,name TEXT NOT NULL,status TEXT NOT NULL,error TEXT NOT NULL DEFAULT '',
			total_checks INTEGER NOT NULL DEFAULT 0,done_checks INTEGER NOT NULL DEFAULT 0,
			created_at TIMESTAMPTZ NOT NULL,started_at TIMESTAMPTZ,completed_at TIMESTAMPTZ,
			scope_policy_id TEXT NOT NULL DEFAULT '',max_concurrent INTEGER NOT NULL DEFAULT 1 CHECK(max_concurrent > 0),
			scan_policy_id TEXT NOT NULL DEFAULT '',active_seconds BIGINT NOT NULL DEFAULT 0 CHECK(active_seconds >= 0),
			window_end TIMESTAMPTZ,long_alert_sent BOOLEAN NOT NULL DEFAULT FALSE,
			rate_limit_per_second INTEGER NOT NULL DEFAULT 0 CHECK(rate_limit_per_second BETWEEN 0 AND 1000)
		)`,
		`CREATE INDEX scans_created_at_idx ON scans(created_at DESC)`,
		`CREATE TABLE scan_targets (
			scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,ordinal INTEGER NOT NULL,
			name TEXT NOT NULL,address TEXT NOT NULL,group_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
			PRIMARY KEY(scan_id,ordinal)
		)`,
		`CREATE INDEX scan_targets_address_idx ON scan_targets(address)`,
		`CREATE TABLE scan_ports (
			scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,ordinal INTEGER NOT NULL,
			port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),PRIMARY KEY(scan_id,ordinal)
		)`,
		`CREATE TABLE service_observations (
			id TEXT PRIMARY KEY,scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,ordinal INTEGER NOT NULL,
			target TEXT NOT NULL,address TEXT NOT NULL,port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
			protocol TEXT NOT NULL,product TEXT NOT NULL DEFAULT '',version TEXT NOT NULL DEFAULT '',
			confidence TEXT NOT NULL,evidence TEXT NOT NULL,observed_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE INDEX observations_product_version_idx ON service_observations(product,version)`,
		`CREATE INDEX observations_scan_idx ON service_observations(scan_id,ordinal)`,
		`CREATE TABLE observation_metadata (
			observation_id TEXT NOT NULL REFERENCES service_observations(id) ON DELETE CASCADE,
			key TEXT NOT NULL,value TEXT NOT NULL,PRIMARY KEY(observation_id,key)
		)`,
		`CREATE TABLE findings (
			id TEXT PRIMARY KEY,scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,ordinal INTEGER NOT NULL,
			check_id TEXT NOT NULL,target TEXT NOT NULL,address TEXT NOT NULL,port INTEGER NOT NULL,
			service TEXT NOT NULL,severity TEXT NOT NULL,title TEXT NOT NULL,evidence TEXT NOT NULL,
			remediation TEXT NOT NULL,observed_at TIMESTAMPTZ NOT NULL,status TEXT NOT NULL DEFAULT 'open'
				CHECK(status IN ('open','in_progress','resolved')),assigned_to TEXT,workflow_updated_at TIMESTAMPTZ
		)`,
		`CREATE INDEX findings_scan_idx ON findings(scan_id,ordinal)`,
		`CREATE INDEX findings_check_severity_idx ON findings(check_id,severity)`,
		`CREATE TABLE scan_checkpoints (
			scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,address TEXT NOT NULL,
			port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),completed_at TIMESTAMPTZ NOT NULL,
			PRIMARY KEY(scan_id,address,port)
		)`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate PostgreSQL scan foundation: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(7,$1)`, time.Now().UTC()); err != nil {
		return fmt.Errorf("record PostgreSQL scan-foundation migration: %w", err)
	}
	return nil
}

func migratePostgreSQLNotifications(ctx context.Context, tx *sql.Tx) error {
	statements := []string{
		`CREATE TABLE smtp_settings (
			id SMALLINT PRIMARY KEY CHECK(id=1),enabled BOOLEAN NOT NULL,host TEXT NOT NULL,
			port INTEGER NOT NULL CHECK(port BETWEEN 0 AND 65535),username TEXT NOT NULL,password_ciphertext BYTEA,
			from_address TEXT NOT NULL,tls_mode TEXT NOT NULL
		)`,
		`CREATE TABLE smtp_recipients (user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE)`,
		`CREATE TABLE scan_long_alerts (scan_id TEXT PRIMARY KEY,sent_at TIMESTAMPTZ NOT NULL)`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate PostgreSQL notifications: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(6,$1)`, time.Now().UTC()); err != nil {
		return fmt.Errorf("record PostgreSQL notification migration: %w", err)
	}
	return nil
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
