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
	postgresFoundationSchemaVersion = 19
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
	if version < 10 {
		if err := migratePostgreSQLAssetGroups(ctx, tx); err != nil {
			return err
		}
	}
	if version < 11 {
		if err := migratePostgreSQLReporting(ctx, tx); err != nil {
			return err
		}
	}
	if version < 12 {
		if err := migratePostgreSQLEndpointFoundation(ctx, tx); err != nil {
			return err
		}
	}
	if version < 13 {
		if err := migratePostgreSQLEndpointInventory(ctx, tx); err != nil {
			return err
		}
	}
	if version < 14 {
		if err := migratePostgreSQLEndpointListeningPosture(ctx, tx); err != nil {
			return err
		}
	}
	if version < 15 {
		if err := migratePostgreSQLEndpointNetwork(ctx, tx); err != nil {
			return err
		}
	}
	if version < 16 {
		if err := migratePostgreSQLEndpointIntegrity(ctx, tx); err != nil {
			return err
		}
	}
	if version < 17 {
		if err := migratePostgreSQLAgentUpdates(ctx, tx); err != nil {
			return err
		}
	}
	if version < 18 {
		if err := migratePostgreSQLScannerWorkers(ctx, tx); err != nil {
			return err
		}
	}
	if version < 19 {
		if err := migratePostgreSQLAgentModules(ctx, tx); err != nil {
			return err
		}
	}
	var organizations int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM installation_organization`).Scan(&organizations); err != nil || organizations != 1 {
		return errors.New("PostgreSQL installation organization boundary is invalid")
	}
	return tx.Commit()
}

func migratePostgreSQLAgentUpdates(ctx context.Context, tx *sql.Tx) error {
	statements := []string{
		`CREATE TABLE agent_update_releases (
			id TEXT PRIMARY KEY,version TEXT NOT NULL,operating_system TEXT NOT NULL,architecture TEXT NOT NULL,
			artifact_sha256 TEXT NOT NULL,artifact_size BIGINT NOT NULL CHECK(artifact_size >= 0),signing_key_id TEXT NOT NULL,
			envelope BYTEA NOT NULL,status TEXT NOT NULL CHECK(status IN ('staged','approved','revoked')),
			created_by TEXT NOT NULL REFERENCES users(id),created_at TIMESTAMPTZ NOT NULL,
			approved_by TEXT REFERENCES users(id),approved_at TIMESTAMPTZ,revoked_by TEXT REFERENCES users(id),
			revoked_at TIMESTAMPTZ,revocation_reason TEXT NOT NULL DEFAULT '',UNIQUE(version,operating_system,architecture)
		)`,
		`CREATE INDEX agent_update_releases_status_idx ON agent_update_releases(status,operating_system,architecture,created_at DESC)`,
		`CREATE TABLE agent_update_assignments (
			endpoint_id TEXT PRIMARY KEY REFERENCES endpoints(id) ON DELETE CASCADE,
			release_id TEXT NOT NULL REFERENCES agent_update_releases(id),
			status TEXT NOT NULL CHECK(status IN ('assigned','offered','installed')),
			assigned_by TEXT NOT NULL REFERENCES users(id),assigned_at TIMESTAMPTZ NOT NULL,
			offered_at TIMESTAMPTZ,installed_at TIMESTAMPTZ
		)`,
		`CREATE INDEX agent_update_assignments_release_idx ON agent_update_assignments(release_id,status)`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate PostgreSQL agent updates: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(17,$1)`, time.Now().UTC()); err != nil {
		return fmt.Errorf("record PostgreSQL agent-update migration: %w", err)
	}
	return nil
}

func migratePostgreSQLEndpointIntegrity(ctx context.Context, tx *sql.Tx) error {
	statements := []string{
		`CREATE TABLE endpoint_integrity_snapshots (
			endpoint_id TEXT PRIMARY KEY REFERENCES endpoints(id) ON DELETE CASCADE,executable_sha256 TEXT NOT NULL,
			configuration_sha256 TEXT NOT NULL,identity_sha256 TEXT NOT NULL,observed_at TIMESTAMPTZ NOT NULL,
			received_at TIMESTAMPTZ NOT NULL,sequence BIGINT NOT NULL DEFAULT 0 CHECK(sequence >= 0),signature TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE endpoint_integrity_events (
			id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
			component TEXT NOT NULL CHECK(component IN ('executable','configuration','identity')),
			previous_sha256 TEXT NOT NULL,current_sha256 TEXT NOT NULL,observed_at TIMESTAMPTZ NOT NULL,
			received_at TIMESTAMPTZ NOT NULL,sequence BIGINT NOT NULL DEFAULT 0 CHECK(sequence >= 0),signature TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX endpoint_integrity_events_endpoint_idx ON endpoint_integrity_events(endpoint_id,received_at DESC,id DESC)`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate PostgreSQL endpoint integrity: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(16,$1)`, time.Now().UTC()); err != nil {
		return fmt.Errorf("record PostgreSQL endpoint-integrity migration: %w", err)
	}
	return nil
}

func migratePostgreSQLEndpointNetwork(ctx context.Context, tx *sql.Tx) error {
	statements := []string{
		`CREATE TABLE endpoint_network_inventory (
			endpoint_id TEXT PRIMARY KEY REFERENCES endpoints(id) ON DELETE CASCADE,
			collected_at TIMESTAMPTZ NOT NULL,received_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE TABLE endpoint_network_connections (
			endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,ordinal INTEGER NOT NULL,
			protocol TEXT NOT NULL,local_address TEXT NOT NULL,local_port INTEGER NOT NULL,remote_address TEXT NOT NULL,
			remote_port INTEGER NOT NULL,process_id INTEGER NOT NULL,process_name TEXT NOT NULL,direction TEXT NOT NULL,
			executable TEXT NOT NULL DEFAULT '',remote_hostname TEXT NOT NULL DEFAULT '',hostname_source TEXT NOT NULL DEFAULT '',
			tls_server_name TEXT NOT NULL DEFAULT '',PRIMARY KEY(endpoint_id,ordinal)
		)`,
		`CREATE INDEX endpoint_network_remote_idx ON endpoint_network_connections(remote_address,remote_port)`,
		`CREATE TABLE threat_indicators (
			id TEXT PRIMARY KEY,type TEXT NOT NULL CHECK(type IN ('ip','hostname')),value TEXT NOT NULL,source TEXT NOT NULL,
			confidence TEXT NOT NULL CHECK(confidence IN ('low','medium','high')),observed_at TIMESTAMPTZ NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL,enabled BOOLEAN NOT NULL,created_by TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL,updated_at TIMESTAMPTZ NOT NULL,UNIQUE(type,value,source)
		)`,
		`CREATE INDEX threat_indicators_active_idx ON threat_indicators(enabled,expires_at,type,value)`,
		`CREATE TABLE endpoint_indicator_matches (
			endpoint_id TEXT NOT NULL,indicator_id TEXT NOT NULL REFERENCES threat_indicators(id) ON DELETE CASCADE,
			connection_ordinal INTEGER NOT NULL,matched_at TIMESTAMPTZ NOT NULL,
			PRIMARY KEY(endpoint_id,indicator_id,connection_ordinal),
			FOREIGN KEY(endpoint_id,connection_ordinal) REFERENCES endpoint_network_connections(endpoint_id,ordinal) ON DELETE CASCADE
		)`,
		`CREATE INDEX endpoint_indicator_matches_endpoint_idx ON endpoint_indicator_matches(endpoint_id,matched_at)`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate PostgreSQL endpoint network inventory: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(15,$1)`, time.Now().UTC()); err != nil {
		return fmt.Errorf("record PostgreSQL endpoint network migration: %w", err)
	}
	return nil
}

func migratePostgreSQLEndpointListeningPosture(ctx context.Context, tx *sql.Tx) error {
	statements := []string{
		`CREATE TABLE endpoint_listening_inventory (
			endpoint_id TEXT PRIMARY KEY REFERENCES endpoints(id) ON DELETE CASCADE,
			collected_at TIMESTAMPTZ NOT NULL,received_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE TABLE endpoint_listening_services (
			endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,ordinal INTEGER NOT NULL,
			protocol TEXT NOT NULL,address TEXT NOT NULL,port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
			process_id INTEGER NOT NULL,process_name TEXT NOT NULL,executable TEXT NOT NULL,
			PRIMARY KEY(endpoint_id,ordinal)
		)`,
		`CREATE INDEX endpoint_listening_service_lookup_idx ON endpoint_listening_services(protocol,port,process_name)`,
		`CREATE TABLE endpoint_posture_inventory (
			endpoint_id TEXT PRIMARY KEY REFERENCES endpoints(id) ON DELETE CASCADE,
			collected_at TIMESTAMPTZ NOT NULL,received_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE TABLE endpoint_posture_evidence (
			endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,evidence_id TEXT NOT NULL,
			title TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN ('pass','fail','unknown')),detail TEXT NOT NULL,
			PRIMARY KEY(endpoint_id,evidence_id)
		)`,
		`CREATE INDEX endpoint_posture_status_idx ON endpoint_posture_evidence(status,evidence_id)`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate PostgreSQL endpoint listening and posture inventory: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(14,$1)`, time.Now().UTC()); err != nil {
		return fmt.Errorf("record PostgreSQL endpoint listening/posture migration: %w", err)
	}
	return nil
}

func migratePostgreSQLEndpointInventory(ctx context.Context, tx *sql.Tx) error {
	statements := []string{
		`CREATE TABLE endpoint_os_inventory (
			endpoint_id TEXT PRIMARY KEY REFERENCES endpoints(id) ON DELETE CASCADE,family TEXT NOT NULL,name TEXT NOT NULL,
			version TEXT NOT NULL,build TEXT NOT NULL,kernel TEXT NOT NULL,architecture TEXT NOT NULL,
			collected_at TIMESTAMPTZ NOT NULL,received_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE TABLE endpoint_os_patches (
			endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,patch_id TEXT NOT NULL,
			description TEXT NOT NULL,installed_at TIMESTAMPTZ,PRIMARY KEY(endpoint_id,patch_id)
		)`,
		`CREATE INDEX endpoint_os_inventory_received_idx ON endpoint_os_inventory(received_at DESC)`,
		`CREATE TABLE endpoint_software_inventory (
			endpoint_id TEXT PRIMARY KEY REFERENCES endpoints(id) ON DELETE CASCADE,
			collected_at TIMESTAMPTZ NOT NULL,received_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE TABLE endpoint_installed_software (
			endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,ordinal INTEGER NOT NULL,
			name TEXT NOT NULL,version TEXT NOT NULL,publisher TEXT NOT NULL,architecture TEXT NOT NULL,source TEXT NOT NULL,
			PRIMARY KEY(endpoint_id,ordinal)
		)`,
		`CREATE INDEX endpoint_installed_software_lookup_idx ON endpoint_installed_software(name,version)`,
		`CREATE TABLE endpoint_cve_matches (
			endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
			cve_id TEXT NOT NULL REFERENCES cves(id) ON DELETE CASCADE,product TEXT NOT NULL,version TEXT NOT NULL,
			package_source TEXT NOT NULL,confidence TEXT NOT NULL,evidence TEXT NOT NULL,matched_at TIMESTAMPTZ NOT NULL,
			PRIMARY KEY(endpoint_id,cve_id,product,version,package_source)
		)`,
		`CREATE INDEX endpoint_cve_matches_cve_idx ON endpoint_cve_matches(cve_id,endpoint_id)`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate PostgreSQL endpoint inventory: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(13,$1)`, time.Now().UTC()); err != nil {
		return fmt.Errorf("record PostgreSQL endpoint-inventory migration: %w", err)
	}
	return nil
}

func migratePostgreSQLEndpointFoundation(ctx context.Context, tx *sql.Tx) error {
	statements := []string{
		`CREATE TABLE agent_enrollment_tokens (
			id TEXT PRIMARY KEY,name TEXT NOT NULL,token_hash BYTEA NOT NULL UNIQUE,created_by TEXT NOT NULL REFERENCES users(id),
			created_at TIMESTAMPTZ NOT NULL,expires_at TIMESTAMPTZ NOT NULL,used_at TIMESTAMPTZ
		)`,
		`CREATE INDEX agent_enrollment_tokens_expiry_idx ON agent_enrollment_tokens(expires_at,used_at)`,
		`CREATE TABLE endpoints (
			id TEXT PRIMARY KEY,name TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN ('active','revoked')),
			certificate_serial TEXT NOT NULL UNIQUE,certificate_pem TEXT NOT NULL,enrolled_at TIMESTAMPTZ NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL,last_seen_at TIMESTAMPTZ,last_heartbeat_generated_at TIMESTAMPTZ,
			last_heartbeat_received_at TIMESTAMPTZ,renewed_at TIMESTAMPTZ,revoked_at TIMESTAMPTZ,
			revocation_reason TEXT NOT NULL DEFAULT '',allowed_collectors JSONB NOT NULL DEFAULT '[]'::jsonb,
			network_telemetry_exclusions JSONB NOT NULL DEFAULT '{"applications":[],"destinations":[]}'::jsonb,
			software_version TEXT NOT NULL DEFAULT '',operating_system TEXT NOT NULL DEFAULT '',architecture TEXT NOT NULL DEFAULT '',
			asset_id TEXT REFERENCES assets(id)
		)`,
		`CREATE INDEX endpoints_status_idx ON endpoints(status,name)`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate PostgreSQL endpoint foundation: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(12,$1)`, time.Now().UTC()); err != nil {
		return fmt.Errorf("record PostgreSQL endpoint-foundation migration: %w", err)
	}
	return nil
}

func migratePostgreSQLReporting(ctx context.Context, tx *sql.Tx) error {
	statements := []string{
		`CREATE INDEX findings_workflow_idx ON findings(status,assigned_to)`,
		`CREATE TABLE finding_exceptions (
			id TEXT PRIMARY KEY,finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
			reason TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN ('pending','approved','rejected')),
			requested_by TEXT NOT NULL REFERENCES users(id),approved_by TEXT REFERENCES users(id),
			created_at TIMESTAMPTZ NOT NULL,expires_at TIMESTAMPTZ,
			reminder_days INTEGER NOT NULL DEFAULT 30 CHECK(reminder_days BETWEEN 1 AND 365),last_reminder_at TIMESTAMPTZ
		)`,
		`CREATE INDEX finding_exceptions_due_idx ON finding_exceptions(status,expires_at,last_reminder_at)`,
		`CREATE TABLE evidence_retention_settings (
			id SMALLINT PRIMARY KEY CHECK(id=1),retention_days INTEGER NOT NULL CHECK(retention_days BETWEEN 30 AND 3650),
			updated_at TIMESTAMPTZ NOT NULL
		)`,
		`INSERT INTO evidence_retention_settings(id,retention_days,updated_at) VALUES(1,365,NOW())`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate PostgreSQL reporting: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(11,$1)`, time.Now().UTC()); err != nil {
		return fmt.Errorf("record PostgreSQL reporting migration: %w", err)
	}
	return nil
}

func migratePostgreSQLAssetGroups(ctx context.Context, tx *sql.Tx) error {
	statements := []string{
		`CREATE TABLE asset_groups (
			id TEXT PRIMARY KEY,name TEXT NOT NULL UNIQUE,description TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL,updated_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE TABLE asset_group_members (
			group_id TEXT NOT NULL REFERENCES asset_groups(id) ON DELETE CASCADE,
			asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,added_at TIMESTAMPTZ NOT NULL,
			added_by TEXT NOT NULL REFERENCES users(id),PRIMARY KEY(group_id,asset_id)
		)`,
		`CREATE INDEX asset_group_members_asset_idx ON asset_group_members(asset_id,group_id)`,
		`CREATE TABLE reusable_scan_policies (
			id TEXT PRIMARY KEY,name TEXT NOT NULL UNIQUE,scope_policy_id TEXT NOT NULL REFERENCES scope_policies(id),
			ports JSONB NOT NULL,enabled BOOLEAN NOT NULL DEFAULT TRUE,created_at TIMESTAMPTZ NOT NULL,updated_at TIMESTAMPTZ NOT NULL,
			schedule_kind TEXT NOT NULL DEFAULT 'manual',schedule_expression TEXT NOT NULL DEFAULT '',
			schedule_timezone TEXT NOT NULL DEFAULT 'UTC',window_start TEXT NOT NULL DEFAULT '',window_end TEXT NOT NULL DEFAULT '',
			run_missed BOOLEAN NOT NULL DEFAULT FALSE,long_run_alert_seconds BIGINT NOT NULL DEFAULT 0 CHECK(long_run_alert_seconds >= 0),
			next_run_at TIMESTAMPTZ,last_scheduled_at TIMESTAMPTZ,
			rate_limit_per_second INTEGER NOT NULL DEFAULT 0 CHECK(rate_limit_per_second BETWEEN 0 AND 1000),
			execution_mode TEXT NOT NULL DEFAULT 'local' CHECK(execution_mode IN ('local','remote')),
			worker_site_id TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE reusable_scan_policy_groups (
			scan_policy_id TEXT NOT NULL REFERENCES reusable_scan_policies(id) ON DELETE CASCADE,
			group_id TEXT NOT NULL REFERENCES asset_groups(id) ON DELETE RESTRICT,ordinal INTEGER NOT NULL,
			PRIMARY KEY(scan_policy_id,group_id)
		)`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate PostgreSQL asset groups: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(10,$1)`, time.Now().UTC()); err != nil {
		return fmt.Errorf("record PostgreSQL asset-group migration: %w", err)
	}
	return nil
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
