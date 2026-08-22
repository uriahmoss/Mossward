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
	postgresFoundationSchemaVersion = 2
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
	var organizations int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM installation_organization`).Scan(&organizations); err != nil || organizations != 1 {
		return errors.New("PostgreSQL installation organization boundary is invalid")
	}
	return tx.Commit()
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
