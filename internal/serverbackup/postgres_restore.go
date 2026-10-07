package serverbackup

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"mossward/internal/store"
)

// RestorePostgreSQL never replaces a database or existing application files.
// Database and filesystem publication are separate commits; retained staging
// makes a publication failure recoverable without dropping the restored data.
func RestorePostgreSQL(ctx context.Context, archive string, options PostgreSQLOptions, targets RestoreTargets) (RestoreResult, error) {
	if targets.IdentityKeyFile == "" || targets.DatabaseFile != "" {
		return RestoreResult{}, errors.New("PostgreSQL restore requires an identity key destination and no SQLite database destination")
	}
	if err := validateRestoreTargets(targets); err != nil {
		return RestoreResult{}, err
	}
	directory, manifest, err := extractAndValidate(archive)
	if err != nil {
		return RestoreResult{}, err
	}
	defer os.RemoveAll(directory)
	if manifest.Backend != "postgresql" {
		return RestoreResult{}, errors.New("PostgreSQL restore requires a PostgreSQL archive")
	}
	if _, err := postgresToolPath(options.ToolsDir, "pg_restore"); err != nil {
		return RestoreResult{}, err
	}
	database, err := openMaintenanceDatabase(ctx, options.URL)
	if err != nil {
		return RestoreResult{}, err
	}
	defer database.Close()
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return RestoreResult{}, errors.New("begin PostgreSQL restore guard failed")
	}
	defer tx.Rollback()
	if err := store.LockPostgreSQLSchemaTransaction(ctx, tx); err != nil {
		return RestoreResult{}, errors.New("acquire PostgreSQL restore guard failed")
	}
	if err := requireEmptyPostgreSQLDatabase(ctx, tx); err != nil {
		return RestoreResult{}, err
	}
	staging, items, err := stagePostgreSQLFiles(directory, targets)
	if err != nil {
		return RestoreResult{}, err
	}
	retainStaging := false
	defer func() {
		if !retainStaging {
			os.RemoveAll(staging)
		}
	}()
	dump := filepath.Join(directory, filepath.FromSlash(postgresDumpEntry))
	retainStaging = true
	if err := runPostgreSQLTool(ctx, options, directory, "pg_restore", "--single-transaction", "--exit-on-error", "--no-owner", "--no-acl", "--no-password", "--dbname=service=mossward", dump); err != nil {
		return RestoreResult{}, fmt.Errorf("native restore failed or was interrupted; do not start Mossward until the database state is checked; recovery files retained at %s: %w", staging, err)
	}
	// Do not automatically remove database objects on a validation failure.
	actual, err := postgresManifest(ctx, database, manifest.CreatedAt)
	if err != nil || actual.SchemaVersion != manifest.SchemaVersion || actual.OrganizationID != manifest.OrganizationID {
		return RestoreResult{}, fmt.Errorf("restored database verification failed; do not start Mossward; recovery files retained at %s", staging)
	}
	for _, item := range items {
		if err := publishPostgreSQLFile(item); err != nil {
			return RestoreResult{}, fmt.Errorf("database restored but file publication failed; do not start Mossward; recovery files retained at %s: %w", staging, err)
		}
	}
	retainStaging = false
	slog.Info("PostgreSQL recovery verified", "schema_version", actual.SchemaVersion)
	return RestoreResult{Manifest: manifest}, nil
}

func requireEmptyPostgreSQLDatabase(ctx context.Context, tx *sql.Tx) error {
	var schema string
	var superuser bool
	if err := tx.QueryRowContext(ctx, `SELECT current_schema(),rolsuper FROM pg_roles WHERE rolname=current_user`).Scan(&schema, &superuser); err != nil {
		return errors.New("inspect PostgreSQL restore role failed")
	}
	if schema != "public" || superuser {
		return errors.New("restore requires the public schema and a non-superuser database owner")
	}
	var objects int
	if err := tx.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema') +
		(SELECT COUNT(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema') +
		(SELECT COUNT(*) FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema') +
		(SELECT COUNT(*) FROM pg_namespace WHERE nspname !~ '^pg_' AND nspname NOT IN ('information_schema','public'))`).Scan(&objects); err != nil {
		return errors.New("inspect PostgreSQL restore destination failed")
	}
	if objects != 0 {
		return errors.New("PostgreSQL restore destination is not empty; use a new dedicated database")
	}
	return nil
}

func stagePostgreSQLFiles(directory string, targets RestoreTargets) (string, []restoreItem, error) {
	items := []restoreItem{
		{source: filepath.Join(directory, "identity", "identity.key"), destination: targets.IdentityKeyFile},
		{source: filepath.Join(directory, "acme"), destination: targets.ACMECacheDir, isDirectory: true},
		{source: filepath.Join(directory, "agent-pki"), destination: targets.AgentPKIDir, isDirectory: true},
	}
	for _, item := range items {
		if item.destination == "" {
			if _, err := os.Stat(item.source); err == nil {
				return "", nil, errors.New("restore requires destinations for every archived application component")
			}
			continue
		}
		if _, err := os.Lstat(item.destination); !os.IsNotExist(err) {
			return "", nil, errors.New("PostgreSQL restore file destinations must not already exist")
		}
	}
	if err := os.MkdirAll(filepath.Dir(targets.IdentityKeyFile), 0o700); err != nil {
		return "", nil, err
	}
	staging, err := os.MkdirTemp(filepath.Dir(targets.IdentityKeyFile), ".mossward-recovery-")
	if err != nil {
		return "", nil, err
	}
	staged := []restoreItem{}
	for index, item := range items {
		if item.destination == "" {
			continue
		}
		if _, err := os.Stat(item.source); os.IsNotExist(err) && item.isDirectory {
			continue
		}
		prepared := filepath.Join(staging, fmt.Sprintf("component-%d", index))
		copyItem := item
		copyItem.destination = prepared
		if err := copyRestoreItem(copyItem); err != nil {
			os.RemoveAll(staging)
			return "", nil, err
		}
		item.source = prepared
		staged = append(staged, item)
	}
	return staging, staged, nil
}

func publishPostgreSQLFile(item restoreItem) error {
	if err := os.MkdirAll(filepath.Dir(item.destination), 0o700); err != nil {
		return err
	}
	if item.isDirectory {
		if err := os.Mkdir(item.destination, 0o700); err != nil {
			return err
		}
	}
	return copyRestoreItem(item)
}
