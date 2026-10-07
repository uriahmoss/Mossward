package serverbackup

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

const (
	postgresArchiveVersion = 2
	postgresDumpEntry      = "database/mossward.dump"
)

func CreatePostgreSQL(ctx context.Context, output string, options PostgreSQLOptions, source Source, now time.Time) error {
	directory, err := os.MkdirTemp("", "mossward-postgres-backup-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	database, err := openMaintenanceDatabase(ctx, options.URL)
	if err != nil {
		return err
	}
	defer database.Close()
	manifest, err := postgresManifest(ctx, database, now)
	if err != nil {
		return err
	}
	dump := filepath.Join(directory, "mossward.dump")
	if err := runPostgreSQLTool(ctx, options, directory, "pg_dump", "--dbname=service=mossward", "--format=custom", "--no-owner", "--no-acl", "--no-password", "--file="+dump); err != nil {
		return err
	}
	if err := validatePostgreSQLDump(dump); err != nil {
		return err
	}
	files := map[string]string{postgresDumpEntry: dump, "identity/identity.key": source.IdentityKeyFile}
	if err := addDirectory(files, source.ACMECacheDir, "acme"); err != nil {
		return err
	}
	if err := addDirectory(files, source.AgentPKIDir, "agent-pki"); err != nil {
		return err
	}
	if err := writeManifestArchive(output, files, manifest); err != nil {
		return err
	}
	if _, err := Inspect(output); err != nil {
		return fmt.Errorf("verify PostgreSQL backup archive: %w", err)
	}
	slog.Info("PostgreSQL backup verified", "schema_version", manifest.SchemaVersion)
	return nil
}

func openMaintenanceDatabase(ctx context.Context, connection string) (*sql.DB, error) {
	database, err := sql.Open("pgx", connection)
	if err != nil {
		return nil, errors.New("invalid PostgreSQL maintenance connection configuration")
	}
	if err := database.PingContext(ctx); err != nil {
		database.Close()
		return nil, errors.New("PostgreSQL maintenance connection failed; check connectivity, TLS, and credentials")
	}
	return database, nil
}

func postgresManifest(ctx context.Context, database *sql.DB, now time.Time) (Manifest, error) {
	manifest := Manifest{FormatVersion: postgresArchiveVersion, Backend: "postgresql", CreatedAt: now.UTC()}
	var schema string
	var additionalSchemas int
	if err := database.QueryRowContext(ctx, `SELECT current_schema(),(SELECT COUNT(*) FROM pg_namespace WHERE nspname !~ '^pg_' AND nspname NOT IN ('information_schema','public'))`).Scan(&schema, &additionalSchemas); err != nil || schema != "public" || additionalSchemas != 0 {
		return manifest, errors.New("PostgreSQL maintenance currently requires a dedicated database with the public application schema")
	}
	if err := database.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&manifest.SchemaVersion); err != nil {
		return manifest, errors.New("read PostgreSQL maintenance schema version failed")
	}
	if err := database.QueryRowContext(ctx, `SELECT id FROM installation_organization WHERE singleton=TRUE`).Scan(&manifest.OrganizationID); err != nil {
		return manifest, errors.New("read PostgreSQL installation identity failed")
	}
	return manifest, nil
}

func validatePostgreSQLDump(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	header := make([]byte, len("PGDMP"))
	if _, err := io.ReadFull(file, header); err != nil || string(header) != "PGDMP" {
		return errors.New("PostgreSQL backup is not a native custom-format dump")
	}
	return nil
}
