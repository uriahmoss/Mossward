package datamigration

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

const postgreSQLTestDSNEnvironment = "MOSSWARD_TEST_POSTGRES_DSN"

func TestPostgreSQLDestinationPreflightRequiresURL(t *testing.T) {
	if _, err := PreflightPostgreSQLDestination(context.Background(), ""); err == nil {
		t.Fatal("empty PostgreSQL migration destination URL was accepted")
	}
}

func TestPostgreSQLDestinationPreflightRequiresEmptySchema(t *testing.T) {
	dsn := os.Getenv(postgreSQLTestDSNEnvironment)
	if dsn == "" {
		t.Skip(postgreSQLTestDSNEnvironment + " is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close() })
	schema := migrationTestSchemaName(t)
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("create migration destination test schema: %v", err)
	}
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if _, err := admin.ExecContext(cleanupContext, `DROP SCHEMA `+schema+` CASCADE`); err != nil {
			t.Errorf("drop migration destination test schema: %v", err)
		}
	})
	isolatedDSN := migrationTestDSN(t, dsn, schema)
	report, err := PreflightPostgreSQLDestination(ctx, isolatedDSN)
	if err != nil || !report.Empty || report.RelationCount != 0 || report.Schema != schema || report.ServerMajorVersion < 14 {
		t.Fatalf("empty PostgreSQL migration destination report = %#v, error = %v", report, err)
	}
	if _, err := admin.ExecContext(ctx, `CREATE TABLE `+schema+`.occupied(id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatalf("occupy PostgreSQL migration destination schema: %v", err)
	}
	report, err = PreflightPostgreSQLDestination(ctx, isolatedDSN)
	if err == nil || report.Empty || report.RelationCount != 1 {
		t.Fatalf("occupied PostgreSQL migration destination report = %#v, error = %v", report, err)
	}
}

func migrationTestSchemaName(t *testing.T) string {
	t.Helper()
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		t.Fatalf("create migration destination test schema name: %v", err)
	}
	return "mossward_migration_test_" + hex.EncodeToString(random)
}

func migrationTestDSN(t *testing.T, dsn, schema string) string {
	t.Helper()
	configuration, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse PostgreSQL migration test configuration: %v", err)
	}
	configuration.RuntimeParams["search_path"] = schema
	registered := stdlib.RegisterConnConfig(configuration)
	t.Cleanup(func() { stdlib.UnregisterConnConfig(registered) })
	return registered
}
