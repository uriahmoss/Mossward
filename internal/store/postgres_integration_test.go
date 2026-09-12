package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"os"
	"reflect"
	"regexp"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"mossward/internal/model"
)

const postgreSQLIntegrationDSNEnvironment = "MOSSWARD_TEST_POSTGRES_DSN"

func TestPostgreSQLMigrationsInIsolatedSchema(t *testing.T) {
	repository, isolatedDSN := openPostgreSQLIntegrationStore(t)
	assertPostgreSQLMigrationState(t, repository.db)
	if err := repository.Close(); err != nil {
		t.Fatalf("close migrated PostgreSQL repository: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	reopened, err := OpenPostgreSQL(ctx, isolatedDSN)
	if err != nil {
		t.Fatalf("reopen migrated PostgreSQL schema: %v", err)
	}
	defer reopened.Close()
	assertPostgreSQLMigrationState(t, reopened.db)
}

func TestPostgreSQLScanAndAssetProjectionRoundTrip(t *testing.T) {
	repository, _ := openPostgreSQLIntegrationStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	scan := serviceHistoryScan("postgres-scan", "postgres-observation", now, true)
	scan.Targets[0].GroupIDs = []string{"group-one", "group-two"}
	scan.Observations[0].Product = "nginx"
	scan.Observations[0].Version = "1.26"
	scan.Observations[0].Metadata = map[string]string{"source": "integration-test"}
	scan.Findings = []model.Finding{{
		ID: "postgres-finding", CheckID: "tls-observed", Target: scan.Targets[0].Name,
		Address: scan.Targets[0].Address, Port: 443, Service: "https", Severity: "info",
		Title: "TLS service observed", Evidence: "reachable", ObservedAt: now,
	}}
	scan.Checkpoints = []model.ScanCheckpoint{{Address: scan.Targets[0].Address, Port: 443, CompletedAt: now}}
	if err := repository.Save(scan); err != nil {
		t.Fatalf("save PostgreSQL scan: %v", err)
	}

	stored, err := repository.Get(scan.ID)
	if err != nil {
		t.Fatalf("get PostgreSQL scan: %v", err)
	}
	if !reflect.DeepEqual(stored.Targets, scan.Targets) || !reflect.DeepEqual(stored.Ports, scan.Ports) {
		t.Fatalf("PostgreSQL scan target or port round trip changed: %#v", stored)
	}
	if len(stored.Observations) != 1 || !reflect.DeepEqual(stored.Observations[0].Metadata, scan.Observations[0].Metadata) {
		t.Fatalf("PostgreSQL observation metadata was not preserved: %#v", stored.Observations)
	}
	if len(stored.Findings) != 1 || stored.Findings[0].Status != model.FindingOpen || len(stored.Checkpoints) != 1 {
		t.Fatalf("PostgreSQL finding or checkpoint was not preserved: %#v", stored)
	}

	assets, err := repository.ListAssets()
	if err != nil || len(assets) != 1 {
		t.Fatalf("PostgreSQL asset projection missing: %#v %v", assets, err)
	}
	detail, err := repository.AssetDetail(assets[0].ID, now)
	if err != nil || len(detail.Services) != 1 || len(detail.Evidence) != 1 {
		t.Fatalf("PostgreSQL asset detail projection missing: %#v %v", detail, err)
	}
	service := detail.Services[0]
	if service.State != model.AssetServiceObserved || service.Product != "nginx" || service.Version != "1.26" ||
		service.ObservationCount != 1 || len(service.Events) != 1 || !reflect.DeepEqual(service.Events[0].FindingIDs, []string{"postgres-finding"}) {
		t.Fatalf("PostgreSQL service history projection changed: %#v", service)
	}
}

func openPostgreSQLIntegrationStore(t *testing.T) (*PostgreSQLStore, string) {
	t.Helper()
	dsn := os.Getenv(postgreSQLIntegrationDSNEnvironment)
	if dsn == "" {
		t.Skip(postgreSQLIntegrationDSNEnvironment + " is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	schema := postgreSQLIntegrationSchemaName(t)
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("create isolated PostgreSQL schema: %v", err)
	}
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if _, err := admin.ExecContext(cleanupContext, `DROP SCHEMA `+schema+` CASCADE`); err != nil {
			t.Errorf("drop isolated PostgreSQL schema: %v", err)
		}
	})
	isolatedDSN := postgreSQLIsolatedDSN(t, dsn, schema)
	repository, err := OpenPostgreSQL(ctx, isolatedDSN)
	if err != nil {
		t.Fatalf("migrate isolated PostgreSQL schema: %v", err)
	}
	t.Cleanup(func() { _ = repository.Close() })
	return repository, isolatedDSN
}

func assertPostgreSQLMigrationState(t *testing.T, database *sql.DB) {
	t.Helper()
	var version, organizations int
	if err := database.QueryRow(`SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatalf("read PostgreSQL migration version: %v", err)
	}
	if version != postgresFoundationSchemaVersion {
		t.Fatalf("PostgreSQL migration version = %d, want %d", version, postgresFoundationSchemaVersion)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM installation_organization`).Scan(&organizations); err != nil {
		t.Fatalf("read PostgreSQL organization boundary: %v", err)
	}
	if organizations != 1 {
		t.Fatalf("PostgreSQL organization count = %d, want 1", organizations)
	}
	for _, table := range []string{
		"scans", "assets", "endpoints", "scanner_workers", "agent_module_releases",
		"endpoint_relay_authorizations", "endpoint_maintenance_windows", "endpoint_coverage_settings",
	} {
		var exists bool
		if err := database.QueryRow(`SELECT to_regclass($1) IS NOT NULL`, table).Scan(&exists); err != nil {
			t.Fatalf("check PostgreSQL table %q: %v", table, err)
		}
		if !exists {
			t.Errorf("PostgreSQL table %q is missing", table)
		}
	}
}

func postgreSQLIntegrationSchemaName(t *testing.T) string {
	t.Helper()
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		t.Fatalf("create PostgreSQL integration schema name: %v", err)
	}
	return "mossward_test_" + hex.EncodeToString(random)
}

func postgreSQLIsolatedDSN(t *testing.T, dsn, schema string) string {
	t.Helper()
	configuration, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse PostgreSQL integration configuration: %v", err)
	}
	configuration.RuntimeParams["search_path"] = schema
	registered := stdlib.RegisterConnConfig(configuration)
	t.Cleanup(func() { stdlib.UnregisterConnConfig(registered) })
	return registered
}

func TestPostgreSQLIntegrationSchemaNameIsSafe(t *testing.T) {
	name := postgreSQLIntegrationSchemaName(t)
	if !regexp.MustCompile(`^mossward_test_[0-9a-f]{16}$`).MatchString(name) {
		t.Fatalf("generated PostgreSQL schema name is unsafe: %q", name)
	}
}
