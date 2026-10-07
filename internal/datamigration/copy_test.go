package datamigration

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"mossward/internal/model"
	"mossward/internal/store"
)

func TestPostgreSQLMigrationCopiesAndRollsBack(t *testing.T) {
	dsn := os.Getenv(postgreSQLTestDSNEnvironment)
	if dsn == "" {
		t.Skip(postgreSQLTestDSNEnvironment + " is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close() })
	schema := migrationTestSchemaName(t)
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec("DROP SCHEMA " + schema + " CASCADE"); err != nil {
			t.Error(err)
		}
	})
	isolated := migrationTestDSN(t, dsn, schema)
	path := filepath.Join(t.TempDir(), "source.db")
	repository, err := store.NewSQLiteStore(path, "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	user := model.User{ID: "migration-admin", Email: "admin@example.test", DisplayName: "Admin", Role: model.RoleAdministrator, Status: model.UserActive, CreatedAt: now, UpdatedAt: now}
	mfa := model.BootstrapMFA{TOTPSecretCiphertext: []byte{0, 255, 42}, RecoveryCodeHashes: [][]byte{[]byte("hashed-recovery")}}
	event := model.AuditEvent{OccurredAt: now, ActorID: user.ID, Action: "identity.bootstrap", Severity: model.AuditInfo}
	if err := repository.BootstrapAdministrator(user, "password-hash", mfa, event); err != nil {
		t.Fatal(err)
	}
	organization, err := repository.Organization()
	if err != nil {
		t.Fatal(err)
	}
	scan := model.Scan{ID: "migration-scan", Name: "Retained scan", Status: model.StatusCompleted, CreatedAt: now, CompletedAt: &now, MaxConcurrent: 1,
		Targets: []model.Target{{Name: "migration.example.test", Address: "192.0.2.20"}}, Ports: []int{443},
		Observations: []model.ServiceObservation{{ID: "migration-observation", Target: "migration.example.test", Address: "192.0.2.20", Port: 443, Protocol: "https", ObservedAt: now, Metadata: map[string]string{"source": "migration"}}}}
	if err := repository.Save(scan); err != nil {
		t.Fatal(err)
	}
	if err := repository.Close(); err != nil {
		t.Fatal(err)
	}
	// Unsupported source columns must roll back the initialized schema too.
	sourceDB, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sourceDB.Exec(`ALTER TABLE users ADD COLUMN unsupported TEXT`); err != nil {
		t.Fatal(err)
	}
	if _, err := CopySQLiteToPostgreSQL(ctx, path, isolated); err == nil {
		t.Fatal("incompatible source accepted")
	}
	if _, err := PreflightPostgreSQLDestination(ctx, isolated); err != nil {
		t.Fatalf("failed migration left destination occupied: %v", err)
	}
	if _, err := sourceDB.Exec(`ALTER TABLE users DROP COLUMN unsupported`); err != nil {
		t.Fatal(err)
	}
	if _, err := sourceDB.Exec(`INSERT INTO check_publishers(key_id,name,public_key,status,added_at) VALUES(?,?,?,?,?)`, "migration-publisher", "Retained publisher", []byte{0, 255, 7}, "trusted", now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := sourceDB.Exec(`INSERT INTO declarative_check_versions(check_id,version,kind,key_id,envelope_json,status,imported_at) VALUES(?,?,?,?,?,?,?)`, "migration-check", "1.0.0", "tcp", "migration-publisher", []byte(`{"signed":true}`), "staged", now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	// A value failure after earlier tables were inserted must remove all partial
	// data and the initialized schema, not just reject incompatible columns.
	if _, err := sourceDB.Exec(`UPDATE totp_credentials SET created_at='invalid-private-value'`); err != nil {
		t.Fatal(err)
	}
	if _, err := CopySQLiteToPostgreSQL(ctx, path, isolated); err == nil {
		t.Fatal("invalid required timestamp accepted")
	}
	if _, err := PreflightPostgreSQLDestination(ctx, isolated); err != nil {
		t.Fatalf("mid-copy failure left destination occupied: %v", err)
	}
	if _, err := sourceDB.Exec(`UPDATE totp_credentials SET created_at=?`, now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	sourceDB.Close()
	before := migrationSourceHash(t, path)
	report, err := CopySQLiteToPostgreSQL(ctx, path, isolated)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Verified || report.Rows == 0 {
		t.Fatalf("unexpected report: %#v", report)
	}
	if after := migrationSourceHash(t, path); before != after {
		t.Fatal("migration modified the SQLite source")
	}
	destination, err := store.OpenPostgreSQL(ctx, isolated)
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	actual, err := destination.Organization()
	if err != nil || actual.ID != organization.ID {
		t.Fatalf("organization identity changed: %#v %v", actual, err)
	}
	secret, _, err := destination.TOTPSecret(user.ID)
	if err != nil || !equivalentValue(secret, mfa.TOTPSecretCiphertext, ColumnBinary) {
		t.Fatalf("ciphertext changed: %v", err)
	}
	retained, err := destination.Get("migration-scan")
	if err != nil || len(retained.Observations) != 1 || retained.Observations[0].Metadata["source"] != "migration" {
		t.Fatal(err)
	}
	assets, err := destination.ListAssets()
	if err != nil || len(assets) != 1 {
		t.Fatalf("asset history not migrated: %#v %v", assets, err)
	}
	var envelope []byte
	if err := admin.QueryRow(`SELECT envelope_json FROM ` + schema + `.declarative_check_versions WHERE check_id='migration-check'`).Scan(&envelope); err != nil || string(envelope) != `{"signed":true}` {
		t.Fatalf("signed catalog evidence changed: %v", err)
	}
	if err := destination.AppendAuditEvent(event); err != nil {
		t.Fatalf("audit sequence was not repaired: %v", err)
	}
	if _, err := CopySQLiteToPostgreSQL(ctx, path, isolated); err == nil {
		t.Fatal("occupied destination accepted")
	}
}

func migrationSourceHash(t *testing.T, path string) [sha256.Size]byte {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(contents)
}

func TestMigrationRequiredFieldsAndValueVerification(t *testing.T) {
	source := SourceReport{Tables: []TableSummary{{Name: "example", Columns: []string{"id"}}}}
	target := map[string][]destinationColumn{"example": {{Name: "id"}, {Name: "required", Nullable: false}}}
	if validateDestination(source, target) == nil {
		t.Fatal("missing required field accepted")
	}
	if !equivalentValue(`{"b":2,"a":1}`, []byte(`{"a": 1, "b": 2}`), ColumnJSON) {
		t.Fatal("JSON formatting rejected")
	}
	if equivalentValue(int64(4), int64(5), "") {
		t.Fatal("changed row value accepted")
	}
}

func TestMigrationOptionalValuesAndColumnMapping(t *testing.T) {
	optional := destinationColumn{Name: "updated_at", Type: string(ColumnTimestamp), Nullable: true}
	value, err := convertMigrationColumn("endpoint_coverage_settings", "", optional)
	if err != nil || value != nil {
		t.Fatalf("unset optional timestamp: %v %v", value, err)
	}
	optional.Nullable = false
	if _, err := convertMigrationColumn("example", "", optional); err == nil {
		t.Fatal("empty required timestamp accepted")
	}
	value, err = convertMigrationColumn("audit_events", "", destinationColumn{Name: "details", Type: string(ColumnJSON)})
	if err != nil || value != "{}" {
		t.Fatalf("unset audit details: %v %v", value, err)
	}
	if migrationColumnName("scanner_worker_dispatch_settings", "id") != "singleton" || migrationColumnName("users", "id") != "id" {
		t.Fatal("singleton mapping affected unrelated identifiers")
	}
}
