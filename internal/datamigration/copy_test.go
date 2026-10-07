package datamigration

import (
	"context"
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
	if err := repository.Save(model.Scan{ID: "migration-scan", Name: "Retained scan", Status: model.StatusCompleted, CreatedAt: now, CompletedAt: &now, MaxConcurrent: 1}); err != nil {
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
	sourceDB.Close()
	report, err := CopySQLiteToPostgreSQL(ctx, path, isolated)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Verified || report.Rows == 0 {
		t.Fatalf("unexpected report: %#v", report)
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
	if _, err := destination.Get("migration-scan"); err != nil {
		t.Fatal(err)
	}
	if err := destination.AppendAuditEvent(event); err != nil {
		t.Fatalf("audit sequence was not repaired: %v", err)
	}
	if _, err := CopySQLiteToPostgreSQL(ctx, path, isolated); err == nil {
		t.Fatal("occupied destination accepted")
	}
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
