package serverbackup

import (
	"context"
	"database/sql"
	"mossward/internal/privatefs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mossward/internal/auth"
	"mossward/internal/model"
	"mossward/internal/store"
)

func TestPostgreSQLNativeBackupRecoveryAndKeyRotation(t *testing.T) {
	sourceURL := os.Getenv("MOSSWARD_TEST_POSTGRES_BACKUP_DSN")
	targetURL := os.Getenv("MOSSWARD_TEST_POSTGRES_RESTORE_DSN")
	if sourceURL == "" || targetURL == "" {
		t.Skip("dedicated PostgreSQL backup and restore test databases are not configured")
	}
	if sourceURL == targetURL {
		t.Fatal("backup and restore databases must differ")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	preparePostgreSQLRecoveryDatabase(t, ctx, sourceURL)
	preparePostgreSQLRecoveryDatabase(t, ctx, targetURL)
	verifyRecoveryRejectsAdditionalSchema(t, ctx, targetURL)
	directory := t.TempDir()
	key := filepath.Join(directory, "source", "identity.key")
	box, err := auth.LoadOrCreateSecretBox(key)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := box.Encrypt([]byte("retained-totp-secret"))
	if err != nil {
		t.Fatal(err)
	}
	repository, err := store.OpenPostgreSQL(ctx, sourceURL)
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	now := time.Now().UTC().Truncate(time.Microsecond)
	user := model.User{ID: "recovery-admin", Email: "admin@example.test", DisplayName: "Recovery admin", Role: model.RoleAdministrator, Status: model.UserActive, CreatedAt: now, UpdatedAt: now}
	if err := repository.BootstrapAdministrator(user, "retained-password-hash", model.BootstrapMFA{TOTPSecretCiphertext: ciphertext}, model.AuditEvent{OccurredAt: now, ActorID: user.ID, Action: "identity.bootstrap", Severity: model.AuditInfo}); err != nil {
		t.Fatal(err)
	}
	organization, err := repository.Organization()
	if err != nil {
		t.Fatal(err)
	}
	scan := model.Scan{ID: "recovery-scan", Name: "Retained scan", MaxConcurrent: 1, Status: model.StatusCompleted, CreatedAt: now, CompletedAt: &now}
	if err := repository.Save(scan); err != nil {
		t.Fatal(err)
	}
	source := Source{IdentityKeyFile: key, AgentPKIDir: filepath.Join(directory, "source", "pki"), ACMECacheDir: filepath.Join(directory, "source", "acme")}
	writeTestFile(t, filepath.Join(source.AgentPKIDir, "root-key"), []byte("test-pki-material"))
	writeTestFile(t, filepath.Join(source.ACMECacheDir, "account"), []byte("test-acme-material"))
	options := PostgreSQLOptions{URL: sourceURL, ToolsDir: os.Getenv("MOSSWARD_TEST_POSTGRES_TOOLS_DIR")}
	archive := filepath.Join(directory, "backup.tar.gz")
	if err := CreatePostgreSQL(ctx, archive, options, source, now); err != nil {
		t.Fatal(err)
	}
	manifest, err := Inspect(archive)
	if err != nil || manifest.Backend != "postgresql" || manifest.OrganizationID != organization.ID {
		t.Fatalf("backup metadata changed: %#v %v", manifest, err)
	}
	if err := CreatePostgreSQL(ctx, archive, options, source, now); err == nil {
		t.Fatal("existing backup overwritten")
	}
	// Rotate the live source after backup; recovery must still pair the historical
	// database ciphertext with the historical keyring, not the rotated one.
	rotationBox, err := auth.BeginIdentityKeyRotation(key)
	if err != nil {
		t.Fatal(err)
	}
	if count, err := repository.RotateIdentityCiphertextsContext(ctx, rotationBox, now.Add(time.Minute)); err != nil || count != 1 {
		t.Fatalf("rotate PostgreSQL identity key: %d %v", count, err)
	}
	if err := rotationBox.FinalizeIdentityKeyRotation(key); err != nil {
		t.Fatal(err)
	}
	rotatedSecret, _, err := repository.TOTPSecret(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := rotationBox.Decrypt(rotatedSecret); err != nil || string(plain) != "retained-totp-secret" {
		t.Fatalf("rotated MFA no longer usable: %v", err)
	}
	targets := RestoreTargets{IdentityKeyFile: filepath.Join(directory, "recovered", "identity.key"), AgentPKIDir: filepath.Join(directory, "recovered", "pki"), ACMECacheDir: filepath.Join(directory, "recovered", "acme")}
	options.URL = targetURL
	// A structurally corrupt native dump with valid archive checksums must fail
	// before publishing keys and leave an empty destination through rollback.
	brokenDump := filepath.Join(directory, "broken.dump")
	writeTestFile(t, brokenDump, []byte("PGDMPinvalid-native-archive"))
	brokenArchive := filepath.Join(directory, "broken.tar.gz")
	if err := writeManifestArchive(brokenArchive, map[string]string{postgresDumpEntry: brokenDump, "identity/identity.key": key}, manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(brokenArchive); err != nil {
		t.Fatalf("malformed-dump fixture must have valid archive checksums: %v", err)
	}
	if _, err := RestorePostgreSQL(ctx, brokenArchive, options, targets); err == nil || !strings.Contains(err.Error(), "pg_restore failed") {
		t.Fatalf("malformed dump did not reach native validation: %v", err)
	}
	if _, err := os.Stat(targets.IdentityKeyFile); !os.IsNotExist(err) {
		t.Fatal("failed native restore published an identity key")
	}
	verifyNativeRestoreRollback(t, ctx, options, sourceURL, source, directory, targets, now)
	if _, err := RestorePostgreSQL(ctx, archive, options, targets); err != nil {
		t.Fatal(err)
	}
	recovered, err := store.OpenPostgreSQL(ctx, targetURL)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	actualOrganization, err := recovered.Organization()
	if err != nil || actualOrganization.ID != organization.ID {
		t.Fatalf("recovered installation identity changed: %v", err)
	}
	if _, err := recovered.Get(scan.ID); err != nil {
		t.Fatal(err)
	}
	secret, _, err := recovered.TOTPSecret(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	recoveryBox, err := auth.LoadOrCreateSecretBox(targets.IdentityKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := recoveryBox.Decrypt(secret); err != nil || string(plain) != "retained-totp-secret" {
		t.Fatalf("recovery keyring does not decrypt historical MFA: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(targets.AgentPKIDir, "root-key")); err != nil || string(data) != "test-pki-material" {
		t.Fatalf("PKI recovery changed: %v", err)
	}
	if err := recovered.AppendAuditEvent(model.AuditEvent{OccurredAt: now.Add(time.Hour), Action: "recovery.verified", Severity: model.AuditInfo}); err != nil {
		t.Fatalf("recovered audit sequence invalid: %v", err)
	}
	if _, err := RestorePostgreSQL(ctx, archive, options, targets); err == nil {
		t.Fatal("occupied recovery destination accepted")
	}
}

func verifyRecoveryRejectsAdditionalSchema(t *testing.T, ctx context.Context, connection string) {
	t.Helper()
	database, err := sql.Open("pgx", connection)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	// "pgfoo" is user-creatable; only the literal "pg_" prefix is reserved.
	if _, err := database.Exec(`CREATE SCHEMA pgrecovery_user`); err != nil {
		t.Fatal(err)
	}
	defer database.Exec(`DROP SCHEMA pgrecovery_user`)
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := requireEmptyPostgreSQLDatabase(ctx, tx); err == nil {
		t.Fatal("user schema mistaken for a system schema")
	}
}

func verifyNativeRestoreRollback(t *testing.T, ctx context.Context, targetOptions PostgreSQLOptions, sourceURL string, source Source, directory string, targets RestoreTargets, now time.Time) {
	t.Helper()
	sourceDatabase, err := sql.Open("pgx", sourceURL)
	if err != nil {
		t.Fatal(err)
	}
	defer sourceDatabase.Close()
	// PostgreSQL does not revalidate existing rows when an immutable check helper
	// changes. The dumped helper rejects historical rows during restore COPY,
	// which fails only after earlier DDL has been created in the transaction.
	if _, err := sourceDatabase.Exec(`CREATE FUNCTION recovery_probe_ok(value INTEGER) RETURNS BOOLEAN LANGUAGE sql IMMUTABLE AS 'SELECT true'; CREATE TABLE recovery_rollback_probe(value INTEGER CHECK(recovery_probe_ok(value))); INSERT INTO recovery_rollback_probe VALUES(0); CREATE OR REPLACE FUNCTION recovery_probe_ok(value INTEGER) RETURNS BOOLEAN LANGUAGE sql IMMUTABLE AS 'SELECT value>0'`); err != nil {
		t.Fatal(err)
	}
	defer sourceDatabase.Exec(`DROP TABLE recovery_rollback_probe; DROP FUNCTION recovery_probe_ok(INTEGER)`)
	archive := filepath.Join(directory, "constraint-failure.tar.gz")
	sourceOptions := targetOptions
	sourceOptions.URL = sourceURL
	if err := CreatePostgreSQL(ctx, archive, sourceOptions, source, now); err != nil {
		t.Fatal(err)
	}
	if _, err := RestorePostgreSQL(ctx, archive, targetOptions, targets); err == nil || !strings.Contains(err.Error(), "pg_restore failed") {
		t.Fatalf("native constraint failure not detected: %v", err)
	}
	targetDatabase, err := sql.Open("pgx", targetOptions.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer targetDatabase.Close()
	tx, err := targetDatabase.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := requireEmptyPostgreSQLDatabase(ctx, tx); err != nil {
		t.Fatalf("failed native restore left partial DDL/data: %v", err)
	}
	if _, err := os.Stat(targets.IdentityKeyFile); !os.IsNotExist(err) {
		t.Fatal("failed native constraint restore published files")
	}
}

func preparePostgreSQLRecoveryDatabase(t *testing.T, ctx context.Context, connection string) {
	t.Helper()
	parsed, err := url.Parse(connection)
	if err != nil || !strings.HasPrefix(strings.TrimPrefix(parsed.Path, "/"), "mossward_test_") {
		t.Fatal("recovery tests require a dedicated PostgreSQL URL database named mossward_test_*")
	}
	database, err := sql.Open("pgx", connection)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := requireEmptyPostgreSQLDatabase(ctx, tx); err != nil {
		t.Fatal(err)
	}
	// These dedicated databases were verified empty before the test. Clean only
	// their generated public application schema, never an arbitrary supplied DB.
	t.Cleanup(func() {
		if _, err := database.Exec(`DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
			t.Error(err)
		}
	})
}

func TestPostgreSQLToolCredentialsArePrivateAndEnvironmentIsolated(t *testing.T) {
	t.Setenv("PGPASSWORD", "inherited-private-password")
	t.Setenv("PGHOST", "wrong-host")
	t.Setenv("PGSSLROOTCERT", "/test/tls/root.crt")
	directory := t.TempDir()
	environment, err := postgresToolEnvironment("postgresql://test_user:private-password@db.example/test?sslmode=verify-full", directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, variable := range environment {
		if strings.Contains(variable, "private-password") || strings.HasPrefix(variable, "PGHOST=") {
			t.Fatal("credentials or inherited connection settings exposed to environment")
		}
	}
	path := filepath.Join(directory, "pg-service.conf")
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), "password=private-password") {
		t.Fatal("private service credentials missing")
	}
	if !strings.Contains(string(data), "sslrootcert=/test/tls/root.crt") || !strings.Contains(string(data), "host=db.example") {
		t.Fatal("TLS material or explicit connection destination was lost")
	}
	if err := privatefs.Check(path); err != nil {
		t.Fatal(err)
	}
	for _, connection := range []string{"not a connection", "postgresql://user:p%0Ainjected@host/db", "postgresql://host/db?service=other"} {
		if _, err := postgresToolEnvironment(connection, directory); err == nil {
			t.Fatal("unsafe maintenance connection accepted")
		}
	}
}

func TestPostgreSQLStagingRejectsExistingDestinationsAndMissingComponents(t *testing.T) {
	directory := t.TempDir()
	extracted := filepath.Join(directory, "extracted")
	writeTestFile(t, filepath.Join(extracted, "identity", "identity.key"), make([]byte, 32))
	writeTestFile(t, filepath.Join(extracted, "agent-pki", "root-key"), []byte("test-pki"))
	existing := filepath.Join(directory, "existing.key")
	writeTestFile(t, existing, []byte("preserve-existing"))
	if _, _, err := stagePostgreSQLFiles(extracted, RestoreTargets{IdentityKeyFile: existing}); err == nil {
		t.Fatal("existing file destination accepted")
	}
	if value, err := os.ReadFile(existing); err != nil || string(value) != "preserve-existing" {
		t.Fatal("staging changed an existing destination")
	}
	if _, _, err := stagePostgreSQLFiles(extracted, RestoreTargets{IdentityKeyFile: filepath.Join(directory, "new.key")}); err == nil {
		t.Fatal("missing destination for archived PKI accepted")
	}
}
