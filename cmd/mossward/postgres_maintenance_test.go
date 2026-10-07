package main

import (
	"bytes"
	"context"
	"database/sql"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mossward/internal/auth"
	"mossward/internal/config"
	"mossward/internal/model"
	"mossward/internal/serverbackup"
	"mossward/internal/store"
)

func TestPostgreSQLMaintenanceRequiresExplicitOfflineApproval(t *testing.T) {
	cfg := config.Config{DatabaseBackend: config.DatabasePostgreSQL}
	for _, args := range [][]string{
		{"backup"}, {"backup", "create", "--output", "unused"},
		{"backup", "restore", "--input", "unused", "--confirm-restore"},
		{"identity-key", "rotate", "--backup", "unused"},
		{"backup", "inspect", "--timeout", "0s", "--input", "unused"},
		{"backup", "create", "--output", "unused", "--confirm-offline", "unexpected"},
	} {
		if err := runPostgreSQLMaintenance(cfg, args); err == nil {
			t.Fatalf("unconfirmed or invalid maintenance accepted: %v", args)
		}
	}
}

func TestPostgreSQLIdentityKeyRotationCommand(t *testing.T) {
	connection := os.Getenv("MOSSWARD_TEST_POSTGRES_ROTATION_DSN")
	if connection == "" {
		t.Skip("dedicated PostgreSQL rotation test database is not configured")
	}
	parsed, err := url.Parse(connection)
	if err != nil || !strings.HasPrefix(strings.TrimPrefix(parsed.Path, "/"), "mossward_test_") {
		t.Fatal("rotation tests require a dedicated PostgreSQL URL database named mossward_test_*")
	}
	database, err := sql.Open("pgx", connection)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	var tables int
	if err := database.QueryRow(`SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public'`).Scan(&tables); err != nil || tables != 0 {
		t.Fatal("rotation test database must be empty")
	}
	t.Cleanup(func() {
		if _, err := database.Exec(`DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
			t.Error(err)
		}
	})
	directory := t.TempDir()
	cfg := config.Config{DatabaseBackend: config.DatabasePostgreSQL, DatabaseURL: connection,
		IdentityKeyFile: filepath.Join(directory, "identity.key"), AgentPKIDirectory: filepath.Join(directory, "pki"), ACMECacheDirectory: filepath.Join(directory, "acme")}
	box, err := auth.LoadOrCreateSecretBox(cfg.IdentityKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := box.Encrypt([]byte("cli-totp-secret"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	repository, err := store.OpenPostgreSQL(ctx, connection)
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	now := time.Now().UTC()
	user := model.User{ID: "rotation-cli-admin", Email: "admin@example.test", Role: model.RoleAdministrator, Status: model.UserActive, CreatedAt: now, UpdatedAt: now}
	if err := repository.BootstrapAdministrator(user, "password-hash", model.BootstrapMFA{TOTPSecretCiphertext: ciphertext}, model.AuditEvent{OccurredAt: now, ActorID: user.ID, Action: "identity.bootstrap", Severity: model.AuditInfo}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(cfg.IdentityKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := runPostgreSQLMaintenance(cfg, []string{"identity-key", "rotate", "--backup", filepath.Join(directory, "failed.tar.gz"), "--confirm-rotation", "--pg-tools-dir", filepath.Join(directory, "missing-tools")}); err == nil {
		t.Fatal("rotation accepted failed mandatory backup")
	}
	unchanged, err := os.ReadFile(cfg.IdentityKeyFile)
	if err != nil || !bytes.Equal(before, unchanged) {
		t.Fatal("failed backup changed the identity key")
	}
	archive := filepath.Join(directory, "rotation.tar.gz")
	args := []string{"identity-key", "rotate", "--backup", archive, "--confirm-rotation"}
	if tools := os.Getenv("MOSSWARD_TEST_POSTGRES_TOOLS_DIR"); tools != "" {
		args = append(args, "--pg-tools-dir", tools)
	}
	if err := runPostgreSQLMaintenance(cfg, args); err != nil {
		t.Fatal(err)
	}
	if _, err := serverbackup.Inspect(archive); err != nil {
		t.Fatal(err)
	}
	rotatedBox, err := auth.LoadOrCreateSecretBox(cfg.IdentityKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	secret, _, err := repository.TOTPSecret(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if plaintext, err := rotatedBox.Decrypt(secret); err != nil || string(plaintext) != "cli-totp-secret" {
		t.Fatalf("CLI rotation broke stored MFA: %v", err)
	}
	if _, err := box.Decrypt(secret); err == nil {
		t.Fatal("stored MFA still encrypted with the old active key")
	}
}
