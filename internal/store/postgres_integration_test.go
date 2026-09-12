package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
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

func TestPostgreSQLLocalAuthFoundationRoundTrip(t *testing.T) {
	repository, _ := openPostgreSQLIntegrationStore(t)
	initialized, err := repository.IdentityInitialized()
	if err != nil || initialized {
		t.Fatalf("unexpected PostgreSQL identity state before bootstrap: %t %v", initialized, err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	user, mfa, bootstrapEvent := bootstrapPostgreSQLTestAdministrator(t, repository, now)
	if err := repository.BootstrapAdministrator(user, "password-hash", mfa, bootstrapEvent); !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatalf("repeat PostgreSQL bootstrap error = %v, want %v", err, ErrAlreadyInitialized)
	}
	identity, err := repository.LocalIdentityByEmail("ADMIN@example.test")
	if err != nil || identity.User.ID != user.ID || identity.User.Email != "admin@example.test" || identity.PasswordHash != "password-hash" {
		t.Fatalf("PostgreSQL local identity round trip changed: %#v %v", identity, err)
	}
	secret, counter, err := repository.TOTPSecret(user.ID)
	if err != nil || !reflect.DeepEqual(secret, mfa.TOTPSecretCiphertext) || counter != 0 {
		t.Fatalf("PostgreSQL TOTP state changed: %q %d %v", secret, counter, err)
	}
	consumed, err := repository.ConsumeRecoveryCode(user.ID, mfa.RecoveryCodeHashes[0], now.Add(time.Minute),
		model.AuditEvent{OccurredAt: now.Add(time.Minute), ActorID: user.ID, Action: "identity.recovery_code.used", Severity: model.AuditWarning})
	if err != nil || !consumed {
		t.Fatalf("consume PostgreSQL recovery code: %t %v", consumed, err)
	}
	consumed, err = repository.ConsumeRecoveryCode(user.ID, mfa.RecoveryCodeHashes[0], now.Add(2*time.Minute), bootstrapEvent)
	if err != nil || consumed {
		t.Fatalf("PostgreSQL recovery code replay accepted: %t %v", consumed, err)
	}

	policy := model.AuthenticationPolicy{SessionLifetimeMinutes: 60, AuditRetentionDays: 365,
		MFARequired: map[model.UserRole]bool{model.RoleAdministrator: true, model.RoleAnalyst: true, model.RoleViewer: false}}
	policyEvent := model.AuditEvent{OccurredAt: now.Add(3 * time.Minute), ActorID: user.ID,
		Action: "identity.authentication_policy.updated", Severity: model.AuditWarning, TargetType: "authentication_policy", Details: `{}`}
	if err := repository.SaveAuthenticationPolicy(policy, now.Add(3*time.Minute), policyEvent); err != nil {
		t.Fatalf("save PostgreSQL authentication policy: %v", err)
	}
	storedPolicy, err := repository.AuthenticationPolicy()
	if err != nil || !reflect.DeepEqual(storedPolicy, policy) {
		t.Fatalf("PostgreSQL authentication policy round trip changed: %#v %v", storedPolicy, err)
	}
	events, err := repository.ListAuditEvents(model.AuditQuery{Text: "identity.", Limit: 10})
	if err != nil || len(events) != 3 {
		t.Fatalf("PostgreSQL local-auth audit trail missing: %#v %v", events, err)
	}
}

func TestPostgreSQLSessionAndInvitationLifecycle(t *testing.T) {
	repository, _ := openPostgreSQLIntegrationStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	administrator, _, _ := bootstrapPostgreSQLTestAdministrator(t, repository, now)
	invitation := model.Invitation{ID: "postgres-invitation", Email: "Analyst@Example.Test", Role: model.RoleAnalyst,
		IdentityKind: model.IdentityLocal, InvitedBy: administrator.ID, ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		TokenHash: []byte("invitation-token-hash")}
	inviteEvent := model.AuditEvent{OccurredAt: now, ActorID: administrator.ID, Action: "identity.invitation.created",
		Severity: model.AuditInfo, TargetType: "invitation", TargetID: invitation.ID, Details: `{}`}
	if err := repository.CreateInvitation(invitation, inviteEvent); err != nil {
		t.Fatalf("create PostgreSQL invitation: %v", err)
	}
	storedInvitation, err := repository.InvitationByTokenHash(invitation.TokenHash, now.Add(time.Minute))
	if err != nil || storedInvitation.Email != "analyst@example.test" || !reflect.DeepEqual(storedInvitation.TokenHash, invitation.TokenHash) {
		t.Fatalf("PostgreSQL invitation round trip changed: %#v %v", storedInvitation, err)
	}
	analyst := model.User{ID: "postgres-analyst", Email: storedInvitation.Email, DisplayName: "PostgreSQL Analyst", Role: model.RoleAnalyst}
	analystMFA := model.BootstrapMFA{TOTPSecretCiphertext: []byte("analyst-encrypted-totp"), RecoveryCodeHashes: [][]byte{[]byte("analyst-recovery")}}
	acceptEvent := model.AuditEvent{OccurredAt: now.Add(time.Minute), ActorID: administrator.ID, Action: "identity.invitation.accepted",
		Severity: model.AuditInfo, TargetType: "user", TargetID: analyst.ID, Details: `{}`}
	if err := repository.AcceptLocalInvitation(storedInvitation, analyst, "analyst-password-hash", analystMFA, now.Add(time.Minute), acceptEvent); err != nil {
		t.Fatalf("accept PostgreSQL invitation: %v", err)
	}
	if err := repository.AcceptLocalInvitation(storedInvitation, analyst, "analyst-password-hash", analystMFA, now.Add(2*time.Minute), acceptEvent); !errors.Is(err, ErrIdentityNotFound) {
		t.Fatalf("PostgreSQL invitation reuse error = %v, want %v", err, ErrIdentityNotFound)
	}

	session := model.Session{PublicID: "postgres-session", IDHash: []byte("session-hash"), UserID: analyst.ID,
		CreatedAt: now.Add(2 * time.Minute), ExpiresAt: now.Add(time.Hour), LastSeenAt: now.Add(2 * time.Minute),
		SourceIP: "192.0.2.25", UserAgentHash: []byte("user-agent-hash")}
	sessionEvent := model.AuditEvent{OccurredAt: session.CreatedAt, ActorID: analyst.ID, Action: "identity.login.succeeded",
		Severity: model.AuditInfo, TargetType: "session", TargetID: session.PublicID, Details: `{}`}
	if err := repository.CreateSession(session, sessionEvent); err != nil {
		t.Fatalf("create PostgreSQL session: %v", err)
	}
	sessionUser, err := repository.SessionUser(session.IDHash, now.Add(3*time.Minute))
	if err != nil || sessionUser.ID != analyst.ID || sessionUser.LastLoginAt == nil {
		t.Fatalf("PostgreSQL session user round trip changed: %#v %v", sessionUser, err)
	}
	verifiedAt := now.Add(3 * time.Minute)
	if err := repository.UpdateSessionMFAVerifiedAt(session.IDHash, analyst.ID, verifiedAt); err != nil {
		t.Fatalf("update PostgreSQL session MFA state: %v", err)
	}
	sessions, err := repository.ListUserSessions(analyst.ID, session.IDHash, now.Add(4*time.Minute))
	if err != nil || len(sessions) != 1 || !sessions[0].Current || sessions[0].MFAVerifiedAt == nil || !sessions[0].MFAVerifiedAt.Equal(verifiedAt) {
		t.Fatalf("PostgreSQL session listing changed: %#v %v", sessions, err)
	}
	revokeEvent := model.AuditEvent{OccurredAt: now.Add(4 * time.Minute), ActorID: analyst.ID, Action: "identity.session.revoked",
		Severity: model.AuditWarning, TargetType: "session", TargetID: session.PublicID, Details: `{}`}
	if err := repository.RevokeUserSession(analyst.ID, session.PublicID, revokeEvent); err != nil {
		t.Fatalf("revoke PostgreSQL session: %v", err)
	}
	if _, err := repository.SessionUser(session.IDHash, now.Add(5*time.Minute)); !errors.Is(err, ErrIdentityNotFound) {
		t.Fatalf("revoked PostgreSQL session lookup error = %v, want %v", err, ErrIdentityNotFound)
	}
}

func TestPostgreSQLWebAuthnStateAndCeremonyLifecycle(t *testing.T) {
	repository, _ := openPostgreSQLIntegrationStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	administrator, _, _ := bootstrapPostgreSQLTestAdministrator(t, repository, now)
	ceremony := model.AuthenticationCeremony{IDHash: []byte("webauthn-ceremony"), UserID: administrator.ID,
		Kind: model.CeremonyWebAuthnRegister, StateCiphertext: []byte("encrypted-ceremony-state"),
		ExpiresAt: now.Add(10 * time.Minute), CreatedAt: now}
	if err := repository.CreateAuthenticationCeremony(ceremony); err != nil {
		t.Fatalf("create PostgreSQL WebAuthn ceremony: %v", err)
	}
	if _, err := repository.ConsumeAuthenticationCeremony(ceremony.IDHash, model.CeremonyWebAuthnLogin); !errors.Is(err, ErrCeremonyNotFound) {
		t.Fatalf("mismatched PostgreSQL ceremony error = %v, want %v", err, ErrCeremonyNotFound)
	}
	consumed, err := repository.ConsumeAuthenticationCeremony(ceremony.IDHash, ceremony.Kind)
	if err != nil || consumed.UserID != administrator.ID || !reflect.DeepEqual(consumed.StateCiphertext, ceremony.StateCiphertext) {
		t.Fatalf("PostgreSQL WebAuthn ceremony round trip changed: %#v %v", consumed, err)
	}
	if _, err := repository.ConsumeAuthenticationCeremony(ceremony.IDHash, ceremony.Kind); !errors.Is(err, ErrCeremonyNotFound) {
		t.Fatalf("PostgreSQL ceremony replay error = %v, want %v", err, ErrCeremonyNotFound)
	}

	credential := model.WebAuthnCredential{ID: []byte("credential-id"), UserID: administrator.ID,
		Name: "Security key", CredentialCiphertext: []byte("encrypted-credential"), CreatedAt: now}
	if err := repository.CreateWebAuthnCredential(credential); err != nil {
		t.Fatalf("create PostgreSQL WebAuthn credential: %v", err)
	}
	lastUsed := now.Add(time.Minute)
	credential.CredentialCiphertext = []byte("updated-encrypted-credential")
	credential.SignCount = 7
	credential.BackupEligible = true
	credential.BackupState = true
	credential.LastUsedAt = &lastUsed
	if err := repository.UpdateWebAuthnCredential(credential); err != nil {
		t.Fatalf("update PostgreSQL WebAuthn credential: %v", err)
	}
	credentials, err := repository.ListWebAuthnCredentials(administrator.ID)
	if err != nil || len(credentials) != 1 {
		t.Fatalf("list PostgreSQL WebAuthn credentials: %#v %v", credentials, err)
	}
	stored := credentials[0]
	if !reflect.DeepEqual(stored.CredentialCiphertext, credential.CredentialCiphertext) || stored.SignCount != 7 ||
		!stored.BackupEligible || !stored.BackupState || stored.LastUsedAt == nil || !stored.LastUsedAt.Equal(lastUsed) {
		t.Fatalf("PostgreSQL WebAuthn authenticator state changed: %#v", stored)
	}
	deleted, err := repository.DeleteWebAuthnCredential(administrator.ID, credential.ID)
	if err != nil || !deleted {
		t.Fatalf("delete PostgreSQL WebAuthn credential: %t %v", deleted, err)
	}
	deleted, err = repository.DeleteWebAuthnCredential(administrator.ID, credential.ID)
	if err != nil || deleted {
		t.Fatalf("repeat PostgreSQL WebAuthn deletion changed: %t %v", deleted, err)
	}
}

func bootstrapPostgreSQLTestAdministrator(t *testing.T, repository *PostgreSQLStore, now time.Time) (model.User, model.BootstrapMFA, model.AuditEvent) {
	t.Helper()
	user := model.User{ID: "postgres-admin", Email: "Admin@Example.Test", DisplayName: "PostgreSQL Admin",
		Role: model.RoleAdministrator, Status: model.UserActive, MFARequired: true, CreatedAt: now, UpdatedAt: now}
	mfa := model.BootstrapMFA{TOTPSecretCiphertext: []byte("encrypted-totp"), RecoveryCodeHashes: [][]byte{[]byte("recovery-one")}}
	event := model.AuditEvent{OccurredAt: now, ActorID: user.ID, Action: "identity.bootstrap.completed",
		Severity: model.AuditInfo, TargetType: "user", TargetID: user.ID, Details: `{}`}
	if err := repository.BootstrapAdministrator(user, "password-hash", mfa, event); err != nil {
		t.Fatalf("bootstrap PostgreSQL administrator: %v", err)
	}
	return user, mfa, event
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
