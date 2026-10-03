package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"mossward/internal/agentmodule"
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

func TestPostgreSQLLocalAuthReplayAndThrottleState(t *testing.T) {
	repository, _ := openPostgreSQLIntegrationStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	administrator, mfa, _ := bootstrapPostgreSQLTestAdministrator(t, repository, now)
	consumed, err := repository.ConsumeTOTPCounter(administrator.ID, 10)
	if err != nil || !consumed {
		t.Fatalf("consume PostgreSQL TOTP counter: %t %v", consumed, err)
	}
	for _, replayedCounter := range []int64{10, 9} {
		consumed, err = repository.ConsumeTOTPCounter(administrator.ID, replayedCounter)
		if err != nil || consumed {
			t.Fatalf("PostgreSQL TOTP counter replay %d accepted: %t %v", replayedCounter, consumed, err)
		}
	}
	consumed, err = repository.ConsumeTOTPCounter(administrator.ID, 11)
	if err != nil || !consumed {
		t.Fatalf("consume newer PostgreSQL TOTP counter: %t %v", consumed, err)
	}
	secret, counter, err := repository.TOTPSecret(administrator.ID)
	if err != nil || !reflect.DeepEqual(secret, mfa.TOTPSecretCiphertext) || counter != 11 {
		t.Fatalf("PostgreSQL TOTP replay state changed: %q %d %v", secret, counter, err)
	}
	window := 10 * time.Minute
	baseBlock := time.Minute
	maximumBlock := 3 * time.Minute
	key := []byte("postgres-login-throttle-key")
	if _, err := repository.RecordLoginFailure(nil, now, window, 3, baseBlock, maximumBlock); err == nil {
		t.Fatal("PostgreSQL login throttle accepted an empty key")
	}
	for attempt := 1; attempt <= 2; attempt++ {
		blockedUntil, err := repository.RecordLoginFailure(key, now.Add(time.Duration(attempt)*time.Second),
			window, 3, baseBlock, maximumBlock)
		if err != nil || !blockedUntil.IsZero() {
			t.Fatalf("PostgreSQL login attempt %d blocked early: %v %v", attempt, blockedUntil, err)
		}
	}
	thirdAt := now.Add(3 * time.Second)
	blockedUntil, err := repository.RecordLoginFailure(key, thirdAt, window, 3, baseBlock, maximumBlock)
	if err != nil || !blockedUntil.Equal(thirdAt.Add(baseBlock)) {
		t.Fatalf("PostgreSQL login threshold block changed: %v %v", blockedUntil, err)
	}
	storedUntil, blocked, err := repository.LoginThrottle(key, thirdAt.Add(30*time.Second))
	if err != nil || !blocked || !storedUntil.Equal(blockedUntil) {
		t.Fatalf("PostgreSQL login throttle lookup changed: until=%v blocked=%t err=%v", storedUntil, blocked, err)
	}
	fourthAt := now.Add(4 * time.Second)
	blockedUntil, err = repository.RecordLoginFailure(key, fourthAt, window, 3, baseBlock, maximumBlock)
	if err != nil || !blockedUntil.Equal(fourthAt.Add(2*baseBlock)) {
		t.Fatalf("PostgreSQL escalating login block changed: %v %v", blockedUntil, err)
	}
	fifthAt := now.Add(5 * time.Second)
	blockedUntil, err = repository.RecordLoginFailure(key, fifthAt, window, 3, baseBlock, maximumBlock)
	if err != nil || !blockedUntil.Equal(fifthAt.Add(maximumBlock)) {
		t.Fatalf("PostgreSQL capped login block changed: %v %v", blockedUntil, err)
	}
	_, blocked, err = repository.LoginThrottle(key, blockedUntil)
	if err != nil || blocked {
		t.Fatalf("expired PostgreSQL login throttle remained active: blocked=%t err=%v", blocked, err)
	}
	resetKey := []byte("postgres-login-window-reset-key")
	if _, err := repository.RecordLoginFailure(resetKey, now, window, 2, baseBlock, maximumBlock); err != nil {
		t.Fatalf("record PostgreSQL reset-window login failure: %v", err)
	}
	resetAt := now.Add(window + time.Second)
	blockedUntil, err = repository.RecordLoginFailure(resetKey, resetAt, window, 2, baseBlock, maximumBlock)
	if err != nil || !blockedUntil.IsZero() {
		t.Fatalf("PostgreSQL login failure window did not reset: %v %v", blockedUntil, err)
	}
	if err := repository.ClearLoginFailures(key, resetKey); err != nil {
		t.Fatalf("clear PostgreSQL login failures: %v", err)
	}
	for _, clearedKey := range [][]byte{key, resetKey} {
		until, blocked, err := repository.LoginThrottle(clearedKey, now)
		if err != nil || blocked || !until.IsZero() {
			t.Fatalf("cleared PostgreSQL login throttle remained: until=%v blocked=%t err=%v", until, blocked, err)
		}
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

func TestPostgreSQLOIDCProviderTrustLifecycle(t *testing.T) {
	repository, _ := openPostgreSQLIntegrationStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	administrator, _, _ := bootstrapPostgreSQLTestAdministrator(t, repository, now)
	provider := model.OIDCProvider{ID: "entra", Name: "Microsoft Entra ID", IssuerURL: "https://login.example.test/tenant/v2.0",
		ClientID: "client-id", ProvisioningMode: model.ProvisionJIT, AllowedTenantID: "tenant-id",
		AllowedEmailDomains: []string{"example.test"}, AllowedGroups: []string{"security-team"},
		RoleMappings: map[string]model.UserRole{"security-team": model.RoleAnalyst}, DefaultRole: model.RoleViewer,
		Enabled: true, RedirectURL: "https://mossward.example.test/auth/oidc/callback", CreatedAt: now, UpdatedAt: now}
	record := model.OIDCProviderRecord{Provider: provider, ClientSecretCiphertext: []byte("encrypted-client-secret")}
	configureEvent := postgresIdentityAuditEvent(now, administrator.ID, "identity.oidc_provider.configured", "oidc_provider", provider.ID)
	if err := repository.UpsertOIDCProvider(record, configureEvent); err != nil {
		t.Fatalf("configure PostgreSQL OIDC provider: %v", err)
	}
	stored, err := repository.OIDCProvider(provider.ID)
	if err != nil || stored.Provider.Enabled || stored.Provider.TestedAt != nil ||
		!reflect.DeepEqual(stored.ClientSecretCiphertext, record.ClientSecretCiphertext) ||
		!reflect.DeepEqual(stored.Provider.RoleMappings, provider.RoleMappings) {
		t.Fatalf("PostgreSQL OIDC provider trust state changed: %#v %v", stored, err)
	}
	stateEvent := postgresIdentityAuditEvent(now.Add(time.Minute), administrator.ID,
		"identity.oidc_provider.enabled", "oidc_provider", provider.ID)
	if err := repository.SetOIDCProviderEnabled(provider.ID, true, now.Add(time.Minute), stateEvent); err == nil {
		t.Fatal("untested PostgreSQL OIDC provider was enabled")
	}
	if err := repository.MarkOIDCProviderTested(provider.ID, now.Add(2*time.Minute), stateEvent); err != nil {
		t.Fatalf("mark PostgreSQL OIDC provider tested: %v", err)
	}
	if err := repository.SetOIDCProviderEnabled(provider.ID, true, now.Add(3*time.Minute), stateEvent); err != nil {
		t.Fatalf("enable tested PostgreSQL OIDC provider: %v", err)
	}
	stored, err = repository.OIDCProvider(provider.ID)
	if err != nil || !stored.Provider.Enabled || stored.Provider.TestedAt == nil {
		t.Fatalf("tested PostgreSQL OIDC provider was not enabled: %#v %v", stored, err)
	}
	record.Provider.ClientID = "rotated-client-id"
	record.Provider.UpdatedAt = now.Add(4 * time.Minute)
	if err := repository.UpsertOIDCProvider(record, configureEvent); err != nil {
		t.Fatalf("rotate PostgreSQL OIDC provider configuration: %v", err)
	}
	stored, err = repository.OIDCProvider(provider.ID)
	if err != nil || stored.Provider.Enabled || stored.Provider.TestedAt != nil {
		t.Fatalf("changed PostgreSQL OIDC provider retained trust: %#v %v", stored, err)
	}
}

func TestPostgreSQLOIDCProvisioningModes(t *testing.T) {
	repository, _ := openPostgreSQLIntegrationStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	administrator, _, _ := bootstrapPostgreSQLTestAdministrator(t, repository, now)
	jitProvider := model.OIDCProvider{ID: "jit-provider", Name: "JIT provider", IssuerURL: "https://jit.example.test",
		ClientID: "jit-client", ProvisioningMode: model.ProvisionJIT, DefaultRole: model.RoleViewer,
		RedirectURL: "https://mossward.example.test/auth/oidc/callback", CreatedAt: now, UpdatedAt: now}
	configureEvent := postgresIdentityAuditEvent(now, administrator.ID, "identity.oidc_provider.configured", "oidc_provider", jitProvider.ID)
	if err := repository.UpsertOIDCProvider(model.OIDCProviderRecord{Provider: jitProvider,
		ClientSecretCiphertext: []byte("jit-encrypted-secret")}, configureEvent); err != nil {
		t.Fatalf("configure PostgreSQL JIT provider: %v", err)
	}
	claims := model.OIDCClaims{UserID: "jit-user", Subject: "jit-subject", Email: "JIT@Example.Test", Name: "JIT User", TenantID: "tenant"}
	loginEvent := postgresIdentityAuditEvent(now.Add(time.Minute), administrator.ID, "identity.oidc.login", "user", claims.UserID)
	user, err := repository.ResolveOIDCUser(jitProvider, claims, model.RoleViewer, now.Add(time.Minute), loginEvent)
	if err != nil || user.Email != "jit@example.test" || user.Role != model.RoleViewer {
		t.Fatalf("provision PostgreSQL JIT user: %#v %v", user, err)
	}
	user, err = repository.ResolveOIDCUser(jitProvider, claims, model.RoleAnalyst, now.Add(2*time.Minute), loginEvent)
	if err != nil || user.ID != claims.UserID || user.Role != model.RoleAnalyst {
		t.Fatalf("refresh PostgreSQL JIT user role: %#v %v", user, err)
	}

	inviteProvider := model.OIDCProvider{ID: "invite-provider", Name: "Invite provider", IssuerURL: "https://invite.example.test",
		ClientID: "invite-client", ProvisioningMode: model.ProvisionInviteOnly, DefaultRole: model.RoleViewer,
		RedirectURL: "https://mossward.example.test/auth/oidc/callback", CreatedAt: now, UpdatedAt: now}
	if err := repository.UpsertOIDCProvider(model.OIDCProviderRecord{Provider: inviteProvider,
		ClientSecretCiphertext: []byte("invite-encrypted-secret")}, configureEvent); err != nil {
		t.Fatalf("configure PostgreSQL invite-only provider: %v", err)
	}
	uninvitedClaims := model.OIDCClaims{UserID: "uninvited-user", Subject: "uninvited-subject", Email: "uninvited@example.test", Name: "Uninvited"}
	if _, err := repository.ResolveOIDCUser(inviteProvider, uninvitedClaims, model.RoleViewer, now, loginEvent); !errors.Is(err, ErrIdentityNotFound) {
		t.Fatalf("uninvited PostgreSQL SSO user error = %v, want %v", err, ErrIdentityNotFound)
	}
	invitation := model.Invitation{ID: "sso-invitation", Email: "invited@example.test", Role: model.RoleAnalyst,
		IdentityKind: model.IdentitySSO, InvitedBy: administrator.ID, ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		TokenHash: []byte("sso-invitation-token")}
	if err := repository.CreateInvitation(invitation, postgresIdentityAuditEvent(now, administrator.ID,
		"identity.invitation.created", "invitation", invitation.ID)); err != nil {
		t.Fatalf("create PostgreSQL SSO invitation: %v", err)
	}
	invitedClaims := model.OIDCClaims{UserID: "invited-user", Subject: "invited-subject", Email: invitation.Email, Name: "Invited User"}
	user, err = repository.ResolveOIDCUser(inviteProvider, invitedClaims, model.RoleViewer, now.Add(time.Minute), loginEvent)
	if err != nil || user.ID != invitedClaims.UserID || user.Role != model.RoleAnalyst {
		t.Fatalf("provision invited PostgreSQL SSO user: %#v %v", user, err)
	}
	if _, err := repository.ResolveOIDCUser(inviteProvider, model.OIDCClaims{UserID: "second-user", Subject: "second-subject",
		Email: invitation.Email, Name: "Second User"}, model.RoleViewer, now.Add(2*time.Minute), loginEvent); !errors.Is(err, ErrIdentityNotFound) {
		t.Fatalf("consumed PostgreSQL SSO invitation reuse error = %v, want %v", err, ErrIdentityNotFound)
	}
}

func TestPostgreSQLScopeAndPolicyTargetingContract(t *testing.T) {
	repository, _ := openPostgreSQLIntegrationStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	administrator, _, _ := bootstrapPostgreSQLTestAdministrator(t, repository, now)
	organization, err := repository.Organization()
	if err != nil || organization.ID == "" {
		t.Fatalf("load PostgreSQL installation organization: %#v %v", organization, err)
	}
	if err := repository.RequireOrganization("different-organization"); !errors.Is(err, ErrOrganizationBoundary) {
		t.Fatalf("PostgreSQL organization boundary error = %v, want %v", err, ErrOrganizationBoundary)
	}
	scope := model.ScopePolicy{ID: "postgres-scope", Name: "Production scope", AllowedCIDRs: []string{"192.0.2.0/24"},
		AllowedPorts: []int{443}, MaxTargets: 100, MaxConcurrent: 4, Enabled: true, CreatedBy: administrator.ID,
		CreatedAt: now, UpdatedAt: now}
	scopeEvent := postgresIdentityAuditEvent(now, administrator.ID, "scope.updated", "scope_policy", scope.ID)
	if err := repository.UpsertScopePolicy(scope, scopeEvent); err != nil {
		t.Fatalf("save PostgreSQL scope policy: %v", err)
	}
	storedScope, err := repository.ScopePolicy(scope.ID)
	if err != nil || storedScope.OrganizationID != organization.ID || !reflect.DeepEqual(storedScope.AllowedCIDRs, scope.AllowedCIDRs) ||
		!reflect.DeepEqual(storedScope.AllowedPorts, scope.AllowedPorts) {
		t.Fatalf("PostgreSQL scope policy round trip changed: %#v %v", storedScope, err)
	}

	if err := repository.Save(serviceHistoryScan("postgres-policy-asset", "postgres-policy-observation", now, true)); err != nil {
		t.Fatalf("create PostgreSQL policy target asset: %v", err)
	}
	assets, err := repository.ListAssets()
	if err != nil || len(assets) != 1 {
		t.Fatalf("load PostgreSQL policy target asset: %#v %v", assets, err)
	}
	groupEvent := postgresIdentityAuditEvent(now, administrator.ID, "asset_group.updated", "asset_group", "")
	for _, groupID := range []string{"postgres-group-one", "postgres-group-two"} {
		group := model.AssetGroup{ID: groupID, Name: groupID, Description: "Integration group", CreatedAt: now, UpdatedAt: now}
		if err := repository.UpsertAssetGroup(group, groupEvent); err != nil {
			t.Fatalf("save PostgreSQL asset group %q: %v", groupID, err)
		}
		if err := repository.AddAssetGroupMember(groupID, assets[0].ID, administrator.ID, now, groupEvent); err != nil {
			t.Fatalf("add overlapping PostgreSQL group member %q: %v", groupID, err)
		}
	}
	nextRun := now.Add(time.Hour)
	policy := model.ReusableScanPolicy{ID: "postgres-policy", Name: "Overnight production scan", ScopePolicyID: scope.ID,
		GroupIDs: []string{"postgres-group-one", "postgres-group-two"}, Ports: []int{443}, Enabled: true,
		CreatedAt: now, UpdatedAt: now, ScheduleKind: "cron", ScheduleExpression: "0 1 * * *",
		ScheduleTimezone: "America/Chicago", WindowStart: "01:00", WindowEnd: "06:00", RunMissed: false,
		LongRunAlertSeconds: 5 * 60 * 60, RateLimitPerSecond: 10, ExecutionMode: model.ScanExecutionRemote,
		WorkerSiteID: "chicago-hq", NextRunAt: &nextRun}
	policyEvent := postgresIdentityAuditEvent(now, administrator.ID, "scan_policy.updated", "scan_policy", policy.ID)
	if err := repository.UpsertReusableScanPolicy(policy, policyEvent); err != nil {
		t.Fatalf("save PostgreSQL reusable scan policy: %v", err)
	}
	storedPolicy, err := repository.ReusableScanPolicy(policy.ID)
	if err != nil || !reflect.DeepEqual(storedPolicy.GroupIDs, policy.GroupIDs) || storedPolicy.ScheduleTimezone != policy.ScheduleTimezone ||
		storedPolicy.WindowStart != policy.WindowStart || storedPolicy.WindowEnd != policy.WindowEnd ||
		storedPolicy.ExecutionMode != policy.ExecutionMode || storedPolicy.WorkerSiteID != policy.WorkerSiteID {
		t.Fatalf("PostgreSQL reusable scan policy round trip changed: %#v %v", storedPolicy, err)
	}
	targets, err := repository.ReusableScanPolicyTargets(policy.ID)
	if err != nil || len(targets) != 1 || len(targets[0].GroupIDs) != 2 || targets[0].Address != assets[0].Address {
		t.Fatalf("PostgreSQL overlapping policy targets were not deduplicated: %#v %v", targets, err)
	}
	groups, err := repository.ListAssetGroups()
	if err != nil || len(groups) != 2 || len(groups[0].ScanPolicyIDs) != 1 || len(groups[1].ScanPolicyIDs) != 1 {
		t.Fatalf("PostgreSQL reverse group policy visibility missing: %#v %v", groups, err)
	}
	lastScheduled := now.Add(30 * time.Minute)
	updatedNextRun := now.Add(24 * time.Hour)
	if err := repository.UpdateReusablePolicySchedule(policy.ID, &updatedNextRun, &lastScheduled, policyEvent); err != nil {
		t.Fatalf("update PostgreSQL reusable policy schedule: %v", err)
	}
	storedPolicy, err = repository.ReusableScanPolicy(policy.ID)
	if err != nil || storedPolicy.NextRunAt == nil || !storedPolicy.NextRunAt.Equal(updatedNextRun) ||
		storedPolicy.LastScheduledAt == nil || !storedPolicy.LastScheduledAt.Equal(lastScheduled) {
		t.Fatalf("PostgreSQL reusable policy schedule changed: %#v %v", storedPolicy, err)
	}
}

func TestPostgreSQLEndpointIdentityLifecycle(t *testing.T) {
	repository, _ := openPostgreSQLIntegrationStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	administrator, _, _ := bootstrapPostgreSQLTestAdministrator(t, repository, now)
	event := postgresIdentityAuditEvent(now, administrator.ID, "endpoint.enrollment_token.created", "endpoint", "")
	expiredToken := model.AgentEnrollmentToken{ID: "expired-endpoint-token", Name: "Expired token",
		TokenHash: []byte("expired-endpoint-token-hash"), CreatedBy: administrator.ID,
		CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)}
	if err := repository.CreateAgentEnrollmentToken(expiredToken, event); err != nil {
		t.Fatalf("create expired PostgreSQL endpoint token fixture: %v", err)
	}
	if _, err := repository.AgentEnrollmentTokenName(expiredToken.TokenHash, now); !errors.Is(err, ErrInvalidEnrollmentToken) {
		t.Fatalf("expired PostgreSQL endpoint token error = %v, want %v", err, ErrInvalidEnrollmentToken)
	}
	token := model.AgentEnrollmentToken{ID: "endpoint-token", Name: "Guarded workstation",
		TokenHash: []byte("endpoint-token-hash"), CreatedBy: administrator.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := repository.CreateAgentEnrollmentToken(token, event); err != nil {
		t.Fatalf("create PostgreSQL endpoint token: %v", err)
	}
	name, err := repository.AgentEnrollmentTokenName(token.TokenHash, now)
	if err != nil || name != token.Name {
		t.Fatalf("look up PostgreSQL endpoint token: %q %v", name, err)
	}
	endpoint := model.Endpoint{ID: "postgres-endpoint", Name: name, Status: model.EndpointActive,
		CertificateSerial: "endpoint-serial-one", CertificatePEM: "endpoint-certificate-one",
		EnrolledAt: now, ExpiresAt: now.Add(24 * time.Hour)}
	enrollEvent := postgresIdentityAuditEvent(now, administrator.ID, "endpoint.enrolled", "endpoint", endpoint.ID)
	if err := repository.ConsumeAgentEnrollmentToken(token.TokenHash, endpoint, now, enrollEvent); err != nil {
		t.Fatalf("enroll PostgreSQL endpoint: %v", err)
	}
	if err := repository.ConsumeAgentEnrollmentToken(token.TokenHash, endpoint, now, enrollEvent); !errors.Is(err, ErrInvalidEnrollmentToken) {
		t.Fatalf("PostgreSQL endpoint token reuse error = %v, want %v", err, ErrInvalidEnrollmentToken)
	}
	tokens, err := repository.ListAgentEnrollmentTokens(now)
	if err != nil || len(tokens) != 1 || tokens[0].UsedAt == nil || len(tokens[0].TokenHash) != 0 {
		t.Fatalf("PostgreSQL endpoint token listing changed: %#v %v", tokens, err)
	}

	collectors := []model.CollectorID{model.CollectorOperatingSystem, model.CollectorInstalledSoftware, model.CollectorSecurityPosture}
	policyEvent := postgresIdentityAuditEvent(now.Add(time.Minute), administrator.ID, "endpoint.policy.updated", "endpoint", endpoint.ID)
	if err := repository.SetEndpointCollectors(endpoint.ID, collectors, policyEvent); err != nil {
		t.Fatalf("set PostgreSQL endpoint collectors: %v", err)
	}
	exclusions := model.NetworkTelemetryExclusions{
		Applications: []model.NetworkTelemetryExclusion{{Kind: model.NetworkExcludeExecutable, Value: "/opt/private-client"}},
		Destinations: []model.NetworkTelemetryExclusion{{Kind: model.NetworkExcludeCIDR, Value: "192.0.2.0/24"}},
	}
	if err := repository.SetEndpointNetworkExclusions(endpoint.ID, exclusions, policyEvent); err != nil {
		t.Fatalf("set PostgreSQL endpoint network exclusions: %v", err)
	}
	generatedAt := now.Add(2 * time.Minute)
	receivedAt := generatedAt.Add(30 * time.Second)
	checkIn := model.AgentCheckIn{GeneratedAt: generatedAt, SoftwareVersion: "1.2.3", OperatingSystem: "linux", Architecture: "amd64"}
	if err := repository.RecordEndpointCheckIn(endpoint.ID, checkIn, receivedAt); err != nil {
		t.Fatalf("record PostgreSQL endpoint check-in: %v", err)
	}
	stored, err := repository.EndpointBySerial(endpoint.CertificateSerial)
	if err != nil || !reflect.DeepEqual(stored.AllowedCollectors, collectors) || !reflect.DeepEqual(stored.NetworkExclusions, exclusions) ||
		stored.SoftwareVersion != checkIn.SoftwareVersion || stored.OperatingSystem != checkIn.OperatingSystem ||
		stored.LastHeartbeatGeneratedAt == nil || !stored.LastHeartbeatGeneratedAt.Equal(generatedAt) ||
		stored.LastHeartbeatReceivedAt == nil || !stored.LastHeartbeatReceivedAt.Equal(receivedAt) {
		t.Fatalf("PostgreSQL endpoint check-in or policy state changed: %#v %v", stored, err)
	}

	renewedAt := now.Add(3 * time.Minute)
	renewed := endpoint
	renewed.CertificateSerial = "endpoint-serial-two"
	renewed.CertificatePEM = "endpoint-certificate-two"
	renewed.ExpiresAt = now.Add(90 * 24 * time.Hour)
	renewed.RenewedAt = &renewedAt
	renewEvent := postgresIdentityAuditEvent(renewedAt, administrator.ID, "endpoint.certificate.renewed", "endpoint", endpoint.ID)
	if err := repository.RenewEndpointCertificate(endpoint.CertificateSerial, renewed, renewEvent); err != nil {
		t.Fatalf("renew PostgreSQL endpoint certificate: %v", err)
	}
	if err := repository.RenewEndpointCertificate(endpoint.CertificateSerial, renewed, renewEvent); !errors.Is(err, ErrEndpointCertificateChanged) {
		t.Fatalf("stale PostgreSQL certificate renewal error = %v, want %v", err, ErrEndpointCertificateChanged)
	}
	if _, err := repository.EndpointBySerial(endpoint.CertificateSerial); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old PostgreSQL endpoint certificate remains current: %v", err)
	}
	revokedAt := now.Add(4 * time.Minute)
	revokeEvent := postgresIdentityAuditEvent(revokedAt, administrator.ID, "endpoint.revoked", "endpoint", endpoint.ID)
	if err := repository.RevokeEndpoint(endpoint.ID, "device retired", revokedAt, revokeEvent); err != nil {
		t.Fatalf("revoke PostgreSQL endpoint: %v", err)
	}
	stored, err = repository.EndpointBySerial(renewed.CertificateSerial)
	if err != nil || stored.Status != model.EndpointRevoked || stored.RevokedAt == nil || !stored.RevokedAt.Equal(revokedAt) ||
		stored.RevocationReason != "device retired" {
		t.Fatalf("PostgreSQL endpoint revocation state changed: %#v %v", stored, err)
	}
}

func TestPostgreSQLEndpointInventoryAndCVEProjection(t *testing.T) {
	repository, _ := openPostgreSQLIntegrationStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	administrator, _, _ := bootstrapPostgreSQLTestAdministrator(t, repository, now)
	endpoint := enrollPostgreSQLTestEndpoint(t, repository, administrator, now, "postgres-inventory-endpoint")
	receivedAt := now.Add(time.Minute)
	installedAt := now.Add(-24 * time.Hour)
	osInventory := model.EndpointOSInventory{Family: "linux", Name: "Example Linux", Version: "1", Build: "1.2",
		Kernel: "6.1.0", Architecture: "amd64", CollectedAt: now,
		Patches: []model.EndpointPatch{{ID: "kernel:6.1.0", Description: "Kernel patch level", InstalledAt: &installedAt}}}
	if err := repository.RecordEndpointOSInventory(endpoint.ID, osInventory, receivedAt); err != nil {
		t.Fatalf("record PostgreSQL endpoint OS inventory: %v", err)
	}
	storedOS, err := repository.EndpointOSInventory(endpoint.ID)
	if err != nil || storedOS.EndpointID != endpoint.ID || len(storedOS.Patches) != 1 ||
		storedOS.Patches[0].InstalledAt == nil || !storedOS.ReceivedAt.Equal(receivedAt) {
		t.Fatalf("PostgreSQL endpoint OS inventory changed: %#v %v", storedOS, err)
	}

	cve := model.CVERecord{ID: "CVE-POSTGRES-0001", Description: "OpenSSL integration fixture", PublishedAt: now,
		ModifiedAt: now, CVSSScore: 9.8, Severity: "critical", KnownExploited: true,
		SourceURL: "https://example.test/cve", Products: []model.AffectedProduct{{Vendor: "openssl", Product: "openssl",
			VersionStartIncluding: "3.0.0", VersionEndExcluding: "3.0.2", Vulnerable: true}}}
	if err := repository.UpsertCVEs([]model.CVERecord{cve}); err != nil {
		t.Fatalf("store PostgreSQL CVE fixture: %v", err)
	}
	software := model.EndpointSoftwareInventory{CollectedAt: now, Items: []model.InstalledSoftware{{
		Name: "openssl", Version: "3.0.1", Publisher: "OpenSSL", Architecture: "amd64", Source: "dpkg"}}}
	if err := repository.RecordEndpointSoftwareInventory(endpoint.ID, software, receivedAt); err != nil {
		t.Fatalf("record PostgreSQL endpoint software inventory: %v", err)
	}
	matches, err := repository.EndpointCVEMatches(endpoint.ID)
	if err != nil || len(matches) != 1 || matches[0].CVEID != cve.ID || !matches[0].KnownExploited ||
		matches[0].Confidence != "medium" || matches[0].PackageSource != "dpkg" {
		t.Fatalf("PostgreSQL endpoint CVE projection changed: %#v %v", matches, err)
	}
	software.Items[0].Version = "3.0.2"
	software.CollectedAt = now.Add(2 * time.Minute)
	if err := repository.RecordEndpointSoftwareInventory(endpoint.ID, software, now.Add(3*time.Minute)); err != nil {
		t.Fatalf("replace PostgreSQL endpoint software inventory: %v", err)
	}
	matches, err = repository.EndpointCVEMatches(endpoint.ID)
	if err != nil || len(matches) != 0 {
		t.Fatalf("stale PostgreSQL endpoint CVE matches remain: %#v %v", matches, err)
	}

	listening := model.EndpointListeningInventory{CollectedAt: now, Services: []model.ListeningService{{
		Protocol: "tcp", Address: "0.0.0.0", Port: 443, ProcessID: 10, ProcessName: "mossward-service", Executable: "/opt/mossward/service"}}}
	if err := repository.RecordEndpointListeningInventory(endpoint.ID, listening, receivedAt); err != nil {
		t.Fatalf("record PostgreSQL endpoint listening inventory: %v", err)
	}
	storedListening, err := repository.EndpointListeningInventory(endpoint.ID)
	if err != nil || len(storedListening.Services) != 1 || storedListening.Services[0].Executable != listening.Services[0].Executable {
		t.Fatalf("PostgreSQL endpoint listening inventory changed: %#v %v", storedListening, err)
	}
	posture := model.EndpointPostureInventory{CollectedAt: now, Evidence: []model.PostureEvidence{{
		ID: "secure_boot", Title: "Secure Boot", Status: "unknown", Detail: "State unavailable"}}}
	if err := repository.RecordEndpointPostureInventory(endpoint.ID, posture, receivedAt); err != nil {
		t.Fatalf("record PostgreSQL endpoint posture inventory: %v", err)
	}
	storedPosture, err := repository.EndpointPostureInventory(endpoint.ID)
	if err != nil || len(storedPosture.Evidence) != 1 || storedPosture.Evidence[0].Status != "unknown" {
		t.Fatalf("PostgreSQL endpoint posture inventory changed: %#v %v", storedPosture, err)
	}

	revokeEvent := postgresIdentityAuditEvent(now.Add(4*time.Minute), administrator.ID, "endpoint.revoked", "endpoint", endpoint.ID)
	if err := repository.RevokeEndpoint(endpoint.ID, "integration retirement", now.Add(4*time.Minute), revokeEvent); err != nil {
		t.Fatalf("revoke PostgreSQL inventory endpoint: %v", err)
	}
	if err := repository.RecordEndpointPostureInventory(endpoint.ID, posture, now.Add(5*time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked PostgreSQL endpoint inventory error = %v, want %v", err, ErrNotFound)
	}
}

func TestPostgreSQLEndpointIntegrityReplayAndChangeEvidence(t *testing.T) {
	repository, _ := openPostgreSQLIntegrationStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	administrator, _, _ := bootstrapPostgreSQLTestAdministrator(t, repository, now)
	endpoint := enrollPostgreSQLTestEndpoint(t, repository, administrator, now, "postgres-integrity-endpoint")
	hashA := strings.Repeat("a", 64)
	hashB := strings.Repeat("b", 64)
	baseline := model.SignedAgentIntegritySnapshot{Sequence: 1, Signature: "signature-one",
		Snapshot: model.AgentIntegritySnapshot{ExecutableSHA256: hashA, ConfigurationSHA256: hashA,
			IdentitySHA256: hashA, ObservedAt: now}}
	if err := repository.RecordEndpointIntegritySnapshot(endpoint.ID, baseline, now.Add(time.Second)); err != nil {
		t.Fatalf("record PostgreSQL endpoint integrity baseline: %v", err)
	}
	events, err := repository.EndpointIntegrityEvents(endpoint.ID)
	if err != nil || len(events) != 0 {
		t.Fatalf("PostgreSQL integrity baseline emitted changes: %#v %v", events, err)
	}
	changed := baseline
	changed.Sequence = 2
	changed.Signature = "signature-two"
	changed.Snapshot.ConfigurationSHA256 = hashB
	changed.Snapshot.IdentitySHA256 = hashB
	changed.Snapshot.ObservedAt = now.Add(time.Minute)
	receivedAt := now.Add(time.Minute + time.Second)
	if err := repository.RecordEndpointIntegritySnapshot(endpoint.ID, changed, receivedAt); err != nil {
		t.Fatalf("record PostgreSQL endpoint integrity changes: %v", err)
	}
	events, err = repository.EndpointIntegrityEvents(endpoint.ID)
	if err != nil || len(events) != 2 {
		t.Fatalf("PostgreSQL integrity component changes missing: %#v %v", events, err)
	}
	components := map[string]model.AgentIntegrityEvent{}
	for _, event := range events {
		components[event.Component] = event
	}
	for _, component := range []string{"configuration", "identity"} {
		event, found := components[component]
		if !found || event.PreviousSHA256 != hashA || event.CurrentSHA256 != hashB || event.Sequence != changed.Sequence ||
			event.Signature != changed.Signature || !event.ObservedAt.Equal(changed.Snapshot.ObservedAt) || !event.ReceivedAt.Equal(receivedAt) {
			t.Fatalf("PostgreSQL %s integrity evidence changed: %#v", component, event)
		}
	}
	if err := repository.RecordEndpointIntegritySnapshot(endpoint.ID, changed, now.Add(2*time.Minute)); !errors.Is(err, ErrEndpointIntegrityReplay) {
		t.Fatalf("PostgreSQL integrity replay error = %v, want %v", err, ErrEndpointIntegrityReplay)
	}
	overflow := changed
	overflow.Sequence = ^uint64(0)
	if err := repository.RecordEndpointIntegritySnapshot(endpoint.ID, overflow, now.Add(2*time.Minute)); err == nil {
		t.Fatal("out-of-range PostgreSQL integrity sequence was accepted")
	}
	revokeEvent := postgresIdentityAuditEvent(now.Add(3*time.Minute), administrator.ID, "endpoint.revoked", "endpoint", endpoint.ID)
	if err := repository.RevokeEndpoint(endpoint.ID, "integrity test retirement", now.Add(3*time.Minute), revokeEvent); err != nil {
		t.Fatalf("revoke PostgreSQL integrity endpoint: %v", err)
	}
	afterRevocation := changed
	afterRevocation.Sequence = 3
	if err := repository.RecordEndpointIntegritySnapshot(endpoint.ID, afterRevocation, now.Add(4*time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked PostgreSQL integrity endpoint error = %v, want %v", err, ErrNotFound)
	}
}

func TestPostgreSQLEndpointNetworkIndicatorDetection(t *testing.T) {
	repository, _ := openPostgreSQLIntegrationStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	administrator, _, _ := bootstrapPostgreSQLTestAdministrator(t, repository, now)
	endpoint := enrollPostgreSQLTestEndpoint(t, repository, administrator, now, "postgres-network-endpoint")
	inventory := model.EndpointNetworkInventory{CollectedAt: now, Connections: []model.NetworkConnection{
		{Protocol: "tcp", LocalAddress: "10.0.0.25", LocalPort: 51000, RemoteAddress: "198.51.100.10",
			RemotePort: 443, ProcessID: 42, ProcessName: "browser", Executable: "/usr/bin/browser",
			RemoteHostname: "command.example.test.", HostnameSource: "dns", TLSServerName: "command.example.test",
			Direction: "outbound_candidate"},
		{Protocol: "tcp", LocalAddress: "10.0.0.25", LocalPort: 51001, RemoteAddress: "198.51.100.11",
			RemotePort: 443, ProcessName: "updater", Direction: "outbound_candidate"},
	}}
	receivedAt := now.Add(time.Second)
	if err := repository.RecordEndpointNetworkInventory(endpoint.ID, inventory, receivedAt); err != nil {
		t.Fatalf("record PostgreSQL endpoint network inventory: %v", err)
	}
	storedInventory, err := repository.EndpointNetworkInventory(endpoint.ID)
	if err != nil || len(storedInventory.Connections) != 2 || !storedInventory.CollectedAt.Equal(now) ||
		!storedInventory.ReceivedAt.Equal(receivedAt) || storedInventory.Connections[0].TLSServerName != "command.example.test" {
		t.Fatalf("PostgreSQL endpoint network inventory changed: %#v %v", storedInventory, err)
	}
	indicators := []model.ThreatIndicator{
		{ID: "active-ip", Type: model.ThreatIndicatorIP, Value: "198.51.100.10", Source: "integration feed",
			Confidence: "high", ObservedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Enabled: true,
			CreatedBy: administrator.ID, CreatedAt: now, UpdatedAt: now},
		{ID: "active-hostname", Type: model.ThreatIndicatorHostname, Value: "command.example.test", Source: "integration feed",
			Confidence: "medium", ObservedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Enabled: true,
			CreatedBy: administrator.ID, CreatedAt: now, UpdatedAt: now},
		{ID: "expired-ip", Type: model.ThreatIndicatorIP, Value: "198.51.100.11", Source: "expired feed",
			Confidence: "low", ObservedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Minute), Enabled: true,
			CreatedBy: administrator.ID, CreatedAt: now, UpdatedAt: now},
		{ID: "disabled-ip", Type: model.ThreatIndicatorIP, Value: "198.51.100.11", Source: "disabled feed",
			Confidence: "high", ObservedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Enabled: false,
			CreatedBy: administrator.ID, CreatedAt: now, UpdatedAt: now},
	}
	indicatorEvent := postgresIdentityAuditEvent(now, administrator.ID, "threat_indicator.updated", "threat_indicator", "")
	for _, indicator := range indicators {
		if err := repository.UpsertThreatIndicator(indicator, now, indicatorEvent); err != nil {
			t.Fatalf("store PostgreSQL threat indicator %q: %v", indicator.ID, err)
		}
	}
	matches, err := repository.EndpointIndicatorMatches(endpoint.ID, now)
	if err != nil || len(matches) != 2 {
		t.Fatalf("PostgreSQL active threat detections changed: %#v %v", matches, err)
	}
	matchIDs := map[string]bool{}
	for _, match := range matches {
		matchIDs[match.IndicatorID] = true
		if match.RemoteAddress != "198.51.100.10" || match.ProcessName != "browser" || match.Executable != "/usr/bin/browser" {
			t.Fatalf("PostgreSQL threat detection lost network context: %#v", match)
		}
	}
	if !matchIDs["active-ip"] || !matchIDs["active-hostname"] || matchIDs["expired-ip"] || matchIDs["disabled-ip"] {
		t.Fatalf("PostgreSQL threat indicator filtering changed: %#v", matchIDs)
	}
	storedIndicators, err := repository.ListThreatIndicators()
	if err != nil || len(storedIndicators) != len(indicators) {
		t.Fatalf("PostgreSQL threat indicator listing changed: %#v %v", storedIndicators, err)
	}
	inventory.CollectedAt = now.Add(2 * time.Minute)
	inventory.Connections = nil
	if err := repository.RecordEndpointNetworkInventory(endpoint.ID, inventory, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("replace PostgreSQL endpoint network inventory: %v", err)
	}
	matches, err = repository.EndpointIndicatorMatches(endpoint.ID, now.Add(2*time.Minute))
	if err != nil || len(matches) != 0 {
		t.Fatalf("obsolete PostgreSQL threat detections remain: %#v %v", matches, err)
	}
}

func TestPostgreSQLRelayAuthorizationBoundaries(t *testing.T) {
	repository, _ := openPostgreSQLIntegrationStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	administrator, _, _ := bootstrapPostgreSQLTestAdministrator(t, repository, now)
	relay := enrollPostgreSQLTestEndpoint(t, repository, administrator, now, "postgres-relay-endpoint")
	downstream := enrollPostgreSQLTestEndpoint(t, repository, administrator, now, "postgres-downstream-endpoint")
	promotion := model.EndpointRelayAuthorization{ID: "postgres-relay-authorization", EndpointID: relay.ID,
		Status: model.EndpointRelayActive, PromotionReason: "guarded network bridge", PromotedBy: administrator.ID, PromotedAt: now}
	promoteEvent := postgresIdentityAuditEvent(now, administrator.ID, "endpoint.relay.promoted", "endpoint", relay.ID)
	if err := repository.PromoteEndpointRelay(promotion, promoteEvent); err != nil {
		t.Fatalf("promote PostgreSQL endpoint relay: %v", err)
	}
	if err := repository.PromoteEndpointRelay(promotion, promoteEvent); !errors.Is(err, ErrEndpointRelayAlreadyActive) {
		t.Fatalf("duplicate PostgreSQL relay promotion error = %v, want %v", err, ErrEndpointRelayAlreadyActive)
	}
	authorization := model.RelayDownstreamAuthorization{ID: "postgres-downstream-authorization", RelayEndpointID: relay.ID,
		DownstreamEndpointID: downstream.ID, Status: model.EndpointRelayActive, AuthorizationReason: "isolated segment",
		AuthorizedBy: administrator.ID, AuthorizedAt: now.Add(time.Minute)}
	downstreamEvent := postgresIdentityAuditEvent(now.Add(time.Minute), administrator.ID,
		"endpoint.relay_downstream.authorized", "endpoint", downstream.ID)
	selfAssignment := authorization
	selfAssignment.ID = "postgres-self-authorization"
	selfAssignment.DownstreamEndpointID = relay.ID
	if err := repository.AuthorizeRelayDownstream(selfAssignment, downstreamEvent); !errors.Is(err, ErrRelayDownstreamSelfAssignment) {
		t.Fatalf("PostgreSQL relay self-assignment error = %v, want %v", err, ErrRelayDownstreamSelfAssignment)
	}
	if err := repository.AuthorizeRelayDownstream(authorization, downstreamEvent); err != nil {
		t.Fatalf("authorize PostgreSQL relay downstream: %v", err)
	}
	if err := repository.AuthorizeRelayDownstream(authorization, downstreamEvent); !errors.Is(err, ErrRelayDownstreamAlreadyActive) {
		t.Fatalf("duplicate PostgreSQL downstream authorization error = %v, want %v", err, ErrRelayDownstreamAlreadyActive)
	}
	relays, err := repository.ListEndpointRelayAuthorizations()
	if err != nil || len(relays) != 1 || relays[0].Status != model.EndpointRelayActive {
		t.Fatalf("PostgreSQL active relay authorization missing: %#v %v", relays, err)
	}
	downstreams, err := repository.ListRelayDownstreamAuthorizations()
	if err != nil || len(downstreams) != 1 || downstreams[0].Status != model.EndpointRelayActive {
		t.Fatalf("PostgreSQL active downstream authorization missing: %#v %v", downstreams, err)
	}

	revokedAt := now.Add(2 * time.Minute)
	revokeEvent := postgresIdentityAuditEvent(revokedAt, administrator.ID, "endpoint.relay.revoked", "endpoint", relay.ID)
	if err := repository.RevokeEndpointRelay(relay.ID, "network path retired", administrator.ID, revokedAt, revokeEvent); err != nil {
		t.Fatalf("revoke PostgreSQL endpoint relay: %v", err)
	}
	relays, err = repository.ListEndpointRelayAuthorizations()
	if err != nil || len(relays) != 1 || relays[0].Status != model.EndpointRelayRevoked || relays[0].RevokedAt == nil ||
		!relays[0].RevokedAt.Equal(revokedAt) {
		t.Fatalf("PostgreSQL relay revocation state changed: %#v %v", relays, err)
	}
	downstreams, err = repository.ListRelayDownstreamAuthorizations()
	if err != nil || len(downstreams) != 1 || downstreams[0].Status != model.EndpointRelayRevoked ||
		downstreams[0].RevocationReason != "relay authorization revoked" || downstreams[0].RevokedAt == nil {
		t.Fatalf("PostgreSQL downstream cascade revocation changed: %#v %v", downstreams, err)
	}
	if err := repository.AuthorizeRelayDownstream(authorization, downstreamEvent); !errors.Is(err, ErrEndpointRelayUnavailable) {
		t.Fatalf("revoked PostgreSQL relay authorization error = %v, want %v", err, ErrEndpointRelayUnavailable)
	}
}

func TestPostgreSQLRelayWindowAndDelayedHeartbeatPolicy(t *testing.T) {
	repository, _ := openPostgreSQLIntegrationStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	administrator, _, _ := bootstrapPostgreSQLTestAdministrator(t, repository, now)
	if err := repository.Save(serviceHistoryScan("relay-policy-asset", "relay-policy-observation", now, true)); err != nil {
		t.Fatalf("create PostgreSQL relay-policy asset: %v", err)
	}
	assets, err := repository.ListAssets()
	if err != nil || len(assets) != 1 {
		t.Fatalf("load PostgreSQL relay-policy asset: %#v %v", assets, err)
	}
	endpoint := enrollPostgreSQLTestEndpoint(t, repository, administrator, now, "postgres-window-endpoint")
	if _, err := repository.db.Exec(`UPDATE endpoints SET asset_id=$1 WHERE id=$2`, assets[0].ID, endpoint.ID); err != nil {
		t.Fatalf("associate PostgreSQL endpoint with asset fixture: %v", err)
	}
	groupEvent := postgresIdentityAuditEvent(now, administrator.ID, "asset_group.updated", "asset_group", "")
	groupIDs := []string{"postgres-window-group-a", "postgres-window-group-b"}
	for _, groupID := range groupIDs {
		group := model.AssetGroup{ID: groupID, Name: groupID, Description: "Guarded segment", CreatedAt: now, UpdatedAt: now}
		if err := repository.UpsertAssetGroup(group, groupEvent); err != nil {
			t.Fatalf("create PostgreSQL relay-policy group %q: %v", groupID, err)
		}
		if err := repository.AddAssetGroupMember(groupID, assets[0].ID, administrator.ID, now, groupEvent); err != nil {
			t.Fatalf("add PostgreSQL relay-policy group member %q: %v", groupID, err)
		}
	}
	windows := []model.RelayUploadWindow{
		{ID: "postgres-endpoint-window", Name: "Endpoint overnight", TargetType: model.MaintenanceTargetEndpoint,
			TargetID: endpoint.ID, Timezone: "America/Chicago", Days: []time.Weekday{time.Monday, time.Wednesday},
			StartMinute: 60, EndMinute: 360, Enabled: true, Reason: "guarded endpoint network",
			CreatedBy: administrator.ID, CreatedAt: now, UpdatedBy: administrator.ID, UpdatedAt: now},
		{ID: "postgres-group-window", Name: "Group overnight", TargetType: model.MaintenanceTargetGroup,
			TargetID: groupIDs[0], Timezone: "UTC", Days: []time.Weekday{time.Tuesday}, StartMinute: 120,
			EndMinute: 240, Enabled: true, Reason: "guarded group network", CreatedBy: administrator.ID,
			CreatedAt: now, UpdatedBy: administrator.ID, UpdatedAt: now},
	}
	windowEvent := postgresIdentityAuditEvent(now, administrator.ID, "endpoint.relay_upload_window.updated", "relay_upload_window", "")
	for _, window := range windows {
		if err := repository.UpsertRelayUploadWindow(window, windowEvent); err != nil {
			t.Fatalf("save PostgreSQL relay upload window %q: %v", window.ID, err)
		}
	}
	applicable, err := repository.RelayUploadWindowsForEndpoint(endpoint.ID)
	if err != nil || len(applicable) != 2 {
		t.Fatalf("PostgreSQL inherited relay upload windows changed: %#v %v", applicable, err)
	}
	allWindows, err := repository.ListRelayUploadWindows()
	if err != nil || len(allWindows) != 2 || allWindows[0].Timezone == "" || len(allWindows[0].Days) == 0 {
		t.Fatalf("PostgreSQL relay upload-window persistence changed: %#v %v", allWindows, err)
	}
	missingWindow := windows[0]
	missingWindow.ID = "postgres-missing-window"
	missingWindow.TargetID = "missing-endpoint"
	if err := repository.UpsertRelayUploadWindow(missingWindow, windowEvent); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing PostgreSQL upload-window target error = %v, want %v", err, ErrNotFound)
	}

	heartbeatEvent := postgresIdentityAuditEvent(now, administrator.ID,
		"endpoint.delayed_heartbeat_policy.updated", "delayed_heartbeat_policy", "")
	groupPolicies := []model.DelayedHeartbeatPolicy{
		{TargetType: model.MaintenanceTargetGroup, TargetID: groupIDs[0], AllowDelayedHeartbeats: true,
			PostWindowGraceMinutes: 15, Reason: "scheduled relay delay", UpdatedBy: administrator.ID, UpdatedAt: now},
		{TargetType: model.MaintenanceTargetGroup, TargetID: groupIDs[1], AllowDelayedHeartbeats: false,
			Reason: "real-time heartbeat required", UpdatedBy: administrator.ID, UpdatedAt: now},
	}
	for _, policy := range groupPolicies {
		if err := repository.UpsertDelayedHeartbeatPolicy(policy, heartbeatEvent); err != nil {
			t.Fatalf("save PostgreSQL delayed-heartbeat policy for %q: %v", policy.TargetID, err)
		}
	}
	resolved, err := repository.ResolveDelayedHeartbeatPolicy(endpoint.ID)
	if err != nil || resolved.AllowDelayedHeartbeats || !resolved.Conflict || resolved.Source != "group_conflict_deny" {
		t.Fatalf("PostgreSQL delayed-heartbeat conflict did not fail closed: %#v %v", resolved, err)
	}
	override := model.DelayedHeartbeatPolicy{TargetType: model.MaintenanceTargetEndpoint, TargetID: endpoint.ID,
		AllowDelayedHeartbeats: true, PostWindowGraceMinutes: 30, Reason: "approved endpoint override",
		UpdatedBy: administrator.ID, UpdatedAt: now.Add(time.Minute)}
	if err := repository.UpsertDelayedHeartbeatPolicy(override, heartbeatEvent); err != nil {
		t.Fatalf("save PostgreSQL delayed-heartbeat endpoint override: %v", err)
	}
	resolved, err = repository.ResolveDelayedHeartbeatPolicy(endpoint.ID)
	if err != nil || !resolved.AllowDelayedHeartbeats || resolved.Conflict || resolved.Source != "endpoint_override" ||
		resolved.PostWindowGraceMinutes != override.PostWindowGraceMinutes {
		t.Fatalf("PostgreSQL delayed-heartbeat endpoint override changed: %#v %v", resolved, err)
	}
	if err := repository.DeleteDelayedHeartbeatPolicy(model.MaintenanceTargetEndpoint, endpoint.ID, heartbeatEvent); err != nil {
		t.Fatalf("delete PostgreSQL delayed-heartbeat endpoint override: %v", err)
	}
	resolved, err = repository.ResolveDelayedHeartbeatPolicy(endpoint.ID)
	if err != nil || resolved.AllowDelayedHeartbeats || !resolved.Conflict || resolved.Source != "group_conflict_deny" {
		t.Fatalf("PostgreSQL delayed-heartbeat inherited conflict was not restored: %#v %v", resolved, err)
	}
}

func TestPostgreSQLMaintenanceAndHeartbeatHealthPolicy(t *testing.T) {
	repository, _ := openPostgreSQLIntegrationStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	administrator, _, _ := bootstrapPostgreSQLTestAdministrator(t, repository, now)
	settings, err := repository.EndpointHeartbeatSettings()
	if err != nil || !settings.Enabled || settings.MissedAfterMinutes != 5 || settings.StaleAfterMinutes != 30 {
		t.Fatalf("PostgreSQL heartbeat defaults changed: %#v %v", settings, err)
	}
	settings.MissedAfterMinutes = 10
	settings.StaleAfterMinutes = 60
	settings.UpdatedBy = administrator.ID
	settings.UpdatedAt = now
	heartbeatEvent := postgresIdentityAuditEvent(now, administrator.ID,
		"endpoint.heartbeat_settings.updated", "endpoint_heartbeat_settings", "global")
	if err := repository.SetEndpointHeartbeatSettings(settings, heartbeatEvent); err != nil {
		t.Fatalf("update PostgreSQL heartbeat settings: %v", err)
	}
	storedSettings, err := repository.EndpointHeartbeatSettings()
	if err != nil || storedSettings.MissedAfterMinutes != 10 || storedSettings.StaleAfterMinutes != 60 ||
		storedSettings.UpdatedBy != administrator.ID || !storedSettings.UpdatedAt.Equal(now) {
		t.Fatalf("PostgreSQL heartbeat settings round trip changed: %#v %v", storedSettings, err)
	}
	invalidSettings := settings
	invalidSettings.StaleAfterMinutes = invalidSettings.MissedAfterMinutes
	if err := repository.SetEndpointHeartbeatSettings(invalidSettings, heartbeatEvent); err == nil {
		t.Fatal("invalid PostgreSQL heartbeat threshold ordering was accepted")
	}
	storedSettings, err = repository.EndpointHeartbeatSettings()
	if err != nil || storedSettings.StaleAfterMinutes != settings.StaleAfterMinutes {
		t.Fatalf("invalid PostgreSQL heartbeat update changed stored settings: %#v %v", storedSettings, err)
	}

	if err := repository.Save(serviceHistoryScan("maintenance-asset", "maintenance-observation", now, true)); err != nil {
		t.Fatalf("create PostgreSQL maintenance asset: %v", err)
	}
	assets, err := repository.ListAssets()
	if err != nil || len(assets) != 1 {
		t.Fatalf("load PostgreSQL maintenance asset: %#v %v", assets, err)
	}
	endpoint := enrollPostgreSQLTestEndpoint(t, repository, administrator, now, "postgres-maintenance-endpoint")
	if _, err := repository.db.Exec(`UPDATE endpoints SET asset_id=$1 WHERE id=$2`, assets[0].ID, endpoint.ID); err != nil {
		t.Fatalf("associate PostgreSQL maintenance endpoint fixture: %v", err)
	}
	group := model.AssetGroup{ID: "postgres-maintenance-group", Name: "Patch ring", CreatedAt: now, UpdatedAt: now}
	groupEvent := postgresIdentityAuditEvent(now, administrator.ID, "asset_group.updated", "asset_group", group.ID)
	if err := repository.UpsertAssetGroup(group, groupEvent); err != nil {
		t.Fatalf("create PostgreSQL maintenance group: %v", err)
	}
	if err := repository.AddAssetGroupMember(group.ID, assets[0].ID, administrator.ID, now, groupEvent); err != nil {
		t.Fatalf("add PostgreSQL maintenance group member: %v", err)
	}
	groupWindow := model.EndpointMaintenanceWindow{ID: "postgres-group-maintenance", Name: "Patch deployment",
		TargetType: model.MaintenanceTargetGroup, TargetID: group.ID, StartsAt: now.Add(-time.Minute),
		EndsAt: now.Add(time.Hour), Reason: "approved patch deployment", CreatedBy: administrator.ID, CreatedAt: now}
	maintenanceEvent := postgresIdentityAuditEvent(now, administrator.ID,
		"endpoint.maintenance.created", "endpoint_maintenance", groupWindow.ID)
	if err := repository.CreateEndpointMaintenanceWindow(groupWindow, maintenanceEvent); err != nil {
		t.Fatalf("create PostgreSQL group maintenance window: %v", err)
	}
	futureWindow := model.EndpointMaintenanceWindow{ID: "postgres-future-maintenance", Name: "Future endpoint work",
		TargetType: model.MaintenanceTargetEndpoint, TargetID: endpoint.ID, StartsAt: now.Add(2 * time.Hour),
		EndsAt: now.Add(3 * time.Hour), Reason: "future approved work", CreatedBy: administrator.ID, CreatedAt: now}
	if err := repository.CreateEndpointMaintenanceWindow(futureWindow, maintenanceEvent); err != nil {
		t.Fatalf("create PostgreSQL future endpoint maintenance window: %v", err)
	}
	active, err := repository.EndpointInMaintenance(endpoint.ID, now)
	if err != nil || !active {
		t.Fatalf("PostgreSQL group-inherited maintenance was not active: %t %v", active, err)
	}
	active, err = repository.EndpointInMaintenance(endpoint.ID, now.Add(90*time.Minute))
	if err != nil || active {
		t.Fatalf("PostgreSQL endpoint maintenance activated outside its windows: %t %v", active, err)
	}
	missingWindow := futureWindow
	missingWindow.ID = "postgres-missing-maintenance"
	missingWindow.TargetID = "missing-endpoint"
	if err := repository.CreateEndpointMaintenanceWindow(missingWindow, maintenanceEvent); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing PostgreSQL maintenance target error = %v, want %v", err, ErrNotFound)
	}
	cancelledAt := now.Add(time.Minute)
	cancelEvent := postgresIdentityAuditEvent(cancelledAt, administrator.ID,
		"endpoint.maintenance.cancelled", "endpoint_maintenance", groupWindow.ID)
	if err := repository.CancelEndpointMaintenanceWindow(groupWindow.ID, administrator.ID, cancelledAt, cancelEvent); err != nil {
		t.Fatalf("cancel PostgreSQL maintenance window: %v", err)
	}
	active, err = repository.EndpointInMaintenance(endpoint.ID, cancelledAt)
	if err != nil || active {
		t.Fatalf("cancelled PostgreSQL maintenance still suppresses health: %t %v", active, err)
	}
	windows, err := repository.ListEndpointMaintenanceWindows()
	if err != nil || len(windows) != 2 {
		t.Fatalf("list PostgreSQL maintenance history: %#v %v", windows, err)
	}
	foundCancelled := false
	for _, window := range windows {
		if window.ID == groupWindow.ID && window.CancelledAt != nil && window.CancelledAt.Equal(cancelledAt) &&
			window.CancelledBy == administrator.ID {
			foundCancelled = true
		}
	}
	if !foundCancelled {
		t.Fatalf("PostgreSQL cancelled maintenance history missing: %#v", windows)
	}
}

func TestPostgreSQLEndpointCoverageAndDiscoveryPolicy(t *testing.T) {
	repository, _ := openPostgreSQLIntegrationStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	administrator, _, _ := bootstrapPostgreSQLTestAdministrator(t, repository, now)
	assetFixtures := []struct{ id, name, address string }{
		{"coverage-linked-scan", "linked.example.test", "192.0.2.101"},
		{"coverage-eligible-scan", "eligible.example.test", "192.0.2.102"},
		{"coverage-unknown-scan", "unknown.example.test", "192.0.2.103"},
		{"coverage-ineligible-scan", "appliance.example.test", "192.0.2.104"},
		{"coverage-retired-scan", "retired.example.test", "192.0.2.105"},
	}
	for index, fixture := range assetFixtures {
		scan := completedAssetScan(fixture.id, fmt.Sprintf("coverage-observation-%d", index), fixture.name,
			fixture.address, now.Add(time.Duration(index)*time.Second))
		if err := repository.Save(scan); err != nil {
			t.Fatalf("create PostgreSQL coverage asset %q: %v", fixture.name, err)
		}
	}
	assets, err := repository.ListAssets()
	if err != nil || len(assets) != len(assetFixtures) {
		t.Fatalf("load PostgreSQL coverage assets: %#v %v", assets, err)
	}
	assetsByName := map[string]model.Asset{}
	for _, asset := range assets {
		assetsByName[asset.Name] = asset
	}
	linked := assetsByName["linked.example.test"]
	endpoint := enrollPostgreSQLTestEndpoint(t, repository, administrator, now, "postgres-coverage-endpoint")
	if _, err := repository.db.Exec(`UPDATE endpoints SET asset_id=$1 WHERE id=$2`, linked.ID, endpoint.ID); err != nil {
		t.Fatalf("associate PostgreSQL coverage endpoint fixture: %v", err)
	}
	eligibilityEvent := postgresIdentityAuditEvent(now, administrator.ID,
		"asset.agent_eligibility.updated", "asset", "")
	eligible := assetsByName["eligible.example.test"]
	if err := repository.UpdateAssetAgentEligibility(eligible.ID, model.AssetAgentEligibilityUpdate{
		Status: model.AgentEligibilityEligible, Reason: "managed workstation"}, eligibilityEvent); err != nil {
		t.Fatalf("classify PostgreSQL eligible coverage asset: %v", err)
	}
	ineligible := assetsByName["appliance.example.test"]
	if err := repository.UpdateAssetAgentEligibility(ineligible.ID, model.AssetAgentEligibilityUpdate{
		Status: model.AgentEligibilityIneligible, Reason: "network appliance"}, eligibilityEvent); err != nil {
		t.Fatalf("classify PostgreSQL ineligible coverage asset: %v", err)
	}
	retired := assetsByName["retired.example.test"]
	if err := repository.UpdateAssetLifecycle(retired.ID, model.AssetLifecycleUpdate{Status: model.AssetRetired,
		Reason: "decommissioned"}, postgresIdentityAuditEvent(now, administrator.ID, "asset.lifecycle.updated", "asset", retired.ID)); err != nil {
		t.Fatalf("retire PostgreSQL coverage asset: %v", err)
	}
	report, err := repository.EndpointCoverageReport(now)
	if err != nil || report.Enabled || len(report.Gaps) != 0 || len(report.Unclassified) != 0 {
		t.Fatalf("disabled PostgreSQL coverage report exposed results: %#v %v", report, err)
	}
	settings := model.EndpointCoverageSettings{Enabled: true, UpdatedBy: administrator.ID, UpdatedAt: now}
	coverageEvent := postgresIdentityAuditEvent(now, administrator.ID,
		"endpoint.coverage.updated", "endpoint_coverage", "global")
	if err := repository.SetEndpointCoverageSettings(settings, coverageEvent); err != nil {
		t.Fatalf("enable PostgreSQL endpoint coverage: %v", err)
	}
	report, err = repository.EndpointCoverageReport(now)
	if err != nil || !report.Enabled || len(report.Gaps) != 1 || report.Gaps[0].AssetID != eligible.ID ||
		len(report.Unclassified) != 1 || report.Unclassified[0].AssetID != assetsByName["unknown.example.test"].ID {
		t.Fatalf("PostgreSQL coverage classification changed: %#v %v", report, err)
	}
	settings.Enabled = false
	settings.UpdatedAt = now.Add(time.Minute)
	if err := repository.SetEndpointCoverageSettings(settings, coverageEvent); err != nil {
		t.Fatalf("disable PostgreSQL endpoint coverage: %v", err)
	}
	report, err = repository.EndpointCoverageReport(now.Add(time.Minute))
	if err != nil || report.Enabled || len(report.Gaps) != 0 || len(report.Unclassified) != 0 {
		t.Fatalf("disabled PostgreSQL coverage retained results: %#v %v", report, err)
	}

	discovery := model.CoverageDiscoveryPolicy{ID: "postgres-office-discovery", Name: "Office discovery",
		CIDRs: []string{"192.0.2.0/28", "198.51.100.0/28"}, Enabled: true, CreatedBy: administrator.ID,
		CreatedAt: now, UpdatedBy: administrator.ID, UpdatedAt: now}
	discoveryEvent := postgresIdentityAuditEvent(now, administrator.ID,
		"endpoint.coverage_discovery_policy.updated", "coverage_discovery_policy", discovery.ID)
	if err := repository.SaveCoverageDiscoveryPolicy(discovery, discoveryEvent); err != nil {
		t.Fatalf("save PostgreSQL coverage discovery policy: %v", err)
	}
	discovery.Name = "Office discovery updated"
	discovery.Enabled = false
	discovery.CreatedBy = ""
	discovery.CreatedAt = time.Time{}
	discovery.UpdatedAt = now.Add(time.Minute)
	if err := repository.SaveCoverageDiscoveryPolicy(discovery, discoveryEvent); err != nil {
		t.Fatalf("update PostgreSQL coverage discovery policy: %v", err)
	}
	policies, err := repository.ListCoverageDiscoveryPolicies()
	if err != nil || len(policies) != 1 || policies[0].Name != discovery.Name || policies[0].Enabled ||
		policies[0].CreatedBy != administrator.ID || !reflect.DeepEqual(policies[0].CIDRs, discovery.CIDRs) {
		t.Fatalf("PostgreSQL coverage discovery policy changed: %#v %v", policies, err)
	}
	missing := discovery
	missing.ID = "postgres-missing-discovery"
	if err := repository.SaveCoverageDiscoveryPolicy(missing, discoveryEvent); !errors.Is(err, ErrNotFound) {
		t.Fatalf("creator-less PostgreSQL discovery policy error = %v, want %v", err, ErrNotFound)
	}
}

func TestPostgreSQLWorkerIdentityAndLifecycle(t *testing.T) {
	repository, _ := openPostgreSQLIntegrationStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	administrator, _, _ := bootstrapPostgreSQLTestAdministrator(t, repository, now)
	tokenHash := []byte("postgres-worker-token-hash")
	token := model.WorkerEnrollmentToken{
		ID: "postgres-worker-token", Name: "Chicago worker", SiteID: "chicago-hq", TokenHash: tokenHash,
		AllowedCIDRs: []string{"192.0.2.0/24", "198.51.100.0/25"}, AllowedPorts: []int{22, 443},
		MaxConcurrent: 4, RateLimitPerSecond: 20, CreatedBy: administrator.ID, CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}
	if err := repository.CreateWorkerEnrollmentToken(token, postgresIdentityAuditEvent(now, administrator.ID,
		"scanner_worker.enrollment_token.created", "scanner_worker_enrollment_token", token.ID)); err != nil {
		t.Fatalf("create PostgreSQL scanner-worker enrollment token: %v", err)
	}
	loadedToken, err := repository.WorkerEnrollmentToken(tokenHash, now)
	if err != nil || loadedToken.SiteID != token.SiteID || !reflect.DeepEqual(loadedToken.AllowedCIDRs, token.AllowedCIDRs) ||
		!reflect.DeepEqual(loadedToken.AllowedPorts, token.AllowedPorts) || loadedToken.MaxConcurrent != token.MaxConcurrent ||
		loadedToken.RateLimitPerSecond != token.RateLimitPerSecond {
		t.Fatalf("PostgreSQL scanner-worker enrollment scope changed: %#v %v", loadedToken, err)
	}
	if _, err := repository.WorkerEnrollmentToken(tokenHash, token.ExpiresAt); !errors.Is(err, ErrInvalidEnrollmentToken) {
		t.Fatalf("expired PostgreSQL scanner-worker token error = %v, want %v", err, ErrInvalidEnrollmentToken)
	}
	worker := model.ScannerWorker{
		ID: "postgres-worker", Name: loadedToken.Name, SiteID: loadedToken.SiteID, Status: model.EndpointActive,
		CertificateSerial: "postgres-worker-serial", CertificatePEM: "postgres-worker-certificate",
		AllowedCIDRs: loadedToken.AllowedCIDRs, AllowedPorts: loadedToken.AllowedPorts,
		MaxConcurrent: loadedToken.MaxConcurrent, RateLimitPerSecond: loadedToken.RateLimitPerSecond,
		EnrolledAt: now, ExpiresAt: now.Add(24 * time.Hour),
	}
	if err := repository.ConsumeWorkerEnrollmentToken(tokenHash, worker, now, postgresIdentityAuditEvent(now,
		administrator.ID, "scanner_worker.enrolled", "scanner_worker", worker.ID)); err != nil {
		t.Fatalf("enroll PostgreSQL scanner worker: %v", err)
	}
	if err := repository.ConsumeWorkerEnrollmentToken(tokenHash, worker, now, postgresIdentityAuditEvent(now,
		administrator.ID, "scanner_worker.enrolled", "scanner_worker", worker.ID)); !errors.Is(err, ErrInvalidEnrollmentToken) {
		t.Fatalf("replayed PostgreSQL scanner-worker token error = %v, want %v", err, ErrInvalidEnrollmentToken)
	}
	stored, err := repository.ScannerWorkerBySerial(worker.CertificateSerial)
	if err != nil || stored.ID != worker.ID || stored.CertificatePEM != "" || !stored.DispatchEnabled ||
		!reflect.DeepEqual(stored.AllowedCIDRs, worker.AllowedCIDRs) || !reflect.DeepEqual(stored.AllowedPorts, worker.AllowedPorts) {
		t.Fatalf("PostgreSQL scanner-worker identity changed or exposed certificate material: %#v %v", stored, err)
	}
	settings, err := repository.ScannerWorkerDispatchSettings()
	if err != nil || !settings.Enabled {
		t.Fatalf("PostgreSQL scanner-worker dispatch secure default changed: %#v %v", settings, err)
	}
	heartbeatAt := now.Add(time.Minute)
	heartbeat := model.WorkerHeartbeat{SchemaVersion: 1, SoftwareVersion: "1.2.3", OperatingSystem: "linux",
		Architecture: "amd64", Capabilities: []model.WorkerCapability{model.WorkerCapabilityTCPConnect,
			model.WorkerCapabilityServiceIdentification}, AvailableConcurrency: 3, Health: model.WorkerHealthDegraded,
		HealthMessage: "rate limited"}
	if err := repository.RecordScannerWorkerHeartbeat(worker.ID, heartbeat, heartbeatAt); err != nil {
		t.Fatalf("record PostgreSQL scanner-worker heartbeat: %v", err)
	}
	workers, err := repository.ListScannerWorkers()
	if err != nil || len(workers) != 1 || workers[0].LastSeenAt == nil || !workers[0].LastSeenAt.Equal(heartbeatAt) ||
		workers[0].SoftwareVersion != heartbeat.SoftwareVersion || workers[0].Health != heartbeat.Health ||
		workers[0].HealthMessage != heartbeat.HealthMessage || workers[0].AvailableConcurrency != heartbeat.AvailableConcurrency ||
		!reflect.DeepEqual(workers[0].Capabilities, heartbeat.Capabilities) {
		t.Fatalf("PostgreSQL scanner-worker heartbeat state changed: %#v %v", workers, err)
	}
	dispatchEvent := postgresIdentityAuditEvent(now, administrator.ID,
		"scanner_worker.dispatch.updated", "scanner_worker_dispatch", "global")
	if err := repository.SetScannerWorkerDispatch(false, dispatchEvent); err != nil {
		t.Fatalf("disable global PostgreSQL scanner-worker dispatch: %v", err)
	}
	if err := repository.SetScannerWorkerDispatchForWorker(worker.ID, false, postgresIdentityAuditEvent(now,
		administrator.ID, "scanner_worker.dispatch.updated", "scanner_worker", worker.ID)); err != nil {
		t.Fatalf("disable PostgreSQL scanner-worker dispatch: %v", err)
	}
	settings, err = repository.ScannerWorkerDispatchSettings()
	workers, workersErr := repository.ListScannerWorkers()
	if err != nil || workersErr != nil || settings.Enabled || workers[0].DispatchEnabled {
		t.Fatalf("PostgreSQL scanner-worker dispatch controls changed: settings=%#v workers=%#v errors=%v %v",
			settings, workers, err, workersErr)
	}
	revokedAt := now.Add(2 * time.Minute)
	if err := repository.RevokeScannerWorker(worker.ID, "certificate compromise", revokedAt,
		postgresIdentityAuditEvent(revokedAt, administrator.ID, "scanner_worker.revoked", "scanner_worker", worker.ID)); err != nil {
		t.Fatalf("revoke PostgreSQL scanner worker: %v", err)
	}
	stored, err = repository.ScannerWorkerBySerial(worker.CertificateSerial)
	if err != nil || stored.Status != model.EndpointRevoked || stored.RevokedAt == nil || !stored.RevokedAt.Equal(revokedAt) ||
		stored.RevocationReason != "certificate compromise" {
		t.Fatalf("PostgreSQL scanner-worker revocation changed: %#v %v", stored, err)
	}
	if err := repository.RecordScannerWorkerHeartbeat(worker.ID, heartbeat, revokedAt); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked PostgreSQL scanner-worker heartbeat error = %v, want %v", err, ErrNotFound)
	}
	if err := repository.SetScannerWorkerDispatchForWorker(worker.ID, true, dispatchEvent); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked PostgreSQL scanner-worker dispatch error = %v, want %v", err, ErrNotFound)
	}
}

func TestPostgreSQLWorkerJobLeaseLifecycle(t *testing.T) {
	repository, _ := openPostgreSQLIntegrationStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	administrator, _, _ := bootstrapPostgreSQLTestAdministrator(t, repository, now)
	worker := enrollPostgreSQLTestWorker(t, repository, administrator, now, "postgres-job-worker")
	job := model.WorkerJob{
		SchemaVersion: 1, ID: "postgres-worker-job", WorkerID: worker.ID, ScanID: "postgres-worker-scan",
		IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute),
		Targets: []model.Target{{Name: "host", Address: "192.0.2.10"}}, Ports: []int{443},
		MaxConcurrent: 2, RateLimitPerSecond: 5,
		RequiredCapabilities: []model.WorkerCapability{model.WorkerCapabilityTCPConnect},
		Status:               model.WorkerJobPending,
	}
	envelope := model.SignedWorkerJob{Algorithm: "Ed25519", KeyID: "postgres-worker-job-key", Job: job,
		Signature: "postgres-worker-job-signature"}
	if err := repository.CreateScannerWorkerJob(envelope, now); err != nil {
		t.Fatalf("create PostgreSQL scanner-worker job: %v", err)
	}
	if err := repository.CreateScannerWorkerJob(envelope, now); !errors.Is(err, ErrWorkerJobReplay) {
		t.Fatalf("replayed PostgreSQL scanner-worker job error = %v, want %v", err, ErrWorkerJobReplay)
	}
	stored, err := repository.ScannerWorkerJob(job.ID)
	if err != nil || !reflect.DeepEqual(stored, envelope) {
		t.Fatalf("PostgreSQL signed scanner-worker job changed: %#v %v", stored, err)
	}
	loads, err := repository.ScannerWorkerJobLoads(now)
	if err != nil || loads[worker.ID].ActiveJobs != 1 || loads[worker.ID].ReservedConcurrency != job.MaxConcurrent {
		t.Fatalf("PostgreSQL scanner-worker load changed: %#v %v", loads, err)
	}
	if _, err := repository.LeaseScannerWorkerJob("different-worker", []byte("wrong-worker-lease"), now,
		now.Add(time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("PostgreSQL job leased to a different worker: %v", err)
	}
	firstLeaseHash := []byte("postgres-first-lease-hash")
	leased, err := repository.LeaseScannerWorkerJob(worker.ID, firstLeaseHash, now, now.Add(time.Minute))
	if err != nil || !reflect.DeepEqual(leased, envelope) {
		t.Fatalf("lease PostgreSQL scanner-worker job: %#v %v", leased, err)
	}
	if _, err := repository.LeaseScannerWorkerJob(worker.ID, []byte("duplicate-lease"), now.Add(30*time.Second),
		now.Add(90*time.Second)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("active PostgreSQL scanner-worker lease was issued twice: %v", err)
	}
	if _, err := repository.RenewScannerWorkerJobLease("different-worker", job.ID, firstLeaseHash,
		now.Add(30*time.Second), now.Add(90*time.Second)); !errors.Is(err, ErrInvalidWorkerJobLease) {
		t.Fatalf("different PostgreSQL worker renewed lease: %v", err)
	}
	if _, err := repository.RenewScannerWorkerJobLease(worker.ID, job.ID, []byte("wrong-lease-hash"),
		now.Add(30*time.Second), now.Add(90*time.Second)); !errors.Is(err, ErrInvalidWorkerJobLease) {
		t.Fatalf("wrong PostgreSQL lease token renewed lease: %v", err)
	}
	renewedUntil, err := repository.RenewScannerWorkerJobLease(worker.ID, job.ID, firstLeaseHash,
		now.Add(30*time.Second), now.Add(90*time.Second))
	if err != nil || !renewedUntil.Equal(now.Add(90*time.Second)) {
		t.Fatalf("renew PostgreSQL scanner-worker lease: %v %v", renewedUntil, err)
	}
	secondLeaseHash := []byte("postgres-second-lease-hash")
	reclaimedAt := now.Add(2 * time.Minute)
	if _, err := repository.LeaseScannerWorkerJob(worker.ID, secondLeaseHash, reclaimedAt,
		reclaimedAt.Add(time.Minute)); err != nil {
		t.Fatalf("reclaim expired PostgreSQL scanner-worker lease: %v", err)
	}
	renewedUntil, err = repository.RenewScannerWorkerJobLease(worker.ID, job.ID, secondLeaseHash,
		reclaimedAt.Add(30*time.Second), job.ExpiresAt.Add(time.Hour))
	if err != nil || !renewedUntil.Equal(job.ExpiresAt) {
		t.Fatalf("PostgreSQL scanner-worker renewal was not capped by job expiry: %v %v", renewedUntil, err)
	}
	var status model.WorkerJobStatus
	var storedLeaseHash []byte
	var attempts, assignments int
	if err := repository.db.QueryRow(`SELECT status,lease_token_hash,lease_attempt FROM scanner_worker_jobs WHERE id=$1`,
		job.ID).Scan(&status, &storedLeaseHash, &attempts); err != nil {
		t.Fatalf("read PostgreSQL scanner-worker lease state: %v", err)
	}
	if err := repository.db.QueryRow(`SELECT COUNT(*) FROM scanner_worker_job_assignments WHERE job_id=$1`,
		job.ID).Scan(&assignments); err != nil {
		t.Fatalf("read PostgreSQL scanner-worker assignment history: %v", err)
	}
	if status != model.WorkerJobLeased || !reflect.DeepEqual(storedLeaseHash, secondLeaseHash) || attempts != 2 || assignments != 1 {
		t.Fatalf("unexpected PostgreSQL scanner-worker lease state: status=%s hash=%q attempts=%d assignments=%d",
			status, storedLeaseHash, attempts, assignments)
	}
	if _, err := repository.LeaseScannerWorkerJob(worker.ID, []byte("expired-job-lease"), job.ExpiresAt,
		job.ExpiresAt.Add(time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired PostgreSQL scanner-worker job was leased: %v", err)
	}
	loads, err = repository.ScannerWorkerJobLoads(job.ExpiresAt)
	if err != nil || len(loads) != 0 {
		t.Fatalf("expired PostgreSQL scanner-worker job retained load: %#v %v", loads, err)
	}
	if err := repository.db.QueryRow(`SELECT status FROM scanner_worker_jobs WHERE id=$1`, job.ID).Scan(&status); err != nil {
		t.Fatalf("read expired PostgreSQL scanner-worker job: %v", err)
	}
	if status != model.WorkerJobExpired {
		t.Fatalf("PostgreSQL scanner-worker job status = %s, want %s", status, model.WorkerJobExpired)
	}
}

func TestPostgreSQLWorkerEvidenceAndResultProjection(t *testing.T) {
	repository, _ := openPostgreSQLIntegrationStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	administrator, _, _ := bootstrapPostgreSQLTestAdministrator(t, repository, now)
	worker := enrollPostgreSQLTestWorker(t, repository, administrator, now, "postgres-evidence-worker")
	job := model.WorkerJob{SchemaVersion: 1, ID: "postgres-evidence-job", WorkerID: worker.ID,
		ScanID: "postgres-evidence-scan", IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute),
		Targets: []model.Target{{Name: "host", Address: "192.0.2.20"}}, Ports: []int{443, 8443},
		MaxConcurrent: 1, RequiredCapabilities: []model.WorkerCapability{model.WorkerCapabilityTCPConnect},
		Status: model.WorkerJobPending}
	scan := model.Scan{ID: job.ScanID, Name: "PostgreSQL remote scan", Targets: job.Targets, Ports: job.Ports,
		Status: model.StatusQueued, TotalChecks: 2, CreatedAt: now}
	if err := repository.Save(scan); err != nil {
		t.Fatalf("save PostgreSQL remote scan: %v", err)
	}
	if err := repository.CreateScannerWorkerJob(model.SignedWorkerJob{Algorithm: "Ed25519",
		KeyID: "postgres-evidence-key", Job: job, Signature: "postgres-evidence-job-signature"}, now); err != nil {
		t.Fatalf("create PostgreSQL evidence job: %v", err)
	}
	leaseHash := []byte("postgres-evidence-lease-hash")
	if _, err := repository.LeaseScannerWorkerJob(worker.ID, leaseHash, now, now.Add(5*time.Minute)); err != nil {
		t.Fatalf("lease PostgreSQL evidence job: %v", err)
	}
	first := model.SignedWorkerEvidenceBatch{Algorithm: "Ed25519", CertificateSerial: worker.CertificateSerial,
		Signature: "postgres-evidence-signature-1", Batch: model.WorkerEvidenceBatch{SchemaVersion: 1,
			ID: "postgres-evidence-batch-1", WorkerID: worker.ID, JobID: job.ID, ScanID: job.ScanID,
			Sequence: 1, CollectedAt: now.Add(time.Minute),
			Observations: []model.ServiceObservation{{ID: "postgres-worker-observation", Target: "host",
				Address: "192.0.2.20", Port: 443, Protocol: "https", Product: "nginx", Version: "1.26",
				Confidence: "high", Evidence: "TLS service", ObservedAt: now.Add(time.Minute)}},
			Checkpoints: []model.WorkerCheckpoint{{Address: "192.0.2.20", Port: 443,
				CompletedAt: now.Add(time.Minute)}}}}
	if err := repository.RecordScannerWorkerEvidenceBatch(first, now.Add(time.Minute)); err != nil {
		t.Fatalf("record first PostgreSQL worker evidence batch: %v", err)
	}
	if err := repository.RecordScannerWorkerEvidenceBatch(first, now.Add(time.Minute)); !errors.Is(err, ErrWorkerEvidenceAlreadyAccepted) {
		t.Fatalf("exact PostgreSQL worker evidence retry error = %v, want %v", err, ErrWorkerEvidenceAlreadyAccepted)
	}
	tamperedBatch := first
	tamperedBatch.Signature = "tampered-signature"
	if err := repository.RecordScannerWorkerEvidenceBatch(tamperedBatch, now.Add(time.Minute)); !errors.Is(err, ErrWorkerEvidenceReplay) {
		t.Fatalf("changed PostgreSQL worker evidence replay error = %v, want %v", err, ErrWorkerEvidenceReplay)
	}
	gap := first
	gap.Batch.ID = "postgres-evidence-batch-3"
	gap.Batch.Sequence = 3
	if err := repository.RecordScannerWorkerEvidenceBatch(gap, now.Add(2*time.Minute)); !errors.Is(err, ErrWorkerEvidenceSequence) {
		t.Fatalf("PostgreSQL worker evidence sequence gap error = %v, want %v", err, ErrWorkerEvidenceSequence)
	}
	receipt := model.WorkerJobResultReceipt{ResultID: "postgres-worker-result", JobID: job.ID, WorkerID: worker.ID,
		Outcome: model.WorkerJobResultSucceeded, CompletedAt: now.Add(3 * time.Minute), AcceptedAt: now.Add(3 * time.Minute)}
	if err := repository.CompleteScannerWorkerJob(receipt, leaseHash, receipt.AcceptedAt); !errors.Is(err, ErrInvalidWorkerJobLease) {
		t.Fatalf("incomplete PostgreSQL worker result error = %v, want %v", err, ErrInvalidWorkerJobLease)
	}
	final := model.SignedWorkerEvidenceBatch{Algorithm: "Ed25519", CertificateSerial: worker.CertificateSerial,
		Signature: "postgres-evidence-signature-2", Batch: model.WorkerEvidenceBatch{SchemaVersion: 1,
			ID: "postgres-evidence-batch-2", WorkerID: worker.ID, JobID: job.ID, ScanID: job.ScanID,
			Sequence: 2, Final: true, CollectedAt: now.Add(2 * time.Minute),
			Findings: []model.Finding{{ID: "postgres-worker-finding", CheckID: "tls.configuration",
				Target: "host", Address: "192.0.2.20", Port: 8443, Service: "https", Severity: "medium",
				Title: "TLS configuration observed", Evidence: "remote evidence", ObservedAt: now.Add(2 * time.Minute)}},
			Checkpoints: []model.WorkerCheckpoint{{Address: "192.0.2.20", Port: 8443,
				CompletedAt: now.Add(2 * time.Minute)}}}}
	if err := repository.RecordScannerWorkerEvidenceBatch(final, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("record final PostgreSQL worker evidence batch: %v", err)
	}
	afterFinal := final
	afterFinal.Batch.ID = "postgres-evidence-after-final"
	afterFinal.Batch.Sequence = 3
	afterFinal.Batch.Final = false
	if err := repository.RecordScannerWorkerEvidenceBatch(afterFinal, now.Add(150*time.Second)); !errors.Is(err, ErrWorkerEvidenceSequence) {
		t.Fatalf("PostgreSQL evidence after final error = %v, want %v", err, ErrWorkerEvidenceSequence)
	}
	checkpoints, err := repository.ScannerWorkerJobCheckpoints(job.ID)
	if err != nil || len(checkpoints) != 2 || checkpoints[0].Port != 443 || checkpoints[1].Port != 8443 {
		t.Fatalf("PostgreSQL worker checkpoints changed: %#v %v", checkpoints, err)
	}
	if err := repository.CompleteScannerWorkerJob(receipt, leaseHash, receipt.AcceptedAt); err != nil {
		t.Fatalf("complete PostgreSQL worker job: %v", err)
	}
	if err := repository.CompleteScannerWorkerJob(receipt, leaseHash, receipt.AcceptedAt); !errors.Is(err, ErrWorkerResultAlreadyAccepted) {
		t.Fatalf("exact PostgreSQL worker result retry error = %v, want %v", err, ErrWorkerResultAlreadyAccepted)
	}
	tamperedReceipt := receipt
	tamperedReceipt.CompletedAt = tamperedReceipt.CompletedAt.Add(time.Second)
	if err := repository.CompleteScannerWorkerJob(tamperedReceipt, leaseHash, receipt.AcceptedAt); !errors.Is(err, ErrWorkerResultReplay) {
		t.Fatalf("changed PostgreSQL worker result replay error = %v, want %v", err, ErrWorkerResultReplay)
	}
	reusedReceipt := receipt
	reusedReceipt.ResultID = "postgres-worker-result-reuse"
	if err := repository.CompleteScannerWorkerJob(reusedReceipt, leaseHash, receipt.AcceptedAt); !errors.Is(err, ErrInvalidWorkerJobLease) {
		t.Fatalf("reused PostgreSQL worker lease error = %v, want %v", err, ErrInvalidWorkerJobLease)
	}
	projected, err := repository.Get(scan.ID)
	if err != nil || projected.Status != model.StatusCompleted || projected.DoneChecks != 2 ||
		len(projected.Observations) != 1 || len(projected.Findings) != 1 || len(projected.Checkpoints) != 2 ||
		projected.CompletedAt == nil || !projected.CompletedAt.Equal(receipt.CompletedAt) {
		t.Fatalf("PostgreSQL worker result projection changed: %#v %v", projected, err)
	}
	var sourceID string
	if err := repository.db.QueryRow(`SELECT source_id FROM asset_service_events WHERE observation_id=$1`,
		"postgres-worker-observation").Scan(&sourceID); err != nil {
		t.Fatalf("read PostgreSQL worker evidence provenance: %v", err)
	}
	if sourceID != "scanner-worker/"+worker.ID {
		t.Fatalf("PostgreSQL worker evidence source = %q, want %q", sourceID, "scanner-worker/"+worker.ID)
	}
}

func TestPostgreSQLWorkerReassignmentPreservesProgress(t *testing.T) {
	repository, _ := openPostgreSQLIntegrationStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	administrator, _, _ := bootstrapPostgreSQLTestAdministrator(t, repository, now)
	previousWorker := enrollPostgreSQLTestWorker(t, repository, administrator, now, "postgres-previous-worker")
	replacementWorker := enrollPostgreSQLTestWorker(t, repository, administrator, now, "postgres-replacement-worker")
	job := model.WorkerJob{SchemaVersion: 1, ID: "postgres-reassignment-job", WorkerID: previousWorker.ID,
		ScanID: "postgres-reassignment-scan", IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute),
		Targets: []model.Target{{Name: "first", Address: "192.0.2.30"}, {Name: "second", Address: "192.0.2.31"}},
		Ports:   []int{443}, MaxConcurrent: 1,
		RequiredCapabilities: []model.WorkerCapability{model.WorkerCapabilityTCPConnect}, Status: model.WorkerJobPending}
	if err := repository.CreateScannerWorkerJob(model.SignedWorkerJob{Algorithm: "Ed25519",
		KeyID: "postgres-reassignment-key", Job: job, Signature: "postgres-original-assignment"}, now); err != nil {
		t.Fatalf("create PostgreSQL reassignment job: %v", err)
	}
	if _, err := repository.LeaseScannerWorkerJob(previousWorker.ID, []byte("postgres-previous-lease"), now,
		now.Add(time.Minute)); err != nil {
		t.Fatalf("lease PostgreSQL reassignment job: %v", err)
	}
	first := model.SignedWorkerEvidenceBatch{Algorithm: "Ed25519", CertificateSerial: previousWorker.CertificateSerial,
		Signature: "postgres-previous-evidence", Batch: model.WorkerEvidenceBatch{SchemaVersion: 1,
			ID: "postgres-previous-batch", WorkerID: previousWorker.ID, JobID: job.ID, ScanID: job.ScanID,
			Sequence: 1, Final: true, CollectedAt: now,
			Checkpoints: []model.WorkerCheckpoint{{Address: "192.0.2.30", Port: 443, CompletedAt: now}}}}
	if err := repository.RecordScannerWorkerEvidenceBatch(first, now); err != nil {
		t.Fatalf("record PostgreSQL pre-reassignment evidence: %v", err)
	}
	if _, err := repository.ScannerWorkerJobResumeCandidate(job.ID, now.Add(30*time.Second)); !errors.Is(err, ErrWorkerJobNotResumable) {
		t.Fatalf("active PostgreSQL lease resume error = %v, want %v", err, ErrWorkerJobNotResumable)
	}
	resumeAt := now.Add(2 * time.Minute)
	candidate, err := repository.ScannerWorkerJobResumeCandidate(job.ID, resumeAt)
	if err != nil || candidate.Envelope.Job.WorkerID != previousWorker.ID || candidate.NextEvidenceSequence != 2 ||
		len(candidate.Completed) != 1 || candidate.Completed[0].Address != "192.0.2.30" {
		t.Fatalf("PostgreSQL worker resume candidate changed: %#v %v", candidate, err)
	}
	job.WorkerID = replacementWorker.ID
	job.Resume = &model.WorkerJobResume{PreviousWorkerID: previousWorker.ID, Completed: candidate.Completed,
		NextEvidenceSequence: candidate.NextEvidenceSequence + 1}
	replacement := model.SignedWorkerJob{Algorithm: "Ed25519", KeyID: "postgres-reassignment-key", Job: job,
		Signature: "postgres-replacement-assignment"}
	if err := repository.ReassignScannerWorkerJob(previousWorker.ID, replacement, resumeAt); !errors.Is(err, ErrWorkerJobNotResumable) {
		t.Fatalf("mismatched PostgreSQL resume state error = %v, want %v", err, ErrWorkerJobNotResumable)
	}
	replacement.Job.Resume.NextEvidenceSequence = candidate.NextEvidenceSequence
	if err := repository.ReassignScannerWorkerJob(previousWorker.ID, replacement, resumeAt); err != nil {
		t.Fatalf("reassign PostgreSQL scanner-worker job: %v", err)
	}
	late := first
	late.Batch.ID = "postgres-late-previous-batch"
	late.Batch.Sequence = 2
	if err := repository.RecordScannerWorkerEvidenceBatch(late, resumeAt); !errors.Is(err, ErrInvalidWorkerJobLease) {
		t.Fatalf("late PostgreSQL evidence from previous worker error = %v, want %v", err, ErrInvalidWorkerJobLease)
	}
	if _, err := repository.LeaseScannerWorkerJob(replacementWorker.ID, []byte("postgres-replacement-lease"), resumeAt,
		resumeAt.Add(time.Minute)); err != nil {
		t.Fatalf("lease reassigned PostgreSQL scanner-worker job: %v", err)
	}
	second := model.SignedWorkerEvidenceBatch{Algorithm: "Ed25519", CertificateSerial: replacementWorker.CertificateSerial,
		Signature: "postgres-replacement-evidence", Batch: model.WorkerEvidenceBatch{SchemaVersion: 1,
			ID: "postgres-replacement-batch", WorkerID: replacementWorker.ID, JobID: job.ID, ScanID: job.ScanID,
			Sequence: 2, Final: true, CollectedAt: resumeAt,
			Checkpoints: []model.WorkerCheckpoint{{Address: "192.0.2.31", Port: 443, CompletedAt: resumeAt}}}}
	if err := repository.RecordScannerWorkerEvidenceBatch(second, resumeAt); err != nil {
		t.Fatalf("continue PostgreSQL evidence after reassignment: %v", err)
	}
	checkpoints, err := repository.ScannerWorkerJobCheckpoints(job.ID)
	if err != nil || len(checkpoints) != 2 {
		t.Fatalf("PostgreSQL reassignment checkpoints changed: %#v %v", checkpoints, err)
	}
	rows, err := repository.db.Query(`SELECT attempt,worker_id,reason FROM scanner_worker_job_assignments
		WHERE job_id=$1 ORDER BY attempt`, job.ID)
	if err != nil {
		t.Fatalf("read PostgreSQL worker assignment history: %v", err)
	}
	defer rows.Close()
	type assignment struct {
		attempt  int
		workerID string
		reason   string
	}
	assignments := []assignment{}
	for rows.Next() {
		var item assignment
		if err := rows.Scan(&item.attempt, &item.workerID, &item.reason); err != nil {
			t.Fatalf("scan PostgreSQL worker assignment history: %v", err)
		}
		assignments = append(assignments, item)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate PostgreSQL worker assignment history: %v", err)
	}
	if len(assignments) != 2 || assignments[0].attempt != 1 || assignments[0].workerID != previousWorker.ID ||
		assignments[0].reason != "initial" || assignments[1].attempt != 2 ||
		assignments[1].workerID != replacementWorker.ID || assignments[1].reason != "expired_lease_resume" {
		t.Fatalf("PostgreSQL worker assignment history changed: %#v", assignments)
	}
}

func TestPostgreSQLWorkerJobDeadLetterQuarantine(t *testing.T) {
	repository, _ := openPostgreSQLIntegrationStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	administrator, _, _ := bootstrapPostgreSQLTestAdministrator(t, repository, now)
	worker := enrollPostgreSQLTestWorker(t, repository, administrator, now, "postgres-quarantine-worker")
	job := model.WorkerJob{SchemaVersion: 1, ID: "postgres-quarantine-job", WorkerID: worker.ID,
		ScanID: "postgres-quarantine-scan", IssuedAt: now, ExpiresAt: now.Add(time.Hour),
		Targets: []model.Target{{Name: "host", Address: "192.0.2.40"}}, Ports: []int{443},
		MaxConcurrent: 1, Status: model.WorkerJobPending}
	if err := repository.Save(model.Scan{ID: job.ScanID, Name: "PostgreSQL quarantined remote scan",
		Targets: job.Targets, Ports: job.Ports, Status: model.StatusQueued, TotalChecks: 1, CreatedAt: now}); err != nil {
		t.Fatalf("save PostgreSQL quarantine scan: %v", err)
	}
	if err := repository.CreateScannerWorkerJob(model.SignedWorkerJob{Job: job}, now); err != nil {
		t.Fatalf("create PostgreSQL quarantine job: %v", err)
	}
	leaseAt := now
	for attempt := 1; attempt <= maximumWorkerLeaseAttempts; attempt++ {
		if _, err := repository.LeaseScannerWorkerJob(worker.ID, []byte{byte(attempt)}, leaseAt,
			leaseAt.Add(time.Second)); err != nil {
			t.Fatalf("PostgreSQL quarantine lease attempt %d: %v", attempt, err)
		}
		leaseAt = leaseAt.Add(2 * time.Second)
	}
	if _, err := repository.ScannerWorkerJobResumeCandidate(job.ID, leaseAt); !errors.Is(err, ErrWorkerJobQuarantined) {
		t.Fatalf("PostgreSQL repeatedly expired job error = %v, want %v", err, ErrWorkerJobQuarantined)
	}
	if _, err := repository.LeaseScannerWorkerJob(worker.ID, []byte("post-quarantine-lease"), leaseAt,
		leaseAt.Add(time.Second)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("quarantined PostgreSQL worker job was leased: %v", err)
	}
	deadLetters, err := repository.ListScannerWorkerDeadLetters()
	if err != nil || len(deadLetters) != 1 || deadLetters[0].JobID != job.ID || deadLetters[0].ScanID != job.ScanID ||
		deadLetters[0].WorkerID != worker.ID || deadLetters[0].FailureCount != maximumWorkerLeaseAttempts ||
		deadLetters[0].Reason != workerLeaseFailureReason || !deadLetters[0].QuarantinedAt.Equal(leaseAt) {
		t.Fatalf("PostgreSQL worker dead letter changed: %#v %v", deadLetters, err)
	}
	stored, err := repository.ScannerWorkerJob(job.ID)
	if err != nil || stored.Job.ID != job.ID {
		t.Fatalf("load quarantined PostgreSQL worker job envelope: %#v %v", stored, err)
	}
	var status model.WorkerJobStatus
	if err := repository.db.QueryRow(`SELECT status FROM scanner_worker_jobs WHERE id=$1`, job.ID).Scan(&status); err != nil {
		t.Fatalf("read quarantined PostgreSQL worker job status: %v", err)
	}
	if status != model.WorkerJobCanceled {
		t.Fatalf("quarantined PostgreSQL worker job status = %s, want %s", status, model.WorkerJobCanceled)
	}
	projected, err := repository.Get(job.ScanID)
	if err != nil || projected.Status != model.StatusFailed || projected.Error != workerLeaseFailureReason ||
		projected.CompletedAt == nil || !projected.CompletedAt.Equal(leaseAt) {
		t.Fatalf("PostgreSQL quarantined scan state changed: %#v %v", projected, err)
	}
}

func TestPostgreSQLFindingWorkflowAndEvidenceRetention(t *testing.T) {
	repository, _ := openPostgreSQLIntegrationStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	administrator, _, _ := bootstrapPostgreSQLTestAdministrator(t, repository, now)
	old := now.AddDate(-2, 0, 0)
	heldScan := model.Scan{ID: "postgres-held-scan", Name: "Held evidence", Status: model.StatusCompleted,
		CreatedAt: old, CompletedAt: &old, Findings: []model.Finding{{ID: "postgres-held-finding",
			CheckID: "tls.configuration", Target: "held-host", Address: "192.0.2.50", Port: 443,
			Service: "https", Severity: "medium", Title: "Held finding", ObservedAt: old}}}
	if err := repository.Save(heldScan); err != nil {
		t.Fatalf("save PostgreSQL finding workflow scan: %v", err)
	}
	workflowEvent := postgresIdentityAuditEvent(now, administrator.ID,
		"finding.workflow.updated", "finding", heldScan.Findings[0].ID)
	if err := repository.UpdateFindingWorkflow(heldScan.Findings[0].ID,
		model.FindingWorkflowUpdate{Status: model.FindingInProgress, AssignedTo: "missing-user"}, now,
		workflowEvent); !errors.Is(err, ErrInvalidFindingWorkflow) {
		t.Fatalf("missing PostgreSQL finding assignee error = %v, want %v", err, ErrInvalidFindingWorkflow)
	}
	if err := repository.UpdateFindingWorkflow(heldScan.Findings[0].ID,
		model.FindingWorkflowUpdate{Status: model.FindingInProgress, AssignedTo: administrator.ID}, now,
		workflowEvent); err != nil {
		t.Fatalf("update PostgreSQL finding workflow: %v", err)
	}
	loaded, err := repository.Get(heldScan.ID)
	if err != nil || len(loaded.Findings) != 1 || loaded.Findings[0].Status != model.FindingInProgress ||
		loaded.Findings[0].AssignedTo != administrator.ID || loaded.Findings[0].WorkflowUpdatedAt == nil ||
		!loaded.Findings[0].WorkflowUpdatedAt.Equal(now) {
		t.Fatalf("PostgreSQL finding workflow changed: %#v %v", loaded.Findings, err)
	}
	exception := model.FindingException{ID: "postgres-finding-exception", FindingID: heldScan.Findings[0].ID,
		Reason: "Temporary vendor dependency", Status: model.ExceptionPending, RequestedBy: administrator.ID,
		CreatedAt: old, ReminderDays: 30}
	exceptionEvent := postgresIdentityAuditEvent(now, administrator.ID,
		"finding.exception.requested", "finding_exception", exception.ID)
	if err := repository.SaveFindingException(exception, exceptionEvent); err != nil {
		t.Fatalf("save PostgreSQL finding exception: %v", err)
	}
	if err := repository.ReviewFindingException(exception.ID, model.ExceptionApproved, administrator.ID, now,
		postgresIdentityAuditEvent(now, administrator.ID, "finding.exception.approved", "finding_exception",
			exception.ID)); err != nil {
		t.Fatalf("approve PostgreSQL finding exception: %v", err)
	}
	if err := repository.ReviewFindingException(exception.ID, model.ExceptionRejected, administrator.ID, now,
		exceptionEvent); !errors.Is(err, ErrFindingNotFound) {
		t.Fatalf("reviewed PostgreSQL finding exception error = %v, want %v", err, ErrFindingNotFound)
	}
	exceptions, err := repository.ListFindingExceptions()
	if err != nil || len(exceptions) != 1 || exceptions[0].Status != model.ExceptionApproved ||
		exceptions[0].ApprovedBy != administrator.ID || exceptions[0].ExpiresAt != nil {
		t.Fatalf("PostgreSQL finding exception changed: %#v %v", exceptions, err)
	}
	due, err := repository.DueOpenEndedExceptions(now)
	if err != nil || len(due) != 1 || due[0].ID != exception.ID {
		t.Fatalf("PostgreSQL exception reminder schedule changed: %#v %v", due, err)
	}
	if err := repository.MarkExceptionReminded(exception.ID, now); err != nil {
		t.Fatalf("mark PostgreSQL finding exception reminded: %v", err)
	}
	due, err = repository.DueOpenEndedExceptions(now)
	if err != nil || len(due) != 0 {
		t.Fatalf("reminded PostgreSQL exception remained due: %#v %v", due, err)
	}
	settings, err := repository.EvidenceRetentionSettings()
	if err != nil || settings.RetentionDays != 365 {
		t.Fatalf("PostgreSQL evidence retention default changed: %#v %v", settings, err)
	}
	retentionEvent := postgresIdentityAuditEvent(now, administrator.ID,
		"evidence.retention.updated", "evidence_retention", "global")
	if err := repository.SaveEvidenceRetentionSettings(model.EvidenceRetentionSettings{RetentionDays: 29,
		UpdatedAt: now}, retentionEvent); !errors.Is(err, ErrInvalidFindingWorkflow) {
		t.Fatalf("invalid PostgreSQL evidence retention error = %v, want %v", err, ErrInvalidFindingWorkflow)
	}
	settings = model.EvidenceRetentionSettings{RetentionDays: 30, UpdatedAt: now}
	if err := repository.SaveEvidenceRetentionSettings(settings, retentionEvent); err != nil {
		t.Fatalf("save PostgreSQL evidence retention settings: %v", err)
	}
	storedSettings, err := repository.EvidenceRetentionSettings()
	if err != nil || storedSettings.RetentionDays != settings.RetentionDays || !storedSettings.UpdatedAt.Equal(now) {
		t.Fatalf("PostgreSQL evidence retention settings changed: %#v %v", storedSettings, err)
	}
	expiredScan := model.Scan{ID: "postgres-expired-scan", Name: "Expired evidence", Status: model.StatusCompleted,
		CreatedAt: old, CompletedAt: &old}
	if err := repository.Save(expiredScan); err != nil {
		t.Fatalf("save PostgreSQL expired evidence fixture: %v", err)
	}
	removed, err := repository.PurgeExpiredEvidence(now)
	if err != nil || removed != 1 {
		t.Fatalf("purge PostgreSQL expired evidence: removed=%d err=%v", removed, err)
	}
	if _, err := repository.Get(expiredScan.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired PostgreSQL evidence remained: %v", err)
	}
	if _, err := repository.Get(heldScan.ID); err != nil {
		t.Fatalf("approved-exception PostgreSQL evidence was purged: %v", err)
	}
	events, err := repository.ListAuditEvents(model.AuditQuery{Text: "finding.", Limit: 10})
	if err != nil || len(events) < 3 {
		t.Fatalf("PostgreSQL finding workflow audit trail missing: %#v %v", events, err)
	}
}

func TestPostgreSQLNotificationSettingsAndAlertDeduplication(t *testing.T) {
	repository, _ := openPostgreSQLIntegrationStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	administrator, _, _ := bootstrapPostgreSQLTestAdministrator(t, repository, now)
	empty, err := repository.SMTPSettings()
	if err != nil || empty.Enabled || empty.HasPassword || len(empty.RecipientUserIDs) != 0 {
		t.Fatalf("unexpected initial PostgreSQL SMTP settings: %#v %v", empty, err)
	}
	settings := model.SMTPSettings{Enabled: true, Host: "smtp.example.test", Port: 587,
		Username: "mossward@example.test", PasswordCiphertext: []byte("encrypted-smtp-password-v1"),
		FromAddress: "mossward@example.test", TLSMode: "starttls",
		RecipientUserIDs: []string{administrator.ID}}
	event := postgresIdentityAuditEvent(now, administrator.ID,
		"notification.smtp.updated", "smtp_settings", "global")
	if err := repository.SaveSMTPSettings(settings, event); err != nil {
		t.Fatalf("save PostgreSQL SMTP settings: %v", err)
	}
	stored, err := repository.SMTPSettings()
	if err != nil || !stored.Enabled || stored.Host != settings.Host || stored.Port != settings.Port ||
		stored.Username != settings.Username || !stored.HasPassword ||
		!reflect.DeepEqual(stored.PasswordCiphertext, settings.PasswordCiphertext) ||
		stored.FromAddress != settings.FromAddress || stored.TLSMode != settings.TLSMode ||
		!reflect.DeepEqual(stored.RecipientUserIDs, settings.RecipientUserIDs) {
		t.Fatalf("PostgreSQL SMTP settings changed: %#v %v", stored, err)
	}
	invalid := settings
	invalid.Host = "invalid-smtp.example.test"
	invalid.PasswordCiphertext = []byte("invalid-replacement-ciphertext")
	invalid.RecipientUserIDs = []string{"missing-recipient"}
	if err := repository.SaveSMTPSettings(invalid, event); err == nil {
		t.Fatal("PostgreSQL SMTP settings accepted a missing recipient")
	}
	afterRollback, err := repository.SMTPSettings()
	if err != nil || afterRollback.Host != settings.Host ||
		!reflect.DeepEqual(afterRollback.PasswordCiphertext, settings.PasswordCiphertext) ||
		!reflect.DeepEqual(afterRollback.RecipientUserIDs, settings.RecipientUserIDs) {
		t.Fatalf("failed PostgreSQL SMTP update was partially applied: %#v %v", afterRollback, err)
	}
	settings.PasswordCiphertext = []byte("encrypted-smtp-password-v2")
	settings.Port = 465
	settings.TLSMode = "tls"
	settings.RecipientUserIDs = []string{}
	if err := repository.SaveSMTPSettings(settings, postgresIdentityAuditEvent(now.Add(time.Minute), administrator.ID,
		"notification.smtp.updated", "smtp_settings", "global")); err != nil {
		t.Fatalf("rotate PostgreSQL SMTP credential: %v", err)
	}
	rotated, err := repository.SMTPSettings()
	if err != nil || !rotated.HasPassword || rotated.Port != settings.Port || rotated.TLSMode != settings.TLSMode ||
		!reflect.DeepEqual(rotated.PasswordCiphertext, settings.PasswordCiphertext) || len(rotated.RecipientUserIDs) != 0 {
		t.Fatalf("PostgreSQL SMTP credential rotation changed: %#v %v", rotated, err)
	}
	scan := model.Scan{ID: "postgres-long-alert-scan", Name: "Long running scan", Status: model.StatusRunning,
		CreatedAt: now}
	if err := repository.Save(scan); err != nil {
		t.Fatalf("save PostgreSQL long-alert scan: %v", err)
	}
	if err := repository.MarkScanLongAlertSent(scan.ID); err != nil {
		t.Fatalf("mark PostgreSQL long-running alert: %v", err)
	}
	if err := repository.MarkScanLongAlertSent(scan.ID); err != nil {
		t.Fatalf("repeat PostgreSQL long-running alert marker: %v", err)
	}
	loaded, err := repository.Get(scan.ID)
	if err != nil || !loaded.LongAlertSent {
		t.Fatalf("PostgreSQL long-running alert marker missing: %#v %v", loaded, err)
	}
	var alertMarkers int
	if err := repository.db.QueryRow(`SELECT COUNT(*) FROM scan_long_alerts WHERE scan_id=$1`, scan.ID).
		Scan(&alertMarkers); err != nil {
		t.Fatalf("count PostgreSQL long-running alert markers: %v", err)
	}
	if alertMarkers != 1 {
		t.Fatalf("PostgreSQL long-running alert markers = %d, want 1", alertMarkers)
	}
	events, err := repository.ListAuditEvents(model.AuditQuery{Text: "notification.smtp.updated", Limit: 10})
	if err != nil || len(events) != 2 {
		t.Fatalf("PostgreSQL SMTP audit trail changed: %#v %v", events, err)
	}
}

func TestPostgreSQLAgentUpdateReleaseAndAssignmentLifecycle(t *testing.T) {
	repository, _ := openPostgreSQLIntegrationStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	administrator, _, _ := bootstrapPostgreSQLTestAdministrator(t, repository, now)
	endpoint := enrollPostgreSQLTestEndpoint(t, repository, administrator, now, "postgres-update-endpoint")
	checkIn := model.AgentCheckIn{SchemaVersion: 1, SoftwareVersion: "1.0.0", OperatingSystem: "linux",
		Architecture: "amd64"}
	if err := repository.RecordEndpointCheckIn(endpoint.ID, checkIn, now); err != nil {
		t.Fatalf("establish PostgreSQL update endpoint platform: %v", err)
	}
	release := model.AgentUpdateRelease{ID: "postgres-agent-update", Version: "1.2.3", OperatingSystem: "linux",
		Architecture: "amd64", ArtifactSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ArtifactSize: 4096, SigningKeyID: "postgres-agent-update-key",
		Envelope: []byte(`{"signed":true,"version":"1.2.3"}`), Status: model.AgentUpdateStaged,
		CreatedBy: administrator.ID, CreatedAt: now}
	if err := repository.CreateAgentUpdateRelease(release, postgresIdentityAuditEvent(now, administrator.ID,
		"agent_update.imported", "agent_update_release", release.ID)); err != nil {
		t.Fatalf("create PostgreSQL agent-update release: %v", err)
	}
	if _, err := repository.AgentUpdateEnvelope(release.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("staged PostgreSQL update envelope error = %v, want %v", err, ErrNotFound)
	}
	duplicate := release
	duplicate.ID = "postgres-agent-update-duplicate"
	duplicate.ArtifactSHA256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := repository.CreateAgentUpdateRelease(duplicate, postgresIdentityAuditEvent(now, administrator.ID,
		"agent_update.imported", "agent_update_release", duplicate.ID)); err == nil {
		t.Fatal("PostgreSQL agent-update release allowed duplicate version and platform")
	}
	approvedAt := now.Add(time.Minute)
	if err := repository.ApproveAgentUpdateRelease(release.ID, administrator.ID, approvedAt,
		postgresIdentityAuditEvent(approvedAt, administrator.ID, "agent_update.approved", "agent_update_release",
			release.ID)); err != nil {
		t.Fatalf("approve PostgreSQL agent-update release: %v", err)
	}
	if err := repository.ApproveAgentUpdateRelease(release.ID, administrator.ID, approvedAt,
		postgresIdentityAuditEvent(approvedAt, administrator.ID, "agent_update.approved", "agent_update_release",
			release.ID)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("reapproved PostgreSQL update error = %v, want %v", err, ErrNotFound)
	}
	envelope, err := repository.AgentUpdateEnvelope(release.ID)
	if err != nil || !reflect.DeepEqual(envelope, release.Envelope) {
		t.Fatalf("approved PostgreSQL agent-update envelope changed: %q %v", envelope, err)
	}
	assignedAt := now.Add(2 * time.Minute)
	if err := repository.AssignAgentUpdate(endpoint.ID, release.ID, administrator.ID, assignedAt,
		postgresIdentityAuditEvent(assignedAt, administrator.ID, "agent_update.assigned", "endpoint", endpoint.ID)); err != nil {
		t.Fatalf("assign PostgreSQL agent update: %v", err)
	}
	offeredAt := now.Add(3 * time.Minute)
	offer, err := repository.AgentUpdateOffer(endpoint.ID, offeredAt)
	if err != nil || !reflect.DeepEqual(offer, release.Envelope) {
		t.Fatalf("load PostgreSQL agent-update offer: %q %v", offer, err)
	}
	secondOfferAt := offeredAt.Add(time.Minute)
	secondOffer, err := repository.AgentUpdateOffer(endpoint.ID, secondOfferAt)
	if err != nil || !reflect.DeepEqual(secondOffer, release.Envelope) {
		t.Fatalf("reload PostgreSQL agent-update offer: %q %v", secondOffer, err)
	}
	var assignmentStatus string
	var storedOfferedAt time.Time
	var installedAt *time.Time
	if err := repository.db.QueryRow(`SELECT status,offered_at,installed_at FROM agent_update_assignments
		WHERE endpoint_id=$1`, endpoint.ID).Scan(&assignmentStatus, &storedOfferedAt, &installedAt); err != nil {
		t.Fatalf("read PostgreSQL agent-update assignment: %v", err)
	}
	if assignmentStatus != "offered" || !storedOfferedAt.Equal(offeredAt) || installedAt != nil {
		t.Fatalf("unexpected PostgreSQL update offer state: status=%s offered=%v installed=%v",
			assignmentStatus, storedOfferedAt, installedAt)
	}
	checkIn.SoftwareVersion = release.Version
	installedCheckInAt := now.Add(5 * time.Minute)
	if err := repository.RecordEndpointCheckIn(endpoint.ID, checkIn, installedCheckInAt); err != nil {
		t.Fatalf("reconcile PostgreSQL installed agent update: %v", err)
	}
	if err := repository.db.QueryRow(`SELECT status,installed_at FROM agent_update_assignments WHERE endpoint_id=$1`,
		endpoint.ID).Scan(&assignmentStatus, &installedAt); err != nil {
		t.Fatalf("read installed PostgreSQL agent-update assignment: %v", err)
	}
	if assignmentStatus != "installed" || installedAt == nil || !installedAt.Equal(installedCheckInAt) {
		t.Fatalf("unexpected PostgreSQL installed update state: status=%s installed=%v", assignmentStatus, installedAt)
	}
	if offer, err := repository.AgentUpdateOffer(endpoint.ID, installedCheckInAt.Add(time.Minute)); err != nil || offer != nil {
		t.Fatalf("installed PostgreSQL agent update was offered again: %q %v", offer, err)
	}
	revokedAt := now.Add(6 * time.Minute)
	if err := repository.RevokeAgentUpdateRelease(release.ID, administrator.ID, "signing key concern", revokedAt,
		postgresIdentityAuditEvent(revokedAt, administrator.ID, "agent_update.revoked", "agent_update_release",
			release.ID)); err != nil {
		t.Fatalf("revoke PostgreSQL agent-update release: %v", err)
	}
	if _, err := repository.AgentUpdateEnvelope(release.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked PostgreSQL update envelope error = %v, want %v", err, ErrNotFound)
	}
	releases, err := repository.ListAgentUpdateReleases()
	if err != nil || len(releases) != 1 || releases[0].Status != model.AgentUpdateRevoked ||
		releases[0].ApprovedBy != administrator.ID || releases[0].ApprovedAt == nil ||
		releases[0].RevokedBy != administrator.ID || releases[0].RevokedAt == nil ||
		releases[0].RevocationReason != "signing key concern" {
		t.Fatalf("PostgreSQL agent-update release lifecycle changed: %#v %v", releases, err)
	}
	events, err := repository.ListAuditEvents(model.AuditQuery{Text: "agent_update.", Limit: 10})
	if err != nil || len(events) != 4 {
		t.Fatalf("PostgreSQL agent-update audit trail changed: %#v %v", events, err)
	}
}

func TestPostgreSQLAgentModuleTrustAssignmentAndHealthLifecycle(t *testing.T) {
	repository, _ := openPostgreSQLIntegrationStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	administrator, _, _ := bootstrapPostgreSQLTestAdministrator(t, repository, now)
	endpoint := enrollPostgreSQLTestEndpoint(t, repository, administrator, now, "postgres-module-endpoint")
	if err := repository.RecordEndpointCheckIn(endpoint.ID, model.AgentCheckIn{SchemaVersion: 1,
		SoftwareVersion: "1.2.0", OperatingSystem: "linux", Architecture: "amd64"}, now); err != nil {
		t.Fatalf("establish PostgreSQL module endpoint platform: %v", err)
	}
	completedAt := now
	assetScan := model.Scan{ID: "postgres-module-asset-scan", Name: "Module asset discovery",
		Targets: []model.Target{{Name: "module-host", Address: "192.0.2.60"}}, Ports: []int{443},
		Status: model.StatusCompleted, CreatedAt: now, CompletedAt: &completedAt}
	if err := repository.Save(assetScan); err != nil {
		t.Fatalf("create PostgreSQL module asset: %v", err)
	}
	assets, err := repository.ListAssets()
	if err != nil || len(assets) != 1 {
		t.Fatalf("load PostgreSQL module asset: %#v %v", assets, err)
	}
	if err := repository.LinkEndpointAsset(endpoint.ID, assets[0].ID, postgresIdentityAuditEvent(now,
		administrator.ID, "agent_module.endpoint_linked", "endpoint", endpoint.ID)); err != nil {
		t.Fatalf("link PostgreSQL module endpoint asset: %v", err)
	}
	publisher := agentmodule.Publisher{KeyID: "publisher", Name: "Mossward test publisher",
		PublicKey: []byte("postgres-module-public-key"), Enabled: true, CreatedBy: administrator.ID, CreatedAt: now}
	if err := repository.SaveAgentModulePublisher(publisher, postgresIdentityAuditEvent(now, administrator.ID,
		"agent_module.publisher.updated", "agent_module_publisher", publisher.KeyID)); err != nil {
		t.Fatalf("save PostgreSQL module publisher: %v", err)
	}
	storedPublisher, err := repository.AgentModulePublisher(publisher.KeyID)
	if err != nil || !reflect.DeepEqual(storedPublisher, publisher) {
		t.Fatalf("PostgreSQL module publisher changed: %#v %v", storedPublisher, err)
	}
	publishers, err := repository.ListAgentModulePublishers()
	if err != nil || len(publishers) != 1 || publishers[0].KeyID != publisher.KeyID {
		t.Fatalf("PostgreSQL module publisher catalog changed: %#v %v", publishers, err)
	}
	manifest := testModuleManifest()
	release := agentmodule.Release{ID: "postgres-module-release", Manifest: manifest,
		Envelope: []byte(`{"signed":true,"module":"com.test.inventory"}`), Status: agentmodule.ReleaseStaged,
		CreatedBy: administrator.ID, CreatedAt: now}
	if err := repository.CreateAgentModuleRelease(release, postgresIdentityAuditEvent(now, administrator.ID,
		"agent_module.release.created", "agent_module_release", release.ID)); err != nil {
		t.Fatalf("create PostgreSQL module release: %v", err)
	}
	assignment := agentmodule.Assignment{ID: "postgres-module-assignment", ReleaseID: release.ID,
		TargetType: "endpoint", TargetID: endpoint.ID, RingPercent: 100, Enabled: true,
		CreatedBy: administrator.ID, CreatedAt: now}
	if err := repository.SaveAgentModuleAssignment(assignment, postgresIdentityAuditEvent(now, administrator.ID,
		"agent_module.assignment.updated", "agent_module_assignment", assignment.ID)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("staged PostgreSQL module assignment error = %v, want %v", err, ErrNotFound)
	}
	approvedAt := now.Add(time.Minute)
	if err := repository.TransitionAgentModuleRelease(release.ID, agentmodule.ReleaseStaged,
		agentmodule.ReleaseApproved, administrator.ID, "", approvedAt, postgresIdentityAuditEvent(approvedAt,
			administrator.ID, "agent_module.release.approved", "agent_module_release", release.ID)); err != nil {
		t.Fatalf("approve PostgreSQL module release: %v", err)
	}
	invalidAssignment := assignment
	invalidAssignment.ID = "postgres-invalid-module-assignment"
	invalidAssignment.TargetID = "missing-endpoint"
	if err := repository.SaveAgentModuleAssignment(invalidAssignment, postgresIdentityAuditEvent(now,
		administrator.ID, "agent_module.assignment.updated", "agent_module_assignment",
		invalidAssignment.ID)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing PostgreSQL module target error = %v, want %v", err, ErrNotFound)
	}
	if err := repository.SaveAgentModuleAssignment(assignment, postgresIdentityAuditEvent(now,
		administrator.ID, "agent_module.assignment.updated", "agent_module_assignment", assignment.ID)); err != nil {
		t.Fatalf("save PostgreSQL module assignment: %v", err)
	}
	assignments, err := repository.ListAgentModuleAssignments()
	if err != nil || len(assignments) != 1 || !reflect.DeepEqual(assignments[0], assignment) {
		t.Fatalf("PostgreSQL module assignment changed: %#v %v", assignments, err)
	}
	incompatible, err := repository.AgentModuleOffers(endpoint.ID, "0.9.0", "linux", "amd64")
	if err != nil || len(incompatible) != 0 {
		t.Fatalf("incompatible PostgreSQL module was offered: %#v %v", incompatible, err)
	}
	offers, err := repository.AgentModuleOffers(endpoint.ID, "1.2.0", "linux", "amd64")
	if err != nil || len(offers) != 1 || offers[0].ReleaseID != release.ID ||
		!reflect.DeepEqual(offers[0].Envelope, release.Envelope) {
		t.Fatalf("PostgreSQL module offer changed: %#v %v", offers, err)
	}
	health := agentmodule.Health{ModuleID: manifest.ID, Version: manifest.Version, Healthy: false,
		CrashCount: 2, Error: "module process exited", ObservedAt: now.Add(2 * time.Minute)}
	if err := repository.RecordAgentModuleHealth(endpoint.ID, []agentmodule.Health{health}); err != nil {
		t.Fatalf("record PostgreSQL module health: %v", err)
	}
	var storedHealth agentmodule.Health
	if err := repository.db.QueryRow(`SELECT module_id,version,healthy,crash_count,error,observed_at
		FROM agent_module_health WHERE endpoint_id=$1 AND module_id=$2`, endpoint.ID, manifest.ID).Scan(
		&storedHealth.ModuleID, &storedHealth.Version, &storedHealth.Healthy, &storedHealth.CrashCount,
		&storedHealth.Error, &storedHealth.ObservedAt); err != nil {
		t.Fatalf("read PostgreSQL module health: %v", err)
	}
	if !reflect.DeepEqual(storedHealth, health) {
		t.Fatalf("PostgreSQL module health changed: %#v", storedHealth)
	}
	if err := repository.SetAgentModulesEnabled(false, postgresIdentityAuditEvent(now, administrator.ID,
		"agent_module.settings.updated", "agent_module_settings", "global")); err != nil {
		t.Fatalf("disable PostgreSQL agent modules: %v", err)
	}
	offers, err = repository.AgentModuleOffers(endpoint.ID, "1.2.0", "linux", "amd64")
	if err != nil || len(offers) != 1 || !offers[0].Disabled {
		t.Fatalf("PostgreSQL module emergency stop changed: %#v %v", offers, err)
	}
	if err := repository.SetAgentModulesEnabled(true, postgresIdentityAuditEvent(now, administrator.ID,
		"agent_module.settings.updated", "agent_module_settings", "global")); err != nil {
		t.Fatalf("re-enable PostgreSQL agent modules: %v", err)
	}
	revokedAt := now.Add(3 * time.Minute)
	if err := repository.TransitionAgentModuleRelease(release.ID, agentmodule.ReleaseApproved,
		agentmodule.ReleaseRevoked, administrator.ID, "publisher concern", revokedAt,
		postgresIdentityAuditEvent(revokedAt, administrator.ID, "agent_module.release.revoked",
			"agent_module_release", release.ID)); err != nil {
		t.Fatalf("revoke PostgreSQL module release: %v", err)
	}
	offers, err = repository.AgentModuleOffers(endpoint.ID, "1.2.0", "linux", "amd64")
	if err != nil || len(offers) != 0 {
		t.Fatalf("revoked PostgreSQL module remained offered: %#v %v", offers, err)
	}
	releases, err := repository.ListAgentModuleReleases()
	if err != nil || len(releases) != 1 || releases[0].Status != agentmodule.ReleaseRevoked ||
		releases[0].ApprovedBy != administrator.ID || releases[0].ApprovedAt == nil ||
		releases[0].RevokedBy != administrator.ID || releases[0].RevokedAt == nil ||
		releases[0].RevocationReason != "publisher concern" {
		t.Fatalf("PostgreSQL module release lifecycle changed: %#v %v", releases, err)
	}
	var linkedAssetID string
	if err := repository.db.QueryRow(`SELECT asset_id FROM endpoints WHERE id=$1`, endpoint.ID).
		Scan(&linkedAssetID); err != nil || linkedAssetID != assets[0].ID {
		t.Fatalf("PostgreSQL endpoint asset link = %q, want %q: %v", linkedAssetID, assets[0].ID, err)
	}
}

func TestPostgreSQLAssetMergePreservesSelectedValuesAndRelationships(t *testing.T) {
	repository, _ := openPostgreSQLIntegrationStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	administrator, _, _ := bootstrapPostgreSQLTestAdministrator(t, repository, now)
	first := completedAssetScan("postgres-merge-scan-one", "postgres-merge-observation-one", "first-host",
		"192.0.2.70", now)
	second := completedAssetScan("postgres-merge-scan-two", "postgres-merge-observation-two", "second-host",
		"192.0.2.71", now.Add(time.Hour))
	first.Observations[0].Port = 80
	second.Observations[0].Port = 443
	if err := repository.Save(first); err != nil {
		t.Fatalf("save first PostgreSQL merge asset: %v", err)
	}
	if err := repository.Save(second); err != nil {
		t.Fatalf("save second PostgreSQL merge asset: %v", err)
	}
	assets, err := repository.ListAssets()
	if err != nil || len(assets) != 2 {
		t.Fatalf("load PostgreSQL merge assets: %#v %v", assets, err)
	}
	assetsByName := map[string]model.Asset{}
	for _, asset := range assets {
		assetsByName[asset.Name] = asset
	}
	survivor := assetsByName["first-host"]
	merged := assetsByName["second-host"]
	for index, assetID := range []string{survivor.ID, merged.ID} {
		group := model.AssetGroup{ID: fmt.Sprintf("postgres-merge-group-%d", index),
			Name: fmt.Sprintf("Merge group %d", index), CreatedAt: now, UpdatedAt: now}
		if err := repository.UpsertAssetGroup(group, postgresIdentityAuditEvent(now, administrator.ID,
			"asset_group.updated", "asset_group", group.ID)); err != nil {
			t.Fatalf("save PostgreSQL merge group: %v", err)
		}
		if err := repository.AddAssetGroupMember(group.ID, assetID, administrator.ID, now,
			postgresIdentityAuditEvent(now, administrator.ID, "asset_group.member.added", "asset_group", group.ID)); err != nil {
			t.Fatalf("add PostgreSQL merge group member: %v", err)
		}
	}
	metadata := model.AssetMetadata{Owner: "Security operations", Environment: "Production",
		Classification: "Critical"}
	if err := repository.UpdateAssetMetadata(merged.ID, metadata, postgresIdentityAuditEvent(now,
		administrator.ID, "asset.metadata.updated", "asset", merged.ID)); err != nil {
		t.Fatalf("update PostgreSQL merge metadata: %v", err)
	}
	endpoint := enrollPostgreSQLTestEndpoint(t, repository, administrator, now, "postgres-merge-endpoint")
	if err := repository.LinkEndpointAsset(endpoint.ID, merged.ID, postgresIdentityAuditEvent(now,
		administrator.ID, "agent_module.endpoint_linked", "endpoint", endpoint.ID)); err != nil {
		t.Fatalf("link PostgreSQL endpoint to merged asset: %v", err)
	}
	request := model.AssetMergeRequest{SurvivorID: survivor.ID, MergedID: merged.ID, NameFrom: merged.ID,
		AddressFrom: merged.ID, OwnerFrom: merged.ID, EnvironmentFrom: merged.ID,
		ClassificationFrom: merged.ID, LifecycleFrom: merged.ID}
	invalid := request
	invalid.NameFrom = "unrelated-asset"
	if err := repository.MergeAssets(invalid, postgresIdentityAuditEvent(now, administrator.ID,
		"asset.merged", "asset", survivor.ID)); err == nil {
		t.Fatal("PostgreSQL asset merge accepted a value source outside the selected assets")
	}
	mergedAt := now.Add(2 * time.Hour)
	if err := repository.MergeAssets(request, postgresIdentityAuditEvent(mergedAt, administrator.ID,
		"asset.merged", "asset", survivor.ID)); err != nil {
		t.Fatalf("merge PostgreSQL assets: %v", err)
	}
	assets, err = repository.ListAssets()
	if err != nil || len(assets) != 1 || assets[0].ID != survivor.ID || assets[0].Name != merged.Name ||
		assets[0].Address != merged.Address || assets[0].Owner != metadata.Owner ||
		assets[0].Environment != metadata.Environment || assets[0].Classification != metadata.Classification ||
		len(assets[0].Addresses) != 2 || len(assets[0].Names) != 2 || !assets[0].FirstSeen.Equal(survivor.FirstSeen) ||
		!assets[0].LastSeen.Equal(merged.LastSeen) || assets[0].LastScanID != merged.LastScanID {
		t.Fatalf("PostgreSQL merged asset identity changed: %#v %v", assets, err)
	}
	detail, err := repository.AssetDetail(survivor.ID, mergedAt)
	if err != nil || len(detail.Services) != 2 || len(detail.Evidence) != 2 {
		t.Fatalf("PostgreSQL merged asset history changed: %#v %v", detail, err)
	}
	memberships, err := repository.AssetGroupMemberships(survivor.ID)
	if err != nil || len(memberships) != 2 {
		t.Fatalf("PostgreSQL merged asset group relationships changed: %#v %v", memberships, err)
	}
	if _, err := repository.AssetDetail(merged.ID, mergedAt); !errors.Is(err, ErrAssetNotFound) {
		t.Fatalf("merged-away PostgreSQL asset remained available: %v", err)
	}
	var linkedAssetID string
	if err := repository.db.QueryRow(`SELECT asset_id FROM endpoints WHERE id=$1`, endpoint.ID).
		Scan(&linkedAssetID); err != nil || linkedAssetID != survivor.ID {
		t.Fatalf("PostgreSQL merged endpoint link = %q, want %q: %v", linkedAssetID, survivor.ID, err)
	}
	events, err := repository.ListAuditEvents(model.AuditQuery{Text: "asset.merged", Limit: 10})
	if err != nil || len(events) != 1 {
		t.Fatalf("PostgreSQL asset-merge audit trail changed: %#v %v", events, err)
	}
}

func TestPostgreSQLAssetLifecycleAgingAndMetadataControls(t *testing.T) {
	repository, _ := openPostgreSQLIntegrationStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	administrator, _, _ := bootstrapPostgreSQLTestAdministrator(t, repository, now)
	settings, err := repository.AssetAgingSettings()
	if err != nil || settings.StaleAfterDays != 30 {
		t.Fatalf("PostgreSQL asset-aging default changed: %#v %v", settings, err)
	}
	observedAt := now.Add(-10 * 24 * time.Hour)
	if err := repository.Save(completedAssetScan("postgres-aging-scan", "postgres-aging-observation",
		"aging.example.test", "192.0.2.90", observedAt)); err != nil {
		t.Fatalf("create PostgreSQL aging asset: %v", err)
	}
	assets, err := repository.ListAssets()
	if err != nil || len(assets) != 1 || assets[0].Lifecycle.Status != model.AssetActive {
		t.Fatalf("PostgreSQL asset aged before its threshold: %#v %v", assets, err)
	}
	asset := assets[0]
	agingEvent := postgresIdentityAuditEvent(now, administrator.ID, "asset.aging.updated", "asset_aging", "global")
	if err := repository.UpdateAssetAgingSettings(model.AssetAgingSettings{StaleAfterDays: 0}, agingEvent); err == nil {
		t.Fatal("PostgreSQL asset aging accepted a zero-day threshold")
	}
	if err := repository.UpdateAssetAgingSettings(model.AssetAgingSettings{StaleAfterDays: 5}, agingEvent); err != nil {
		t.Fatalf("update PostgreSQL asset-aging threshold: %v", err)
	}
	assets, err = repository.ListAssets()
	if err != nil || assets[0].Lifecycle.Status != model.AssetStale || assets[0].Lifecycle.RetiredAt != nil {
		t.Fatalf("PostgreSQL calculated asset staleness changed: %#v %v", assets, err)
	}
	metadata := model.AssetMetadata{Owner: "Infrastructure", Environment: "Production", Classification: "Critical"}
	if err := repository.UpdateAssetMetadata(asset.ID, metadata, postgresIdentityAuditEvent(now, administrator.ID,
		"asset.metadata.updated", "asset", asset.ID)); err != nil {
		t.Fatalf("update PostgreSQL asset metadata: %v", err)
	}
	eligibility := model.AssetAgentEligibilityUpdate{Status: model.AgentEligibilityEligible,
		Reason: "managed server"}
	if err := repository.UpdateAssetAgentEligibility(asset.ID, eligibility, postgresIdentityAuditEvent(now,
		administrator.ID, "asset.agent_eligibility.updated", "asset", asset.ID)); err != nil {
		t.Fatalf("update PostgreSQL asset agent eligibility: %v", err)
	}
	if err := repository.UpdateAssetMetadata("missing-asset", metadata, postgresIdentityAuditEvent(now,
		administrator.ID, "asset.metadata.updated", "asset", "missing-asset")); !errors.Is(err, ErrAssetNotFound) {
		t.Fatalf("missing PostgreSQL asset metadata error = %v, want %v", err, ErrAssetNotFound)
	}
	if err := repository.UpdateAssetLifecycle(asset.ID, model.AssetLifecycleUpdate{Status: model.AssetStale},
		postgresIdentityAuditEvent(now, administrator.ID, "asset.retired", "asset", asset.ID)); !errors.Is(err, ErrInvalidAssetLifecycle) {
		t.Fatalf("explicit PostgreSQL stale lifecycle error = %v, want %v", err, ErrInvalidAssetLifecycle)
	}
	retiredAt := now.Add(time.Minute)
	retirement := model.AssetLifecycleUpdate{Status: model.AssetRetired, Reason: "device decommissioned"}
	if err := repository.UpdateAssetLifecycle(asset.ID, retirement, postgresIdentityAuditEvent(retiredAt,
		administrator.ID, "asset.retired", "asset", asset.ID)); err != nil {
		t.Fatalf("retire PostgreSQL asset: %v", err)
	}
	assets, err = repository.ListAssets()
	if err != nil || len(assets) != 1 || assets[0].Lifecycle.Status != model.AssetRetired ||
		assets[0].Lifecycle.RetiredAt == nil || !assets[0].Lifecycle.RetiredAt.Equal(retiredAt) ||
		assets[0].Lifecycle.RetiredBy != administrator.ID ||
		assets[0].Lifecycle.RetirementReason != retirement.Reason || assets[0].Owner != metadata.Owner ||
		assets[0].Environment != metadata.Environment || assets[0].Classification != metadata.Classification ||
		assets[0].AgentEligibility.Status != eligibility.Status || assets[0].AgentEligibility.Reason != eligibility.Reason ||
		assets[0].AgentEligibility.UpdatedBy != administrator.ID || assets[0].AgentEligibility.UpdatedAt == nil {
		t.Fatalf("PostgreSQL retired asset governance state changed: %#v %v", assets, err)
	}
	if err := repository.UpdateAssetAgingSettings(model.AssetAgingSettings{StaleAfterDays: 30},
		postgresIdentityAuditEvent(now.Add(2*time.Minute), administrator.ID, "asset.aging.updated",
			"asset_aging", "global")); err != nil {
		t.Fatalf("restore PostgreSQL asset-aging threshold: %v", err)
	}
	restoredAt := now.Add(3 * time.Minute)
	if err := repository.UpdateAssetLifecycle(asset.ID, model.AssetLifecycleUpdate{Status: model.AssetActive},
		postgresIdentityAuditEvent(restoredAt, administrator.ID, "asset.restored", "asset", asset.ID)); err != nil {
		t.Fatalf("restore PostgreSQL asset: %v", err)
	}
	assets, err = repository.ListAssets()
	if err != nil || assets[0].Lifecycle.Status != model.AssetActive || assets[0].Lifecycle.RetiredAt != nil ||
		assets[0].Lifecycle.RetiredBy != "" || assets[0].Lifecycle.RetirementReason != "" {
		t.Fatalf("PostgreSQL restored asset lifecycle changed: %#v %v", assets, err)
	}
	events, err := repository.ListAuditEvents(model.AuditQuery{Text: "asset.", Limit: 20})
	if err != nil || len(events) != 6 {
		t.Fatalf("PostgreSQL asset-governance audit trail changed: %#v %v", events, err)
	}
}

func TestPostgreSQLIdentityCiphertextRotationIsAtomic(t *testing.T) {
	repository, _ := openPostgreSQLIntegrationStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	administrator, _, _ := bootstrapPostgreSQLTestAdministrator(t, repository, now)
	oldTOTP := []byte("old:totp-secret")
	if _, err := repository.db.Exec(`UPDATE totp_credentials SET secret_ciphertext=$1 WHERE user_id=$2`,
		oldTOTP, administrator.ID); err != nil {
		t.Fatalf("prepare PostgreSQL TOTP rotation fixture: %v", err)
	}
	credential := model.WebAuthnCredential{ID: []byte("postgres-rotation-credential"), UserID: administrator.ID,
		Name: "Rotation credential", CredentialCiphertext: []byte("old:webauthn-credential"), CreatedAt: now}
	if err := repository.CreateWebAuthnCredential(credential); err != nil {
		t.Fatalf("create PostgreSQL rotation credential: %v", err)
	}
	ceremony := model.AuthenticationCeremony{IDHash: []byte("postgres-rotation-ceremony"),
		UserID: administrator.ID, Kind: model.CeremonyWebAuthnRegister,
		StateCiphertext: []byte("old:webauthn-ceremony"), ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	if err := repository.CreateAuthenticationCeremony(ceremony); err != nil {
		t.Fatalf("create PostgreSQL rotation ceremony: %v", err)
	}
	provider := model.OIDCProvider{ID: "postgres-rotation-provider", Name: "Rotation provider",
		IssuerURL: "https://identity.example.test", ClientID: "rotation-client", ProvisioningMode: model.ProvisionJIT,
		DefaultRole: model.RoleViewer, RedirectURL: "https://mossward.example.test/auth/oidc/callback",
		CreatedAt: now, UpdatedAt: now}
	if err := repository.UpsertOIDCProvider(model.OIDCProviderRecord{Provider: provider,
		ClientSecretCiphertext: []byte("old:oidc-client-secret")}, postgresIdentityAuditEvent(now, administrator.ID,
		"identity.oidc_provider.configured", "oidc_provider", provider.ID)); err != nil {
		t.Fatalf("create PostgreSQL rotation OIDC provider: %v", err)
	}
	smtp := model.SMTPSettings{Enabled: true, Host: "smtp.example.test", Port: 587,
		Username: "mossward@example.test", PasswordCiphertext: []byte("invalid-smtp-ciphertext"),
		FromAddress: "mossward@example.test", TLSMode: "starttls", RecipientUserIDs: []string{administrator.ID}}
	if err := repository.SaveSMTPSettings(smtp, postgresIdentityAuditEvent(now, administrator.ID,
		"notification.smtp.updated", "smtp_settings", "global")); err != nil {
		t.Fatalf("create PostgreSQL rotation SMTP settings: %v", err)
	}
	cipher := postgreSQLTestRotationCipher{}
	if rotated, err := repository.RotateIdentityCiphertexts(cipher, now.Add(time.Minute)); err == nil || rotated != 0 {
		t.Fatalf("invalid PostgreSQL ciphertext rotation = %d, %v; want atomic failure", rotated, err)
	}
	storedTOTP, _, err := repository.TOTPSecret(administrator.ID)
	if err != nil || !bytes.Equal(storedTOTP, oldTOTP) {
		t.Fatalf("failed PostgreSQL rotation changed TOTP ciphertext: %q %v", storedTOTP, err)
	}
	storedProvider, err := repository.OIDCProvider(provider.ID)
	if err != nil || !bytes.Equal(storedProvider.ClientSecretCiphertext, []byte("old:oidc-client-secret")) {
		t.Fatalf("failed PostgreSQL rotation changed OIDC ciphertext: %#v %v", storedProvider, err)
	}
	smtp.PasswordCiphertext = []byte("old:smtp-password")
	if err := repository.SaveSMTPSettings(smtp, postgresIdentityAuditEvent(now.Add(2*time.Minute), administrator.ID,
		"notification.smtp.updated", "smtp_settings", "global")); err != nil {
		t.Fatalf("repair PostgreSQL rotation SMTP fixture: %v", err)
	}
	rotatedAt := now.Add(3 * time.Minute)
	rotated, err := repository.RotateIdentityCiphertexts(cipher, rotatedAt)
	if err != nil || rotated != 5 {
		t.Fatalf("rotate PostgreSQL identity ciphertexts: count=%d err=%v", rotated, err)
	}
	storedTOTP, _, err = repository.TOTPSecret(administrator.ID)
	if err != nil || !bytes.Equal(storedTOTP, []byte("new:totp-secret")) {
		t.Fatalf("PostgreSQL TOTP ciphertext was not rotated: %q %v", storedTOTP, err)
	}
	credentials, err := repository.ListWebAuthnCredentials(administrator.ID)
	if err != nil || len(credentials) != 1 ||
		!bytes.Equal(credentials[0].CredentialCiphertext, []byte("new:webauthn-credential")) {
		t.Fatalf("PostgreSQL WebAuthn credential was not rotated: %#v %v", credentials, err)
	}
	consumed, err := repository.ConsumeAuthenticationCeremony(ceremony.IDHash, ceremony.Kind)
	if err != nil || !bytes.Equal(consumed.StateCiphertext, []byte("new:webauthn-ceremony")) {
		t.Fatalf("PostgreSQL WebAuthn ceremony was not rotated: %#v %v", consumed, err)
	}
	storedProvider, err = repository.OIDCProvider(provider.ID)
	if err != nil || !bytes.Equal(storedProvider.ClientSecretCiphertext, []byte("new:oidc-client-secret")) {
		t.Fatalf("PostgreSQL OIDC secret was not rotated: %#v %v", storedProvider, err)
	}
	storedSMTP, err := repository.SMTPSettings()
	if err != nil || !bytes.Equal(storedSMTP.PasswordCiphertext, []byte("new:smtp-password")) {
		t.Fatalf("PostgreSQL SMTP secret was not rotated: %#v %v", storedSMTP, err)
	}
	events, err := repository.ListAuditEvents(model.AuditQuery{Text: "identity.encryption_key.rotated", Limit: 10})
	if err != nil || len(events) != 1 || !strings.Contains(events[0].Details, `"ciphertexts":5`) {
		t.Fatalf("PostgreSQL ciphertext-rotation audit event changed: %#v %v", events, err)
	}
}

func TestPostgreSQLCVEFeedScanMatchAndCriticalNews(t *testing.T) {
	repository, _ := openPostgreSQLIntegrationStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	initial, err := repository.FeedStatus()
	if err != nil || initial.Status != "not_synced" || initial.DatabaseCVEs != 0 || initial.LastStarted != nil ||
		initial.LastSuccess != nil {
		t.Fatalf("unexpected initial PostgreSQL CVE feed state: %#v %v", initial, err)
	}
	if err := repository.RecordFeedStart("NVD", now); err != nil {
		t.Fatalf("start PostgreSQL CVE feed: %v", err)
	}
	running, err := repository.FeedStatus()
	if err != nil || running.Status != "running" || running.LastStarted == nil || !running.LastStarted.Equal(now) {
		t.Fatalf("PostgreSQL running CVE feed state changed: %#v %v", running, err)
	}
	matchedCVE := model.CVERecord{ID: "CVE-POSTGRES-NEWS-0001", Description: "Critical nginx issue",
		PublishedAt: now.Add(-time.Hour), ModifiedAt: now, CVSSScore: 9.8,
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Severity: "CRITICAL",
		SourceURL: "https://example.test/cve/matched", Products: []model.AffectedProduct{{
			CPE23: "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*", Part: "A", Vendor: "NGINX", Product: "NGINX",
			VersionStartIncluding: "1.20.0", VersionEndExcluding: "1.25.4", Vulnerable: true}},
		References: []model.CVEReference{{URL: "https://example.test/advisory/matched", Source: "vendor"}}}
	generalCVE := model.CVERecord{ID: "CVE-POSTGRES-NEWS-0002", Description: "General critical issue",
		PublishedAt: now, ModifiedAt: now, CVSSScore: 10, Severity: "critical", KnownExploited: true,
		SourceURL: "https://example.test/cve/general", Products: []model.AffectedProduct{{
			CPE23: "cpe:2.3:a:example:unobserved:*:*:*:*:*:*:*:*", Part: "a", Vendor: "example",
			Product: "unobserved", Version: "9.9.9", Vulnerable: true}},
		References: []model.CVEReference{{URL: "https://example.test/advisory/general", Source: "vendor"}}}
	if err := repository.UpsertCVEs([]model.CVERecord{matchedCVE, generalCVE}); err != nil {
		t.Fatalf("store PostgreSQL CVE catalog: %v", err)
	}
	observation := model.ServiceObservation{ID: "postgres-cve-observation", Target: "web",
		Address: "192.0.2.80", Port: 443, Protocol: "https", Product: "nginx", Version: "1.25.3",
		Confidence: "high", Evidence: "nginx version banner", ObservedAt: now}
	matches, err := repository.MatchObservation(observation)
	if err != nil || len(matches) != 1 || matches[0].CVEID != matchedCVE.ID ||
		matches[0].Severity != "critical" || matches[0].KnownExploited || matches[0].ObservationID != observation.ID {
		t.Fatalf("PostgreSQL CVE observation match changed: %#v %v", matches, err)
	}
	notAffected := observation
	notAffected.ID = "postgres-cve-unaffected-observation"
	notAffected.Version = "1.25.4"
	if matches, err := repository.MatchObservation(notAffected); err != nil || len(matches) != 0 {
		t.Fatalf("PostgreSQL excluded CVE boundary matched: %#v %v", matches, err)
	}
	withoutVersion := observation
	withoutVersion.ID = "postgres-cve-versionless-observation"
	withoutVersion.Version = ""
	if matches, err := repository.MatchObservation(withoutVersion); err != nil || len(matches) != 0 {
		t.Fatalf("PostgreSQL versionless observation matched: %#v %v", matches, err)
	}
	completedAt := now.Add(time.Minute)
	scan := model.Scan{ID: "postgres-cve-scan", Name: "CVE match scan",
		Targets: []model.Target{{Name: observation.Target, Address: observation.Address}}, Ports: []int{observation.Port},
		Status: model.StatusCompleted, TotalChecks: 1, DoneChecks: 1, CreatedAt: now, CompletedAt: &completedAt,
		Observations: []model.ServiceObservation{observation}, CVEMatches: matches}
	if err := repository.Save(scan); err != nil {
		t.Fatalf("save PostgreSQL CVE-matched scan: %v", err)
	}
	loaded, err := repository.Get(scan.ID)
	if err != nil || len(loaded.CVEMatches) != 1 || loaded.CVEMatches[0].CVEID != matchedCVE.ID ||
		loaded.CVEMatches[0].Description != matchedCVE.Description ||
		loaded.CVEMatches[0].CVSSScore != matchedCVE.CVSSScore || loaded.CVEMatches[0].Severity != "critical" {
		t.Fatalf("PostgreSQL scan CVE match changed: %#v %v", loaded.CVEMatches, err)
	}
	news, err := repository.ListCriticalNews(6)
	if err != nil || len(news) != 2 || news[0].ID != matchedCVE.ID || news[0].Relevance != "matched" ||
		!strings.Contains(news[0].Evidence, "nginx 1.25.3") || news[1].ID != generalCVE.ID ||
		news[1].Relevance != "general" {
		t.Fatalf("PostgreSQL critical CVE news ordering changed: %#v %v", news, err)
	}
	matchedCVE.References = []model.CVEReference{{URL: "https://example.test/advisory/replaced", Source: "updated"}}
	if err := repository.UpsertCVEs([]model.CVERecord{matchedCVE}); err != nil {
		t.Fatalf("replace PostgreSQL CVE references: %v", err)
	}
	var referenceCount int
	var referenceURL string
	if err := repository.db.QueryRow(`SELECT COUNT(*),MIN(url) FROM cve_references WHERE cve_id=$1`, matchedCVE.ID).
		Scan(&referenceCount, &referenceURL); err != nil || referenceCount != 1 || referenceURL != matchedCVE.References[0].URL {
		t.Fatalf("PostgreSQL CVE references were not replaced: count=%d url=%q err=%v",
			referenceCount, referenceURL, err)
	}
	succeededAt := now.Add(2 * time.Minute)
	if err := repository.RecordFeedResult("NVD", succeededAt, 2, ""); err != nil {
		t.Fatalf("complete PostgreSQL CVE feed: %v", err)
	}
	ready, err := repository.FeedStatus()
	if err != nil || ready.Status != "ready" || ready.LastSuccess == nil || !ready.LastSuccess.Equal(succeededAt) ||
		ready.Records != 2 || ready.DatabaseCVEs != 2 || ready.Error != "" {
		t.Fatalf("PostgreSQL ready CVE feed state changed: %#v %v", ready, err)
	}
	if err := repository.RecordFeedStart("NVD", now.Add(3*time.Minute)); err != nil {
		t.Fatalf("restart PostgreSQL CVE feed: %v", err)
	}
	if err := repository.RecordFeedResult("NVD", now.Add(4*time.Minute), 0, "upstream unavailable"); err != nil {
		t.Fatalf("fail PostgreSQL CVE feed: %v", err)
	}
	failed, err := repository.FeedStatus()
	if err != nil || failed.Status != "failed" || failed.LastSuccess == nil || !failed.LastSuccess.Equal(succeededAt) ||
		failed.Records != 0 || failed.Error != "upstream unavailable" || failed.DatabaseCVEs != 2 {
		t.Fatalf("PostgreSQL failed CVE feed state changed: %#v %v", failed, err)
	}
}

type postgreSQLTestRotationCipher struct{}

func (postgreSQLTestRotationCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	prefix := []byte("old:")
	if !bytes.HasPrefix(ciphertext, prefix) {
		return nil, errors.New("ciphertext is not encrypted by the legacy test key")
	}
	return bytes.Clone(ciphertext[len(prefix):]), nil
}

func (postgreSQLTestRotationCipher) Encrypt(plaintext []byte) ([]byte, error) {
	return append([]byte("new:"), plaintext...), nil
}

func enrollPostgreSQLTestWorker(
	t *testing.T,
	repository *PostgreSQLStore,
	administrator model.User,
	now time.Time,
	workerID string,
) model.ScannerWorker {
	t.Helper()
	token := model.WorkerEnrollmentToken{ID: workerID + "-token", Name: workerID, SiteID: "postgres-test-site",
		TokenHash: []byte(workerID + "-token-hash"), AllowedCIDRs: []string{"192.0.2.0/24"},
		AllowedPorts: []int{443}, MaxConcurrent: 4, RateLimitPerSecond: 10, CreatedBy: administrator.ID,
		CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := repository.CreateWorkerEnrollmentToken(token, postgresIdentityAuditEvent(now, administrator.ID,
		"scanner_worker.enrollment_token.created", "scanner_worker_enrollment_token", token.ID)); err != nil {
		t.Fatalf("create PostgreSQL scanner-worker test token: %v", err)
	}
	worker := model.ScannerWorker{ID: workerID, Name: token.Name, SiteID: token.SiteID, Status: model.EndpointActive,
		CertificateSerial: workerID + "-serial", CertificatePEM: workerID + "-certificate",
		AllowedCIDRs: token.AllowedCIDRs, AllowedPorts: token.AllowedPorts, MaxConcurrent: token.MaxConcurrent,
		RateLimitPerSecond: token.RateLimitPerSecond, EnrolledAt: now, ExpiresAt: now.Add(24 * time.Hour)}
	if err := repository.ConsumeWorkerEnrollmentToken(token.TokenHash, worker, now, postgresIdentityAuditEvent(now,
		administrator.ID, "scanner_worker.enrolled", "scanner_worker", worker.ID)); err != nil {
		t.Fatalf("enroll PostgreSQL scanner-worker test fixture: %v", err)
	}
	return worker
}

func enrollPostgreSQLTestEndpoint(
	t *testing.T,
	repository *PostgreSQLStore,
	administrator model.User,
	now time.Time,
	endpointID string,
) model.Endpoint {
	t.Helper()
	token := model.AgentEnrollmentToken{ID: endpointID + "-token", Name: endpointID,
		TokenHash: []byte(endpointID + "-token-hash"), CreatedBy: administrator.ID,
		CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := repository.CreateAgentEnrollmentToken(token, postgresIdentityAuditEvent(now, administrator.ID,
		"endpoint.enrollment_token.created", "endpoint_enrollment_token", token.ID)); err != nil {
		t.Fatalf("create PostgreSQL endpoint enrollment token: %v", err)
	}
	endpoint := model.Endpoint{ID: endpointID, Name: token.Name, Status: model.EndpointActive,
		CertificateSerial: endpointID + "-serial", CertificatePEM: endpointID + "-certificate",
		EnrolledAt: now, ExpiresAt: now.Add(24 * time.Hour)}
	if err := repository.ConsumeAgentEnrollmentToken(token.TokenHash, endpoint, now, postgresIdentityAuditEvent(now,
		administrator.ID, "endpoint.enrolled", "endpoint", endpoint.ID)); err != nil {
		t.Fatalf("enroll PostgreSQL inventory endpoint: %v", err)
	}
	return endpoint
}

func postgresIdentityAuditEvent(at time.Time, actorID, action, targetType, targetID string) model.AuditEvent {
	return model.AuditEvent{OccurredAt: at, ActorID: actorID, Action: action, Severity: model.AuditInfo,
		TargetType: targetType, TargetID: targetID, Details: `{}`}
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
