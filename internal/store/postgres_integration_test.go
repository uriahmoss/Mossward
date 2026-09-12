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
	"strings"
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
	endpoint := enrollPostgreSQLTestEndpoint(t, repository, administrator, now)
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
	endpoint := enrollPostgreSQLTestEndpoint(t, repository, administrator, now)
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
	endpoint := enrollPostgreSQLTestEndpoint(t, repository, administrator, now)
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

func enrollPostgreSQLTestEndpoint(t *testing.T, repository *PostgreSQLStore, administrator model.User, now time.Time) model.Endpoint {
	t.Helper()
	token := model.AgentEnrollmentToken{ID: "inventory-endpoint-token", Name: "Inventory endpoint",
		TokenHash: []byte("inventory-endpoint-token-hash"), CreatedBy: administrator.ID,
		CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := repository.CreateAgentEnrollmentToken(token, postgresIdentityAuditEvent(now, administrator.ID,
		"endpoint.enrollment_token.created", "endpoint_enrollment_token", token.ID)); err != nil {
		t.Fatalf("create PostgreSQL endpoint enrollment token: %v", err)
	}
	endpoint := model.Endpoint{ID: "postgres-inventory-endpoint", Name: token.Name, Status: model.EndpointActive,
		CertificateSerial: "postgres-inventory-serial", CertificatePEM: "postgres-inventory-certificate",
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
