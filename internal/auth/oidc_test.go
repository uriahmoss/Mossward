package auth

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"mossward/internal/model"
)

func TestOIDCProviderMustBeTestedBeforeEnableAndSecretIsEncrypted(t *testing.T) {
	service, repository := testService(t)
	admin := completeTestBootstrap(t, service, BootstrapRequest{Email: "admin@example.com", DisplayName: "Admin",
		Password: "correct horse battery staple"})
	issuer := "https://identity.example.test"
	discovery := `{"issuer":"https://identity.example.test","authorization_endpoint":"https://identity.example.test/authorize","token_endpoint":"https://identity.example.test/token","jwks_uri":"https://identity.example.test/keys","response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"]}`
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}},
			Body: io.NopCloser(strings.NewReader(discovery)), Request: request}, nil
	})}
	provider, err := service.ConfigureOIDCProvider(admin, OIDCProviderRequest{Name: "Entra test", IssuerURL: issuer,
		ClientID: "client-id", ClientSecret: "client-secret-value", RedirectURL: "http://localhost:8080/api/auth/oidc/callback",
		ProvisioningMode: model.ProvisionInviteOnly, DefaultRole: model.RoleViewer}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	record, err := repository.OIDCProvider(provider.ID)
	if err != nil {
		t.Fatal(err)
	}
	if string(record.ClientSecretCiphertext) == "client-secret-value" {
		t.Fatal("OIDC client secret was stored without encryption")
	}
	if err := service.SetOIDCProviderEnabled(admin, provider.ID, true, "127.0.0.1"); err == nil {
		t.Fatal("expected untested provider enablement to fail")
	}
	ctx := oidc.ClientContext(context.Background(), client)
	if err := service.TestOIDCProvider(ctx, admin, provider.ID, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := service.SetOIDCProviderEnabled(admin, provider.ID, true, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	destination, err := service.BeginOIDCLogin(ctx, provider.ID)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(destination)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")
	if state == "" || parsed.Query().Get("nonce") == "" || parsed.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("OIDC authorization request omitted state, nonce, or PKCE: %s", destination)
	}
	if _, err := service.consumeOIDCCeremony(state); err != nil {
		t.Fatal(err)
	}
	if _, err := service.consumeOIDCCeremony(state); err == nil {
		t.Fatal("expected replayed OIDC state to be rejected")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestOIDCClaimRestrictionsAndRoleMappings(t *testing.T) {
	provider := model.OIDCProvider{AllowedTenantID: "tenant", AllowedEmailDomains: []string{"example.com"},
		AllowedGroups: []string{"security"}, DefaultRole: model.RoleViewer,
		RoleMappings: map[string]model.UserRole{"security": model.RoleAnalyst}}
	role, err := authorizeOIDCClaims(provider, model.OIDCClaims{Email: "person@example.com", TenantID: "tenant", Groups: []string{"security"}})
	if err != nil || role != model.RoleAnalyst {
		t.Fatalf("expected analyst claim mapping, role=%q err=%v", role, err)
	}
	for _, claims := range []model.OIDCClaims{
		{Email: "person@outside.test", TenantID: "tenant", Groups: []string{"security"}},
		{Email: "person@example.com", TenantID: "other", Groups: []string{"security"}},
		{Email: "person@example.com", TenantID: "tenant", Groups: []string{"other"}},
	} {
		if _, err := authorizeOIDCClaims(provider, claims); err == nil {
			t.Fatalf("expected claims to be rejected: %#v", claims)
		}
	}
}

func TestOIDCInviteOnlyAndJITProvisioning(t *testing.T) {
	service, repository := testService(t)
	admin := completeTestBootstrap(t, service, BootstrapRequest{Email: "admin@example.com", DisplayName: "Admin",
		Password: "correct horse battery staple"})
	inviteProvider, err := service.ConfigureOIDCProvider(admin, OIDCProviderRequest{Name: "Invite provider",
		IssuerURL: "https://invite.example.test", ClientID: "client", ClientSecret: "secret",
		RedirectURL:      "https://mossward.example.test/api/auth/oidc/callback",
		ProvisioningMode: model.ProvisionInviteOnly, DefaultRole: model.RoleViewer}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.InviteUser(admin, "invited@example.com", model.RoleAnalyst, model.IdentitySSO, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	now := service.now()
	invited, err := repository.ResolveOIDCUser(inviteProvider, model.OIDCClaims{UserID: "invited-id", Subject: "subject-1", Email: "invited@example.com", Name: "Invited"},
		model.RoleViewer, now, model.AuditEvent{OccurredAt: now, Action: "test", Severity: model.AuditInfo})
	if err != nil || invited.Role != model.RoleAnalyst {
		t.Fatalf("invite role was not honored: user=%#v err=%v", invited, err)
	}
	if _, err := repository.ResolveOIDCUser(inviteProvider, model.OIDCClaims{UserID: "other-id", Subject: "uninvited", Email: "other@example.com", Name: "Other"},
		model.RoleViewer, now, model.AuditEvent{OccurredAt: now, Action: "test", Severity: model.AuditInfo}); err == nil {
		t.Fatal("invite-only provider provisioned an uninvited user")
	}

	jitProvider, err := service.ConfigureOIDCProvider(admin, OIDCProviderRequest{Name: "JIT provider",
		IssuerURL: "https://jit.example.test", ClientID: "client", ClientSecret: "secret",
		RedirectURL:      "https://mossward.example.test/api/auth/oidc/callback",
		ProvisioningMode: model.ProvisionJIT, DefaultRole: model.RoleViewer}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	claims := model.OIDCClaims{UserID: "jit-id", Subject: "jit-subject", Email: "jit@example.com", Name: "JIT User"}
	jitUser, err := repository.ResolveOIDCUser(jitProvider, claims, model.RoleViewer, now,
		model.AuditEvent{OccurredAt: now, Action: "test", Severity: model.AuditInfo})
	if err != nil || jitUser.Role != model.RoleViewer {
		t.Fatalf("JIT provisioning failed: user=%#v err=%v", jitUser, err)
	}
	updated, err := repository.ResolveOIDCUser(jitProvider, claims, model.RoleAnalyst, now.Add(time.Minute),
		model.AuditEvent{OccurredAt: now, Action: "test", Severity: model.AuditInfo})
	if err != nil || updated.ID != jitUser.ID || updated.Role != model.RoleAnalyst {
		t.Fatalf("JIT group-derived role was not re-evaluated: user=%#v err=%v", updated, err)
	}
}
