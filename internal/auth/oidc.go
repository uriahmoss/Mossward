package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"mossward/internal/model"
	"mossward/internal/store"
)

type OIDCProviderRequest struct {
	ID                   string                    `json:"id"`
	Name                 string                    `json:"name"`
	IssuerURL            string                    `json:"issuer_url"`
	ClientID             string                    `json:"client_id"`
	ClientSecret         string                    `json:"client_secret"`
	RedirectURL          string                    `json:"redirect_url"`
	ProvisioningMode     model.ProvisioningMode    `json:"provisioning_mode"`
	AllowedTenantID      string                    `json:"allowed_tenant_id"`
	AllowedEmailDomains  []string                  `json:"allowed_email_domains"`
	AllowedGroups        []string                  `json:"allowed_groups"`
	RoleMappings         map[string]model.UserRole `json:"role_mappings"`
	DefaultRole          model.UserRole            `json:"default_role"`
	ConfirmAdministrator bool                      `json:"confirm_administrator_mapping"`
}

type oidcCeremonyState struct {
	ProviderID   string    `json:"provider_id"`
	Nonce        string    `json:"nonce"`
	PKCEVerifier string    `json:"pkce_verifier"`
	ExpiresAt    time.Time `json:"expires_at"`
}

func (s *Service) BeginOIDCLogin(ctx context.Context, providerID string) (string, error) {
	record, err := s.store.OIDCProvider(providerID)
	if err != nil || !record.Provider.Enabled {
		return "", store.ErrIdentityNotFound
	}
	provider, err := oidc.NewProvider(ctx, record.Provider.IssuerURL)
	if err != nil {
		return "", fmt.Errorf("discover OIDC provider: %w", err)
	}
	secret, err := s.secrets.Decrypt(record.ClientSecretCiphertext)
	if err != nil {
		return "", err
	}
	stateToken, err := randomHex(sessionTokenBytes)
	if err != nil {
		return "", err
	}
	nonce, err := randomHex(sessionTokenBytes)
	if err != nil {
		return "", err
	}
	verifier := oauth2.GenerateVerifier()
	now := s.now()
	state := oidcCeremonyState{ProviderID: providerID, Nonce: nonce, PKCEVerifier: verifier,
		ExpiresAt: now.Add(webAuthnCeremonyLifetime)}
	encoded, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	ciphertext, err := s.secrets.Encrypt(encoded)
	if err != nil {
		return "", err
	}
	rawState, _ := hex.DecodeString(stateToken)
	hash := sha256.Sum256(rawState)
	ceremony := model.AuthenticationCeremony{IDHash: hash[:], Kind: model.CeremonyOIDC,
		StateCiphertext: ciphertext, CreatedAt: now, ExpiresAt: state.ExpiresAt}
	if err := s.store.CreateAuthenticationCeremony(ceremony); err != nil {
		return "", err
	}
	config := oauth2.Config{ClientID: record.Provider.ClientID, ClientSecret: string(secret),
		Endpoint: provider.Endpoint(), RedirectURL: record.Provider.RedirectURL, Scopes: []string{oidc.ScopeOpenID, "profile", "email", "groups"}}
	return config.AuthCodeURL(stateToken, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), nil
}

func (s *Service) FinishOIDCLogin(ctx context.Context, stateToken, code, sourceIP, userAgent string) (model.User, string, error) {
	state, err := s.consumeOIDCCeremony(stateToken)
	if err != nil {
		return model.User{}, "", err
	}
	record, err := s.store.OIDCProvider(state.ProviderID)
	if err != nil || !record.Provider.Enabled {
		return model.User{}, "", ErrInvalidCredentials
	}
	provider, err := oidc.NewProvider(ctx, record.Provider.IssuerURL)
	if err != nil {
		return model.User{}, "", err
	}
	secret, err := s.secrets.Decrypt(record.ClientSecretCiphertext)
	if err != nil {
		return model.User{}, "", err
	}
	config := oauth2.Config{ClientID: record.Provider.ClientID, ClientSecret: string(secret), Endpoint: provider.Endpoint(),
		RedirectURL: record.Provider.RedirectURL, Scopes: []string{oidc.ScopeOpenID, "profile", "email", "groups"}}
	token, err := config.Exchange(ctx, code, oauth2.VerifierOption(state.PKCEVerifier))
	if err != nil {
		return model.User{}, "", ErrInvalidCredentials
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return model.User{}, "", ErrInvalidCredentials
	}
	idToken, err := provider.Verifier(&oidc.Config{ClientID: record.Provider.ClientID}).Verify(ctx, rawIDToken)
	if err != nil {
		return model.User{}, "", ErrInvalidCredentials
	}
	var rawClaims struct {
		Subject       string   `json:"sub"`
		Email         string   `json:"email"`
		Name          string   `json:"name"`
		TenantID      string   `json:"tid"`
		Nonce         string   `json:"nonce"`
		EmailVerified bool     `json:"email_verified"`
		Groups        []string `json:"groups"`
	}
	if err := idToken.Claims(&rawClaims); err != nil || rawClaims.Nonce != state.Nonce || rawClaims.Subject == "" || rawClaims.Email == "" {
		return model.User{}, "", ErrInvalidCredentials
	}
	claims := model.OIDCClaims{Subject: rawClaims.Subject, Email: rawClaims.Email, Name: rawClaims.Name,
		TenantID: rawClaims.TenantID, Groups: rawClaims.Groups}
	claims.UserID, err = randomHex(identifierBytes)
	if err != nil {
		return model.User{}, "", err
	}
	role, err := authorizeOIDCClaims(record.Provider, claims)
	if err != nil {
		return model.User{}, "", ErrInvalidCredentials
	}
	now := s.now()
	event := model.AuditEvent{OccurredAt: now, Action: "identity.oidc.login", Severity: model.AuditInfo,
		TargetType: "oidc_provider", TargetID: record.Provider.ID, SourceIP: sourceIP, Details: "{}"}
	user, err := s.store.ResolveOIDCUser(record.Provider, claims, role, now, event)
	if err != nil {
		return model.User{}, "", ErrInvalidCredentials
	}
	sessionToken, err := s.CreateSession(user, sourceIP, userAgent, now)
	return user, sessionToken, err
}

func (s *Service) consumeOIDCCeremony(token string) (oidcCeremonyState, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(token))
	if err != nil || len(raw) != sessionTokenBytes {
		return oidcCeremonyState{}, ErrInvalidCredentials
	}
	hash := sha256.Sum256(raw)
	ceremony, err := s.store.ConsumeAuthenticationCeremony(hash[:], model.CeremonyOIDC)
	if err != nil || !s.now().Before(ceremony.ExpiresAt) {
		return oidcCeremonyState{}, ErrInvalidCredentials
	}
	encoded, err := s.secrets.Decrypt(ceremony.StateCiphertext)
	if err != nil {
		return oidcCeremonyState{}, err
	}
	var state oidcCeremonyState
	if err := json.Unmarshal(encoded, &state); err != nil {
		return state, err
	}
	return state, nil
}

func authorizeOIDCClaims(provider model.OIDCProvider, claims model.OIDCClaims) (model.UserRole, error) {
	if provider.AllowedTenantID != "" && claims.TenantID != provider.AllowedTenantID {
		return "", errors.New("tenant not allowed")
	}
	if len(provider.AllowedEmailDomains) > 0 && !emailDomainAllowed(claims.Email, provider.AllowedEmailDomains) {
		return "", errors.New("email domain not allowed")
	}
	if len(provider.AllowedGroups) > 0 && !hasAnyGroup(claims.Groups, provider.AllowedGroups) {
		return "", errors.New("group not allowed")
	}
	role := provider.DefaultRole
	for _, group := range claims.Groups {
		if mapped, ok := provider.RoleMappings[group]; ok && roleRank(mapped) > roleRank(role) {
			role = mapped
		}
	}
	return role, nil
}

func emailDomainAllowed(email string, domains []string) bool {
	parts := strings.Split(strings.ToLower(email), "@")
	if len(parts) != 2 {
		return false
	}
	for _, domain := range domains {
		if parts[1] == strings.ToLower(domain) {
			return true
		}
	}
	return false
}

func hasAnyGroup(actual, allowed []string) bool {
	for _, candidate := range actual {
		for _, permitted := range allowed {
			if candidate == permitted {
				return true
			}
		}
	}
	return false
}

func roleRank(role model.UserRole) int {
	switch role {
	case model.RoleAdministrator:
		return 3
	case model.RoleAnalyst:
		return 2
	default:
		return 1
	}
}

func (s *Service) ConfigureOIDCProvider(actor model.User, request OIDCProviderRequest, sourceIP string) (model.OIDCProvider, error) {
	if err := validateOIDCProviderRequest(request); err != nil {
		return model.OIDCProvider{}, err
	}
	if oidcRequestGrantsAdministrator(request) && !request.ConfirmAdministrator {
		return model.OIDCProvider{}, errors.New("administrator mappings require explicit confirmation")
	}
	id := strings.TrimSpace(request.ID)
	var createdAt = s.now()
	if id == "" {
		var err error
		id, err = randomHex(identifierBytes)
		if err != nil {
			return model.OIDCProvider{}, err
		}
	} else if current, err := s.store.OIDCProvider(id); err == nil {
		createdAt = current.Provider.CreatedAt
	}
	secret, err := s.secrets.Encrypt([]byte(request.ClientSecret))
	if err != nil {
		return model.OIDCProvider{}, err
	}
	provider := model.OIDCProvider{ID: id, Name: strings.TrimSpace(request.Name), IssuerURL: strings.TrimRight(request.IssuerURL, "/"),
		ClientID: strings.TrimSpace(request.ClientID), RedirectURL: request.RedirectURL, ProvisioningMode: request.ProvisioningMode,
		AllowedTenantID: strings.TrimSpace(request.AllowedTenantID), AllowedEmailDomains: normalizedStrings(request.AllowedEmailDomains),
		AllowedGroups: normalizedStrings(request.AllowedGroups), RoleMappings: request.RoleMappings, DefaultRole: request.DefaultRole,
		CreatedAt: createdAt, UpdatedAt: s.now()}
	event := model.AuditEvent{OccurredAt: s.now(), ActorID: actor.ID, Action: "identity.oidc_provider.configured",
		Severity: model.AuditWarning, TargetType: "oidc_provider", TargetID: id, SourceIP: sourceIP, Details: "{}"}
	if err := s.store.UpsertOIDCProvider(model.OIDCProviderRecord{Provider: provider, ClientSecretCiphertext: secret}, event); err != nil {
		return model.OIDCProvider{}, err
	}
	return provider, nil
}

func (s *Service) OIDCProviders() ([]model.OIDCProvider, error) {
	records, err := s.store.ListOIDCProviders()
	if err != nil {
		return nil, err
	}
	providers := make([]model.OIDCProvider, 0, len(records))
	for _, record := range records {
		providers = append(providers, record.Provider)
	}
	return providers, nil
}

func (s *Service) TestOIDCProvider(ctx context.Context, actor model.User, id, sourceIP string) error {
	record, err := s.store.OIDCProvider(id)
	if err != nil {
		return err
	}
	provider, err := oidc.NewProvider(ctx, record.Provider.IssuerURL)
	if err != nil {
		return fmt.Errorf("OIDC discovery failed: %w", err)
	}
	_ = provider.Verifier(&oidc.Config{ClientID: record.Provider.ClientID})
	if _, err := s.secrets.Decrypt(record.ClientSecretCiphertext); err != nil {
		return err
	}
	now := s.now()
	event := model.AuditEvent{OccurredAt: now, ActorID: actor.ID, Action: "identity.oidc_provider.tested",
		Severity: model.AuditInfo, TargetType: "oidc_provider", TargetID: id, SourceIP: sourceIP, Details: "{}"}
	return s.store.MarkOIDCProviderTested(id, now, event)
}

func (s *Service) SetOIDCProviderEnabled(actor model.User, id string, enabled bool, sourceIP string) error {
	now := s.now()
	event := model.AuditEvent{OccurredAt: now, ActorID: actor.ID, Action: "identity.oidc_provider.enabled_changed",
		Severity: model.AuditWarning, TargetType: "oidc_provider", TargetID: id, SourceIP: sourceIP,
		Details: jsonObject(map[string]any{"enabled": enabled})}
	return s.store.SetOIDCProviderEnabled(id, enabled, now, event)
}

func validateOIDCProviderRequest(request OIDCProviderRequest) error {
	if strings.TrimSpace(request.Name) == "" || strings.TrimSpace(request.ClientID) == "" || request.ClientSecret == "" {
		return errors.New("provider name, client ID, and client secret are required")
	}
	for _, raw := range []string{request.IssuerURL, request.RedirectURL} {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && !isLoopbackURL(parsed)) {
			return errors.New("issuer and redirect URLs must use HTTPS outside localhost")
		}
	}
	if request.ProvisioningMode != model.ProvisionInviteOnly && request.ProvisioningMode != model.ProvisionJIT {
		return errors.New("valid provisioning mode is required")
	}
	if !validRole(request.DefaultRole) {
		return errors.New("valid default role is required")
	}
	for _, role := range request.RoleMappings {
		if !validRole(role) {
			return errors.New("role mappings contain an invalid role")
		}
	}
	return nil
}

func oidcRequestGrantsAdministrator(request OIDCProviderRequest) bool {
	if request.ProvisioningMode == model.ProvisionJIT && request.DefaultRole == model.RoleAdministrator {
		return true
	}
	for _, role := range request.RoleMappings {
		if role == model.RoleAdministrator {
			return true
		}
	}
	return false
}

func isLoopbackURL(value *url.URL) bool {
	host := strings.Split(value.Host, ":")[0]
	return host == "localhost" || host == "127.0.0.1" || host == "[::1]"
}

func normalizedStrings(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
