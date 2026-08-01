package api

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	identity "mossward/internal/auth"
	"mossward/internal/model"
	"mossward/internal/store"
)

const (
	sessionCookieName = "mossward_session"
	sessionCookieAge  = 12 * time.Hour
)

func (a *API) registerIdentityRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/auth/status", a.identityStatus)
	mux.HandleFunc("POST /api/auth/bootstrap/begin", a.beginBootstrap)
	mux.HandleFunc("POST /api/auth/bootstrap/complete", a.completeBootstrap)
	mux.HandleFunc("POST /api/auth/login", a.login)
	mux.HandleFunc("POST /api/auth/webauthn/login/begin", a.beginWebAuthnLogin)
	mux.HandleFunc("POST /api/auth/webauthn/login/finish", a.finishWebAuthnLogin)
	mux.HandleFunc("POST /api/auth/logout", a.logout)
	mux.HandleFunc("GET /api/auth/sessions", a.listSessions)
	mux.HandleFunc("DELETE /api/auth/sessions/{id}", a.revokeSession)
	mux.HandleFunc("POST /api/auth/sessions/revoke-others", a.revokeOtherSessions)
	mux.HandleFunc("POST /api/auth/mfa/verify", a.refreshMFA)
	mux.HandleFunc("GET /api/auth/webauthn/credentials", a.listWebAuthnCredentials)
	mux.HandleFunc("POST /api/auth/webauthn/register/begin", a.beginWebAuthnRegistration)
	mux.HandleFunc("POST /api/auth/webauthn/register/finish", a.finishWebAuthnRegistration)
	mux.HandleFunc("DELETE /api/auth/webauthn/credentials/{id}", a.removeWebAuthnCredential)
	mux.HandleFunc("GET /api/users", a.listUsers)
	mux.HandleFunc("PATCH /api/users/{id}", a.updateUser)
	mux.HandleFunc("GET /api/invitations", a.listInvitations)
	mux.HandleFunc("POST /api/invitations", a.createInvitation)
	mux.HandleFunc("POST /api/invitations/accept/begin", a.beginInvitationAcceptance)
	mux.HandleFunc("POST /api/invitations/accept/complete", a.completeInvitationAcceptance)
	mux.HandleFunc("GET /api/auth/oidc/providers", a.publicOIDCProviders)
	mux.HandleFunc("GET /api/auth/oidc/{id}/start", a.beginOIDCLogin)
	mux.HandleFunc("GET /api/auth/oidc/callback", a.finishOIDCLogin)
	mux.HandleFunc("GET /api/admin/oidc/providers", a.listOIDCProviders)
	mux.HandleFunc("POST /api/admin/oidc/providers", a.configureOIDCProvider)
	mux.HandleFunc("POST /api/admin/oidc/providers/{id}/test", a.testOIDCProvider)
	mux.HandleFunc("POST /api/admin/oidc/providers/{id}/enabled", a.setOIDCProviderEnabled)
	mux.HandleFunc("GET /api/admin/auth-policy", a.getAuthenticationPolicy)
	mux.HandleFunc("PUT /api/admin/auth-policy", a.updateAuthenticationPolicy)
	mux.HandleFunc("GET /api/admin/audit-events", a.listAuditEvents)
	mux.HandleFunc("GET /api/scope-policies", a.listEnabledScopePolicies)
	mux.HandleFunc("GET /api/admin/scope-policies", a.listAllScopePolicies)
	mux.HandleFunc("POST /api/admin/scope-policies", a.saveScopePolicy)
	mux.HandleFunc("PUT /api/admin/scope-policies/{id}", a.saveScopePolicy)
}

func (a *API) getAuthenticationPolicy(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdministrator(w, r); !ok {
		return
	}
	policy, err := a.auth.Policy()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load authentication policy")
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

func (a *API) updateAuthenticationPolicy(w http.ResponseWriter, r *http.Request) {
	actor, _, ok := a.requireAdministratorWithRecentMFA(w, r)
	if !ok {
		return
	}
	var policy model.AuthenticationPolicy
	if !decodeJSON(w, r, &policy) {
		return
	}
	if err := a.auth.UpdatePolicy(actor, policy, requestIP(r)); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) listAuditEvents(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdministrator(w, r); !ok {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	events, err := a.auth.AuditEvents(r.URL.Query().Get("q"), model.AuditSeverity(r.URL.Query().Get("severity")), limit)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, events)
}

func (a *API) publicOIDCProviders(w http.ResponseWriter, _ *http.Request) {
	providers, err := a.auth.OIDCProviders()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load SSO providers")
		return
	}
	items := []map[string]string{}
	for _, provider := range providers {
		if provider.Enabled {
			items = append(items, map[string]string{"id": provider.ID, "name": provider.Name})
		}
	}
	writeJSON(w, http.StatusOK, items)
}

func (a *API) beginOIDCLogin(w http.ResponseWriter, r *http.Request) {
	destination, err := a.auth.BeginOIDCLogin(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "SSO provider is unavailable")
		return
	}
	http.Redirect(w, r, destination, http.StatusSeeOther)
}

func (a *API) finishOIDCLogin(w http.ResponseWriter, r *http.Request) {
	user, token, err := a.auth.FinishOIDCLogin(r.Context(), r.URL.Query().Get("state"), r.URL.Query().Get("code"), requestIP(r), r.UserAgent())
	if err != nil {
		writeError(w, http.StatusUnauthorized, "SSO authentication failed")
		return
	}
	a.setSessionCookie(w, r, token)
	slog.Info("OIDC login completed", "user_id", user.ID)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *API) listOIDCProviders(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdministrator(w, r); !ok {
		return
	}
	providers, err := a.auth.OIDCProviders()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load OIDC providers")
		return
	}
	writeJSON(w, http.StatusOK, providers)
}

func (a *API) configureOIDCProvider(w http.ResponseWriter, r *http.Request) {
	actor, _, ok := a.requireAdministratorWithRecentMFA(w, r)
	if !ok {
		return
	}
	var request identity.OIDCProviderRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	provider, err := a.auth.ConfigureOIDCProvider(actor, request, requestIP(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, provider)
}

func (a *API) testOIDCProvider(w http.ResponseWriter, r *http.Request) {
	actor, _, ok := a.requireAdministratorWithRecentMFA(w, r)
	if !ok {
		return
	}
	if err := a.auth.TestOIDCProvider(r.Context(), actor, r.PathValue("id"), requestIP(r)); err != nil {
		writeError(w, http.StatusBadGateway, "OIDC discovery test failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) setOIDCProviderEnabled(w http.ResponseWriter, r *http.Request) {
	actor, _, ok := a.requireAdministratorWithRecentMFA(w, r)
	if !ok {
		return
	}
	var request struct {
		Enabled bool `json:"enabled"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	if err := a.auth.SetOIDCProviderEnabled(actor, r.PathValue("id"), request.Enabled, requestIP(r)); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) beginInvitationAcceptance(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Token       string `json:"token"`
		DisplayName string `json:"display_name"`
		Password    string `json:"password"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	enrollment, err := a.auth.BeginLocalInvitation(request.Token, request.DisplayName, request.Password)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invitation is invalid or expired")
		return
	}
	writeJSON(w, http.StatusOK, enrollment)
}

func (a *API) completeInvitationAcceptance(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Token string `json:"token"`
		Code  string `json:"code"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	user, codes, err := a.auth.CompleteLocalInvitation(request.Token, request.Code, requestIP(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	session, err := a.auth.CreateSession(user, requestIP(r), r.UserAgent(), time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "account created; sign in to continue")
		return
	}
	a.setSessionCookie(w, r, session)
	writeJSON(w, http.StatusCreated, map[string]any{"user": user, "recovery_codes": codes})
}

func (a *API) listUsers(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdministrator(w, r); !ok {
		return
	}
	users, err := a.auth.Users()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load users")
		return
	}
	writeJSON(w, http.StatusOK, users)
}

func (a *API) listInvitations(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdministrator(w, r); !ok {
		return
	}
	items, err := a.auth.Invitations()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load invitations")
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (a *API) createInvitation(w http.ResponseWriter, r *http.Request) {
	actor, _, ok := a.requireAdministratorWithRecentMFA(w, r)
	if !ok {
		return
	}
	var request struct {
		Email        string             `json:"email"`
		Role         model.UserRole     `json:"role"`
		IdentityKind model.IdentityKind `json:"identity_kind"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	result, err := a.auth.InviteUser(actor, request.Email, request.Role, request.IdentityKind, requestIP(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, result)
}

func (a *API) updateUser(w http.ResponseWriter, r *http.Request) {
	actor, _, ok := a.requireAdministratorWithRecentMFA(w, r)
	if !ok {
		return
	}
	var request struct {
		Role   model.UserRole   `json:"role"`
		Status model.UserStatus `json:"status"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	err := a.auth.UpdateUserAccess(actor, r.PathValue("id"), request.Role, request.Status, requestIP(r))
	if errors.Is(err, store.ErrFinalAdministrator) {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "could not update user access")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) requireAdministrator(w http.ResponseWriter, r *http.Request) (model.User, bool) {
	user, ok := a.currentUser(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return model.User{}, false
	}
	if user.Role != model.RoleAdministrator {
		writeError(w, http.StatusForbidden, "administrator role required")
		return model.User{}, false
	}
	return user, true
}

func (a *API) requireAdministratorWithRecentMFA(w http.ResponseWriter, r *http.Request) (model.User, string, bool) {
	user, token, ok := a.requireRecentMFA(w, r)
	if !ok {
		return model.User{}, "", false
	}
	if user.Role != model.RoleAdministrator {
		writeError(w, http.StatusForbidden, "administrator role required")
		return model.User{}, "", false
	}
	return user, token, true
}

func (a *API) beginWebAuthnLogin(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	assertion, token, err := a.auth.BeginWebAuthnLogin(request.Email, request.Password, requestIP(r))
	if errors.Is(err, identity.ErrLoginRateLimited) {
		writeError(w, http.StatusTooManyRequests, err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid email, password, or security key")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"options": assertion, "ceremony_token": token})
}

func (a *API) finishWebAuthnLogin(w http.ResponseWriter, r *http.Request) {
	user, token, err := a.auth.FinishWebAuthnLogin(r.Header.Get("X-Mossward-Ceremony"), requestIP(r), r.UserAgent(), r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "security-key authentication failed")
		return
	}
	a.setSessionCookie(w, r, token)
	writeJSON(w, http.StatusOK, user)
}

func (a *API) refreshMFA(w http.ResponseWriter, r *http.Request) {
	user, token, ok := a.authenticatedRequest(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var request struct {
		Code string `json:"code"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	if err := a.auth.RefreshMFA(user, token, request.Code, requestIP(r)); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid authenticator or recovery code")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) beginWebAuthnRegistration(w http.ResponseWriter, r *http.Request) {
	user, _, ok := a.requireRecentMFA(w, r)
	if !ok {
		return
	}
	creation, token, err := a.auth.BeginWebAuthnRegistration(user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not begin security-key registration")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"options": creation, "ceremony_token": token})
}

func (a *API) finishWebAuthnRegistration(w http.ResponseWriter, r *http.Request) {
	user, _, ok := a.requireRecentMFA(w, r)
	if !ok {
		return
	}
	if err := a.auth.FinishWebAuthnRegistration(user, r.Header.Get("X-Mossward-Ceremony"),
		r.Header.Get("X-Mossward-Credential-Name"), r); err != nil {
		writeError(w, http.StatusBadRequest, "security-key registration could not be verified")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) listWebAuthnCredentials(w http.ResponseWriter, r *http.Request) {
	user, ok := a.currentUser(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	credentials, err := a.auth.WebAuthnCredentials(user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load security keys")
		return
	}
	items := make([]map[string]any, 0, len(credentials))
	for _, credential := range credentials {
		items = append(items, map[string]any{"id": hex.EncodeToString(credential.Credential.ID), "name": credential.Name,
			"created_at": credential.CreatedAt, "last_used_at": credential.LastUsedAt})
	}
	writeJSON(w, http.StatusOK, items)
}

func (a *API) removeWebAuthnCredential(w http.ResponseWriter, r *http.Request) {
	user, _, ok := a.requireRecentMFA(w, r)
	if !ok {
		return
	}
	if err := a.auth.RemoveWebAuthnCredential(user.ID, r.PathValue("id")); err != nil {
		writeError(w, http.StatusNotFound, "security key not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) requireRecentMFA(w http.ResponseWriter, r *http.Request) (model.User, string, bool) {
	user, token, ok := a.authenticatedRequest(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return model.User{}, "", false
	}
	recent, err := a.auth.HasRecentMFA(user.ID, token)
	if err != nil || !recent {
		writeError(w, http.StatusForbidden, "recent MFA verification required")
		return model.User{}, "", false
	}
	return user, token, true
}

func (a *API) authenticatedRequest(r *http.Request) (model.User, string, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return model.User{}, "", false
	}
	user, err := a.auth.SessionUser(cookie.Value)
	return user, cookie.Value, err == nil
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		_ = a.auth.Logout(cookie.Value, requestIP(r))
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", HttpOnly: true,
		Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) identityStatus(w http.ResponseWriter, r *http.Request) {
	initialized, err := a.auth.Initialized()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read identity state")
		return
	}
	_, authenticated := a.currentUser(r)
	writeJSON(w, http.StatusOK, map[string]bool{"initialized": initialized, "authenticated": authenticated})
}

func (a *API) beginBootstrap(w http.ResponseWriter, r *http.Request) {
	if !requestIsLoopback(r) {
		writeError(w, http.StatusForbidden, "initial setup is restricted to localhost")
		return
	}
	var request identity.BootstrapRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	request.SourceIP = requestIP(r)
	enrollment, err := a.auth.BeginBootstrap(request)
	if errors.Is(err, store.ErrAlreadyInitialized) {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, enrollment)
}

func (a *API) completeBootstrap(w http.ResponseWriter, r *http.Request) {
	if !requestIsLoopback(r) {
		writeError(w, http.StatusForbidden, "initial setup is restricted to localhost")
		return
	}
	var request struct {
		Token string `json:"token"`
		Code  string `json:"code"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	user, recoveryCodes, err := a.auth.CompleteBootstrap(request.Token, request.Code)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	sessionToken, err := a.auth.CreateSession(user, requestIP(r), r.UserAgent(), time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "administrator created; sign in to continue")
		return
	}
	a.setSessionCookie(w, r, sessionToken)
	writeJSON(w, http.StatusCreated, map[string]any{"user": user, "recovery_codes": recoveryCodes})
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	user, token, err := a.auth.AuthenticateLocal(request.Email, request.Password, request.Code, requestIP(r), r.UserAgent())
	if errors.Is(err, identity.ErrLoginRateLimited) {
		writeError(w, http.StatusTooManyRequests, err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid email, password, or authenticator code")
		return
	}
	a.setSessionCookie(w, r, token)
	writeJSON(w, http.StatusOK, user)
}

func (a *API) listSessions(w http.ResponseWriter, r *http.Request) {
	user, ok := a.currentUser(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	cookie, _ := r.Cookie(sessionCookieName)
	sessions, err := a.auth.Sessions(user.ID, cookie.Value)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load sessions")
		return
	}
	writeJSON(w, http.StatusOK, sessions)
}

func (a *API) revokeSession(w http.ResponseWriter, r *http.Request) {
	user, ok := a.currentUser(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if err := a.auth.RevokeSession(user, r.PathValue("id"), requestIP(r)); err != nil {
		writeError(w, http.StatusInternalServerError, "could not revoke session")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) revokeOtherSessions(w http.ResponseWriter, r *http.Request) {
	user, ok := a.currentUser(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	cookie, _ := r.Cookie(sessionCookieName)
	if err := a.auth.RevokeOtherSessions(user, cookie.Value, requestIP(r)); err != nil {
		writeError(w, http.StatusInternalServerError, "could not revoke sessions")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) identityGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requestNeedsCSRF(r) && r.Header.Get("X-Mossward-CSRF") != "1" {
			writeError(w, http.StatusForbidden, "CSRF validation failed")
			return
		}
		if identityPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		initialized, err := a.auth.Initialized()
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "identity service unavailable")
			return
		}
		if !initialized {
			redirectOrError(w, r, "/setup.html", "initial setup required")
			return
		}
		if _, ok := a.currentUser(r); !ok {
			redirectOrError(w, r, "/login.html", "authentication required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requestNeedsCSRF(r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return false
	}
	_, err := r.Cookie(sessionCookieName)
	return err == nil
}

func (a *API) currentUser(r *http.Request) (model.User, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return model.User{}, false
	}
	user, err := a.auth.SessionUser(cookie.Value)
	return user, err == nil
}

func identityPublicPath(path string) bool {
	if path == "/api/health" || path == "/api/auth/status" || path == "/api/auth/login" ||
		path == "/api/auth/webauthn/login/begin" || path == "/api/auth/webauthn/login/finish" ||
		path == "/api/invitations/accept/begin" || path == "/api/invitations/accept/complete" ||
		path == "/api/auth/oidc/providers" || strings.HasPrefix(path, "/api/auth/oidc/") ||
		path == "/api/auth/bootstrap/begin" || path == "/api/auth/bootstrap/complete" ||
		path == "/setup.html" || path == "/login.html" || path == "/accept-invite.html" {
		return true
	}
	return strings.HasSuffix(path, ".css") || strings.HasSuffix(path, ".js")
}

func decodeJSON(w http.ResponseWriter, r *http.Request, value any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON request")
		return false
	}
	return true
}

func redirectOrError(w http.ResponseWriter, r *http.Request, destination, message string) {
	if r.Method == http.MethodGet && !strings.HasPrefix(r.URL.Path, "/api/") {
		http.Redirect(w, r, destination, http.StatusSeeOther)
		return
	}
	writeError(w, http.StatusUnauthorized, message)
}

func (a *API) setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	maxAge := int(sessionCookieAge.Seconds())
	if policy, err := a.auth.Policy(); err == nil {
		maxAge = int((time.Duration(policy.SessionLifetimeMinutes) * time.Minute).Seconds())
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: token, Path: "/", HttpOnly: true,
		Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: maxAge})
}

func requestIsLoopback(r *http.Request) bool {
	ip := net.ParseIP(requestIP(r))
	if ip == nil || !ip.IsLoopback() {
		return false
	}
	host := r.Host
	if parsed, _, err := net.SplitHostPort(r.Host); err == nil {
		host = parsed
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	hostIP := net.ParseIP(strings.Trim(host, "[]"))
	return hostIP != nil && hostIP.IsLoopback()
}

func requestIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
