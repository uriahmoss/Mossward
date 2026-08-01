package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"mossward/internal/auth"
	"mossward/internal/config"
	"mossward/internal/model"
	"mossward/internal/scanner"
	"mossward/internal/store"
)

func testHandler(t *testing.T) (http.Handler, *store.SQLiteStore) {
	t.Helper()
	cfg := config.Config{
		AllowedCIDRs:   []string{"127.0.0.0/8", "::1/128"},
		AllowedPorts:   map[int]bool{80: true, 443: true},
		MaxTargets:     10,
		MaxConcurrent:  2,
		QueueSize:      2,
		ConnectTimeout: 20 * time.Millisecond,
	}
	repository, err := store.NewSQLiteStore(filepath.Join(t.TempDir(), "mossward.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repository.Close() })
	engine, err := scanner.New(cfg, repository)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Shutdown)
	secretBox, err := auth.LoadOrCreateSecretBox(filepath.Join(t.TempDir(), "identity.key"))
	if err != nil {
		t.Fatal(err)
	}
	webauthnManager, err := auth.NewWebAuthnManager("localhost", []string{"http://localhost:8080"})
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := auth.NewService(repository, secretBox, webauthnManager)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := identityService.BeginBootstrap(auth.BootstrapRequest{Email: "admin@example.test", DisplayName: "Admin", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCode(enrollment.Secret, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	user, _, err := identityService.CompleteBootstrap(enrollment.Token, code)
	if err != nil {
		t.Fatal(err)
	}
	token, err := identityService.CreateSession(user, "127.0.0.1", "test", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	handler := New(cfg, repository, engine, identityService)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
		if r.Method != http.MethodGet {
			r.Header.Set("X-Mossward-CSRF", "1")
		}
		handler.ServeHTTP(w, r)
	}), repository
}

func TestCreateScanAcceptsAuthorizedTarget(t *testing.T) {
	handler, repository := testHandler(t)
	body := bytes.NewBufferString(`{"name":"test","targets":["127.0.0.1"],"ports":[80]}`)
	request := httptest.NewRequest(http.MethodPost, "/api/scans", body)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("expected %d, got %d: %s", http.StatusAccepted, response.Code, response.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		scan, err := repository.Get(created.ID)
		if err != nil {
			t.Fatal(err)
		}
		if scan.Status == "completed" || scan.Status == "failed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("scan did not reach a terminal state")
		}
		time.Sleep(5 * time.Millisecond)
	}
	completed, err := repository.Get(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if completed.TotalChecks != 1 || completed.DoneChecks != 1 {
		t.Fatalf("expected completed progress 1/1, got %d/%d", completed.DoneChecks, completed.TotalChecks)
	}
}

func TestCreateScanUsesSelectedDatabaseScopePolicy(t *testing.T) {
	handler, repository := testHandler(t)
	now := time.Now().UTC()
	policy := model.ScopePolicy{ID: "web-only", Name: "Web only", AllowedCIDRs: []string{"127.0.0.0/8"},
		AllowedPorts: []int{443}, MaxTargets: 2, MaxConcurrent: 1, Enabled: true, CreatedAt: now, UpdatedAt: now}
	if err := repository.UpsertScopePolicy(policy, model.AuditEvent{OccurredAt: now, Action: "test", Severity: model.AuditInfo}); err != nil {
		t.Fatal(err)
	}
	body := bytes.NewBufferString(`{"name":"policy scan","scope_policy_id":"web-only","targets":["127.0.0.1"],"ports":[443]}`)
	request := httptest.NewRequest(http.MethodPost, "/api/scans", body)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("expected policy scan acceptance, got %d: %s", response.Code, response.Body.String())
	}
	var created model.Scan
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	stored, err := repository.Get(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ScopePolicyID != policy.ID || stored.MaxConcurrent != policy.MaxConcurrent {
		t.Fatalf("scan policy provenance was not persisted: %#v", stored)
	}

	request = httptest.NewRequest(http.MethodPost, "/api/scans", bytes.NewBufferString(
		`{"scope_policy_id":"web-only","targets":["127.0.0.1"],"ports":[80]}`))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected policy port rejection, got %d", response.Code)
	}
}

func TestCreateScanRejectsPublicTarget(t *testing.T) {
	handler, _ := testHandler(t)
	body := bytes.NewBufferString(`{"name":"test","targets":["8.8.8.8"],"ports":[443]}`)
	request := httptest.NewRequest(http.MethodPost, "/api/scans", body)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, response.Code)
	}
	var result map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["error"] == "" {
		t.Fatal("expected policy error")
	}
}

func TestCreateScanRejectsTrailingJSON(t *testing.T) {
	handler, _ := testHandler(t)
	body := bytes.NewBufferString(`{"targets":["127.0.0.1"]} {"unexpected":true}`)
	request := httptest.NewRequest(http.MethodPost, "/api/scans", body)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, response.Code)
	}
}

func TestWebRoutesServeHomeAndScanner(t *testing.T) {
	handler, _ := testHandler(t)
	for _, path := range []string{"/", "/scan.html", "/scan-detail.html", "/account.html", "/users.html", "/setup.html", "/login.html", "/accept-invite.html", "/styles.css", "/home.js", "/scan.js", "/scan-detail.js", "/account.js", "/users.js", "/setup.js", "/login.js", "/accept-invite.js"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Errorf("%s: expected %d, got %d", path, http.StatusOK, response.Code)
		}
		if response.Header().Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("%s: missing Referrer-Policy security header", path)
		}
	}
}

func TestUninitializedApplicationRedirectsToLocalSetup(t *testing.T) {
	cfg := config.Config{AllowedCIDRs: []string{"127.0.0.0/8"}, AllowedPorts: map[int]bool{80: true},
		MaxTargets: 1, MaxConcurrent: 1, QueueSize: 1, ConnectTimeout: 20 * time.Millisecond}
	repository, err := store.NewSQLiteStore(filepath.Join(t.TempDir(), "mossward.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repository.Close() })
	engine, err := scanner.New(cfg, repository)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Shutdown)
	box, err := auth.LoadOrCreateSecretBox(filepath.Join(t.TempDir(), "identity.key"))
	if err != nil {
		t.Fatal(err)
	}
	webauthnManager, err := auth.NewWebAuthnManager("localhost", []string{"http://localhost:8080"})
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := auth.NewService(repository, box, webauthnManager)
	if err != nil {
		t.Fatal(err)
	}
	handler := New(cfg, repository, engine, identityService)
	request := httptest.NewRequest(http.MethodGet, "/api/ready", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "setup_required") {
		t.Fatalf("expected local setup readiness, got %d: %s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, "/", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/setup.html" {
		t.Fatalf("expected setup redirect, got %d %q", response.Code, response.Header().Get("Location"))
	}

	request = httptest.NewRequest(http.MethodPost, "/api/auth/bootstrap/begin", bytes.NewBufferString(`{"email":"admin@example.test","display_name":"Admin","password":"correct horse battery staple"}`))
	request.RemoteAddr = "203.0.113.4:4444"
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("expected remote bootstrap rejection, got %d", response.Code)
	}
}

func TestTrustedProxyEstablishesSecureRequest(t *testing.T) {
	cfg := config.Config{TransportMode: config.TransportProxy, PublicOrigin: "https://mossward.example.com", TrustedProxyCIDRs: []string{"10.0.0.0/8"}}
	api := &API{cfg: cfg}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requestIsSecure(r) {
			http.SetCookie(w, &http.Cookie{Name: "test", Value: "value", Secure: true})
		}
		w.WriteHeader(http.StatusNoContent)
	})
	handler := api.trustedProxyRequest(api.transportSecurity(securityHeaders(inner)))

	request := httptest.NewRequest(http.MethodGet, "http://mossward.example.com/", nil)
	request.Host = "mossward.example.com"
	request.RemoteAddr = "10.1.2.3:443"
	request.Header.Set("X-Forwarded-Proto", "https")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || response.Header().Get("Strict-Transport-Security") == "" || !strings.Contains(response.Header().Get("Set-Cookie"), "Secure") {
		t.Fatalf("trusted HTTPS proxy was not honored: %d %#v", response.Code, response.Header())
	}

	request = httptest.NewRequest(http.MethodGet, "http://mossward.example.com/", nil)
	request.Host = "mossward.example.com"
	request.RemoteAddr = "192.0.2.5:443"
	request.Header.Set("X-Forwarded-Proto", "https")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected spoofed forwarded scheme rejection, got %d", response.Code)
	}
}

func TestIntelligenceEndpointsReturnEmptyLocalFeed(t *testing.T) {
	handler, _ := testHandler(t)
	for _, path := range []string{"/api/intelligence/news", "/api/intelligence/status"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("%s returned %d: %s", path, response.Code, response.Body.String())
		}
	}
}

func TestCertificateStatusReportsUnmanagedMode(t *testing.T) {
	handler, _ := testHandler(t)
	request := httptest.NewRequest(http.MethodGet, "/api/admin/certificate-status", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "not_managed") {
		t.Fatalf("unexpected certificate status: %d %s", response.Code, response.Body.String())
	}
}

func TestEndpointAdministrationReportsDisabledService(t *testing.T) {
	handler, _ := testHandler(t)
	request := httptest.NewRequest(http.MethodGet, "/api/admin/endpoints", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected disabled endpoint identity status, got %d", response.Code)
	}
}

func TestWebAuthnRegistrationRequiresAndUsesRecentMFA(t *testing.T) {
	handler, _ := testHandler(t)
	request := httptest.NewRequest(http.MethodPost, "/api/auth/webauthn/register/begin", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("expected registration options, got %d: %s", response.Code, response.Body.String())
	}
	var result struct {
		CeremonyToken string `json:"ceremony_token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.CeremonyToken == "" {
		t.Fatal("registration response omitted ceremony token")
	}
}

func TestForwardedClientIPRequiresTrustedDirectProxy(t *testing.T) {
	api := &API{cfg: config.Config{TrustedProxyCIDRs: []string{"10.0.0.0/8"}}}
	handler := api.trustedProxyRequest(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(requestIP(r)))
	}))
	for _, test := range []struct {
		peer      string
		forwarded string
		want      string
	}{{"203.0.113.5:443", "192.0.2.10", "203.0.113.5"},
		{"10.0.0.5:443", "192.0.2.10, 10.0.0.6", "192.0.2.10"}} {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.RemoteAddr = test.peer
		request.Header.Set("X-Forwarded-For", test.forwarded)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Body.String() != test.want {
			t.Fatalf("peer %s resolved to %q, want %q", test.peer, response.Body.String(), test.want)
		}
	}
}

func TestGetScanReturnsProgressFields(t *testing.T) {
	handler, repository := testHandler(t)
	body := bytes.NewBufferString(`{"name":"progress","targets":["127.0.0.1"],"ports":[80,443]}`)
	createRequest := httptest.NewRequest(http.MethodPost, "/api/scans", body)
	createResponse := httptest.NewRecorder()
	handler.ServeHTTP(createResponse, createRequest)

	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(createResponse.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		scan, err := repository.Get(created.ID)
		if err != nil {
			t.Fatal(err)
		}
		if scan.Status == "completed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("scan did not complete")
		}
		time.Sleep(5 * time.Millisecond)
	}

	getRequest := httptest.NewRequest(http.MethodGet, "/api/scans/"+created.ID, nil)
	getResponse := httptest.NewRecorder()
	handler.ServeHTTP(getResponse, getRequest)
	if getResponse.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, getResponse.Code)
	}
	var result struct {
		Total int `json:"total_checks"`
		Done  int `json:"done_checks"`
	}
	if err := json.Unmarshal(getResponse.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Total != 2 || result.Done != 2 {
		t.Fatalf("expected progress 2/2, got %d/%d", result.Done, result.Total)
	}
}
