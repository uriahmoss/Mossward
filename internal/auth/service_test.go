package auth

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	wa "github.com/go-webauthn/webauthn/webauthn"
	"github.com/pquerna/otp/totp"

	"mossward/internal/model"
	"mossward/internal/store"
)

func TestWebAuthnCredentialEncryptedRoundTrip(t *testing.T) {
	service, repository := testService(t)
	user := completeTestBootstrap(t, service, BootstrapRequest{Email: "admin@example.com", DisplayName: "Admin",
		Password: "correct horse battery staple"})
	original := &wa.Credential{ID: []byte("credential-id"), PublicKey: []byte("sensitive-public-key-record")}
	if err := service.StoreWebAuthnCredential(user.ID, "MacBook Touch ID", original); err != nil {
		t.Fatal(err)
	}
	records, err := repository.ListWebAuthnCredentials(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || bytes.Contains(records[0].CredentialCiphertext, original.PublicKey) {
		t.Fatalf("credential was not encrypted at rest: %#v", records)
	}
	credentials, err := service.WebAuthnCredentials(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(credentials) != 1 || credentials[0].Name != "MacBook Touch ID" ||
		!bytes.Equal(credentials[0].Credential.ID, original.ID) ||
		!bytes.Equal(credentials[0].Credential.PublicKey, original.PublicKey) {
		t.Fatalf("credential did not round-trip: %#v", credentials)
	}
}

func TestWebAuthnCeremonyIsEncryptedExpiringAndSingleUse(t *testing.T) {
	service, _ := testService(t)
	user := completeTestBootstrap(t, service, BootstrapRequest{Email: "admin@example.com", DisplayName: "Admin",
		Password: "correct horse battery staple"})
	data := &wa.SessionData{Challenge: "registration-challenge", UserID: []byte(user.ID),
		Expires: service.now().Add(10 * time.Minute)}
	token, err := service.BeginWebAuthnCeremony(user.ID, model.CeremonyWebAuthnRegister, data)
	if err != nil {
		t.Fatal(err)
	}
	loaded, loadedUserID, err := service.ConsumeWebAuthnCeremony(token, model.CeremonyWebAuthnRegister)
	if err != nil {
		t.Fatal(err)
	}
	if loadedUserID != user.ID || loaded.Challenge != data.Challenge {
		t.Fatalf("unexpected ceremony data: user=%q data=%#v", loadedUserID, loaded)
	}
	if _, _, err := service.ConsumeWebAuthnCeremony(token, model.CeremonyWebAuthnRegister); !errors.Is(err, ErrWebAuthnCeremonyExpired) {
		t.Fatalf("expected consumed ceremony to be rejected, got %v", err)
	}

	expiredToken, err := service.BeginWebAuthnCeremony("", model.CeremonyWebAuthnLogin,
		&wa.SessionData{Challenge: "login-challenge", Expires: service.now().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return time.Date(2026, 8, 1, 12, 2, 0, 0, time.UTC) }
	if _, _, err := service.ConsumeWebAuthnCeremony(expiredToken, model.CeremonyWebAuthnLogin); !errors.Is(err, ErrWebAuthnCeremonyExpired) {
		t.Fatalf("expected expired ceremony to be rejected, got %v", err)
	}
}

func TestRecentMFAExpiresAndCanBeRefreshed(t *testing.T) {
	service, _ := testService(t)
	enrollment, err := service.BeginBootstrap(BootstrapRequest{Email: "admin@example.com", DisplayName: "Admin",
		Password: "correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enrollment.QRCodeDataURI, "data:image/png;base64,") || enrollment.OTPAuthURL == "" {
		t.Fatalf("bootstrap enrollment is missing QR provisioning: %#v", enrollment)
	}
	code, err := totp.GenerateCode(enrollment.Secret, service.now())
	if err != nil {
		t.Fatal(err)
	}
	user, _, err := service.CompleteBootstrap(enrollment.Token, code)
	if err != nil {
		t.Fatal(err)
	}
	token, err := service.CreateSession(user, "127.0.0.1", "test", service.now().Add(-recentMFALifetime-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	recent, err := service.HasRecentMFA(user.ID, token)
	if err != nil || recent {
		t.Fatalf("expected expired MFA verification, recent=%t err=%v", recent, err)
	}
	newCode, err := totp.GenerateCode(enrollment.Secret, service.now())
	if err != nil {
		t.Fatal(err)
	}
	if err := service.RefreshMFA(user, token, newCode, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	recent, err = service.HasRecentMFA(user.ID, token)
	if err != nil || !recent {
		t.Fatalf("expected refreshed MFA verification, recent=%t err=%v", recent, err)
	}
}

func TestInvitationTokenIsRandomHashedAndExpiring(t *testing.T) {
	service, _ := testService(t)
	admin := completeTestBootstrap(t, service, BootstrapRequest{Email: "admin@example.com", DisplayName: "Admin",
		Password: "correct horse battery staple"})
	result, err := service.InviteUser(admin, "analyst@example.com", model.RoleAnalyst, model.IdentityLocal, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	rawToken, err := hex.DecodeString(result.Token)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(rawToken)
	if len(result.Token) != sessionTokenBytes*2 || !bytes.Equal(hash[:], result.Invitation.TokenHash) {
		t.Fatal("invitation token was not stored as a one-way hash")
	}
	if !result.Invitation.ExpiresAt.Equal(service.now().Add(invitationLifetime)) {
		t.Fatalf("unexpected invitation expiration: %v", result.Invitation.ExpiresAt)
	}
	items, err := service.Invitations()
	if err != nil || len(items) != 1 || len(items[0].TokenHash) != 0 {
		t.Fatalf("unexpected invitation listing: %#v err=%v", items, err)
	}
}

func TestFinalLocalAdministratorCannotBeDisabledOrDemoted(t *testing.T) {
	service, _ := testService(t)
	admin := completeTestBootstrap(t, service, BootstrapRequest{Email: "admin@example.com", DisplayName: "Admin",
		Password: "correct horse battery staple"})
	for _, change := range []struct {
		role   model.UserRole
		status model.UserStatus
	}{{model.RoleViewer, model.UserActive}, {model.RoleAdministrator, model.UserDisabled}} {
		err := service.UpdateUserAccess(admin, admin.ID, change.role, change.status, "127.0.0.1")
		if !errors.Is(err, store.ErrFinalAdministrator) {
			t.Fatalf("expected final administrator protection, got %v", err)
		}
	}
}

func TestLocalInvitationAcceptanceIsSingleUseAndRequiresMFA(t *testing.T) {
	service, repository := testService(t)
	admin := completeTestBootstrap(t, service, BootstrapRequest{Email: "admin@example.com", DisplayName: "Admin",
		Password: "correct horse battery staple"})
	invited, err := service.InviteUser(admin, "analyst@example.com", model.RoleAnalyst, model.IdentityLocal, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := service.BeginLocalInvitation(invited.Token, "Invited Analyst", "another correct horse password")
	if err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCode(enrollment.Secret, service.now())
	if err != nil {
		t.Fatal(err)
	}
	user, recoveryCodes, err := service.CompleteLocalInvitation(enrollment.Token, code, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if user.Role != model.RoleAnalyst || len(recoveryCodes) != recoveryCodeCount {
		t.Fatalf("unexpected invited user: %#v codes=%d", user, len(recoveryCodes))
	}
	identity, err := repository.LocalIdentityByEmail(user.Email)
	if err != nil || identity.PasswordHash == "" {
		t.Fatalf("invited identity was not persisted: %#v err=%v", identity, err)
	}
	if _, err := service.BeginLocalInvitation(invited.Token, "Replay", "another correct horse password"); !errors.Is(err, store.ErrIdentityNotFound) {
		t.Fatalf("expected accepted invitation token to be rejected, got %v", err)
	}
}

func TestAuthenticationPolicyControlsSessionsMFAAndAuditSearch(t *testing.T) {
	service, _ := testService(t)
	admin := completeTestBootstrap(t, service, BootstrapRequest{Email: "admin@example.com", DisplayName: "Admin",
		Password: "correct horse battery staple"})
	policy := model.AuthenticationPolicy{SessionLifetimeMinutes: 30, AuditRetentionDays: 90,
		MFARequired: map[model.UserRole]bool{model.RoleAdministrator: true, model.RoleAnalyst: true, model.RoleViewer: false}}
	if err := service.UpdatePolicy(admin, policy, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	token, err := service.CreateSession(admin, "127.0.0.1", "test", service.now())
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := service.Sessions(admin.ID, token)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].ExpiresAt.Sub(sessions[0].CreatedAt) != 30*time.Minute {
		t.Fatalf("session policy was not applied: %#v", sessions)
	}
	events, err := service.AuditEvents("authentication_policy", model.AuditWarning, 20)
	if err != nil || len(events) != 1 || events[0].Action != "identity.authentication_policy.updated" {
		t.Fatalf("audit search did not find policy update: %#v err=%v", events, err)
	}
	policy.MFARequired[model.RoleAdministrator] = false
	if err := service.UpdatePolicy(admin, policy, "127.0.0.1"); err == nil {
		t.Fatal("expected disabling Administrator MFA to fail")
	}
}

func testService(t *testing.T) (*Service, *store.SQLiteStore) {
	t.Helper()
	repository, err := store.NewSQLiteStore(filepath.Join(t.TempDir(), "mossward.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repository.Close() })
	box, err := LoadOrCreateSecretBox(filepath.Join(t.TempDir(), "identity.key"))
	if err != nil {
		t.Fatal(err)
	}
	webauthnManager, err := NewWebAuthnManager("localhost", []string{"http://localhost:8080"})
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(repository, box, webauthnManager)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC) }
	return service, repository
}

func TestBootstrapAdministratorIsLocalAndOneTime(t *testing.T) {
	service, repository := testService(t)
	user := completeTestBootstrap(t, service, BootstrapRequest{Email: "Admin@Example.com", DisplayName: "Admin",
		Password: "correct horse battery staple", SourceIP: "127.0.0.1"})
	if user.Email != "admin@example.com" || user.Role != model.RoleAdministrator || !user.MFARequired {
		t.Fatalf("unexpected bootstrap user: %#v", user)
	}
	identity, err := repository.LocalIdentityByEmail(user.Email)
	if err != nil {
		t.Fatal(err)
	}
	if identity.PasswordHash == "" || identity.PasswordHash == "correct horse battery staple" {
		t.Fatal("bootstrap password was not hashed")
	}
	_, err = service.BeginBootstrap(BootstrapRequest{Email: "other@example.com", DisplayName: "Other",
		Password: "another correct horse password"})
	if !errors.Is(err, store.ErrAlreadyInitialized) {
		t.Fatalf("expected one-time bootstrap error, got %v", err)
	}
}

func TestLocalPasswordAndSessionRoundTrip(t *testing.T) {
	service, _ := testService(t)
	user := completeTestBootstrap(t, service, BootstrapRequest{Email: "admin@example.com", DisplayName: "Admin",
		Password: "correct horse battery staple"})
	authenticated, err := service.VerifyLocalPassword(user.Email, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	verifiedAt := service.now()
	token, err := service.CreateSession(authenticated, "127.0.0.1", "test-agent", verifiedAt)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := service.SessionUser(token)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ID != user.ID {
		t.Fatalf("session user ID = %q, want %q", loaded.ID, user.ID)
	}
	if _, err := service.VerifyLocalPassword(user.Email, "wrong password value"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected generic credential error, got %v", err)
	}
}

func TestTOTPCodeCannotBeReplayed(t *testing.T) {
	service, _ := testService(t)
	enrollment, err := service.BeginBootstrap(BootstrapRequest{Email: "admin@example.com", DisplayName: "Admin",
		Password: "correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCode(enrollment.Secret, service.now())
	if err != nil {
		t.Fatal(err)
	}
	user, _, err := service.CompleteBootstrap(enrollment.Token, code)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.AuthenticateLocal(user.Email, "correct horse battery staple", code, "127.0.0.1", "test"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.AuthenticateLocal(user.Email, "correct horse battery staple", code, "127.0.0.1", "test"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected replayed TOTP to fail generically, got %v", err)
	}
}

func TestRecoveryCodeIsSingleUse(t *testing.T) {
	service, _ := testService(t)
	enrollment, err := service.BeginBootstrap(BootstrapRequest{Email: "admin@example.com", DisplayName: "Admin",
		Password: "correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCode(enrollment.Secret, service.now())
	if err != nil {
		t.Fatal(err)
	}
	user, recoveryCodes, err := service.CompleteBootstrap(enrollment.Token, code)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.AuthenticateLocal(user.Email, "correct horse battery staple", recoveryCodes[0], "127.0.0.1", "test"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.AuthenticateLocal(user.Email, "correct horse battery staple", recoveryCodes[0], "127.0.0.1", "test"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected reused recovery code to fail generically, got %v", err)
	}
}

func TestRepeatedFailuresTemporarilyThrottleLogin(t *testing.T) {
	service, _ := testService(t)
	enrollment, err := service.BeginBootstrap(BootstrapRequest{Email: "admin@example.com", DisplayName: "Admin",
		Password: "correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCode(enrollment.Secret, service.now())
	if err != nil {
		t.Fatal(err)
	}
	user, recoveryCodes, err := service.CompleteBootstrap(enrollment.Token, code)
	if err != nil {
		t.Fatal(err)
	}
	for range loginFailureThreshold {
		_, _, _ = service.AuthenticateLocal(user.Email, "definitely the wrong password", "000000", "127.0.0.9", "test")
	}
	_, _, err = service.AuthenticateLocal(user.Email, "correct horse battery staple", recoveryCodes[0], "127.0.0.9", "test")
	if !errors.Is(err, ErrLoginRateLimited) {
		t.Fatalf("expected rate limit, got %v", err)
	}
}

func TestSessionInventoryAndRevokeOthers(t *testing.T) {
	service, _ := testService(t)
	user := completeTestBootstrap(t, service, BootstrapRequest{Email: "admin@example.com", DisplayName: "Admin",
		Password: "correct horse battery staple"})
	now := service.now()
	current, err := service.CreateSession(user, "127.0.0.1", "current", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateSession(user, "127.0.0.2", "other", now); err != nil {
		t.Fatal(err)
	}
	sessions, err := service.Sessions(user.ID, current)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 2 {
		t.Fatalf("session count = %d, want 2", len(sessions))
	}
	if err := service.RevokeOtherSessions(user, current, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	sessions, err = service.Sessions(user.ID, current)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || !sessions[0].Current {
		t.Fatalf("unexpected remaining sessions: %#v", sessions)
	}
}

func completeTestBootstrap(t *testing.T, service *Service, request BootstrapRequest) model.User {
	t.Helper()
	enrollment, err := service.BeginBootstrap(request)
	if err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCode(enrollment.Secret, service.now())
	if err != nil {
		t.Fatal(err)
	}
	user, recoveryCodes, err := service.CompleteBootstrap(enrollment.Token, code)
	if err != nil {
		t.Fatal(err)
	}
	if len(recoveryCodes) != recoveryCodeCount {
		t.Fatalf("recovery code count = %d", len(recoveryCodes))
	}
	return user
}
