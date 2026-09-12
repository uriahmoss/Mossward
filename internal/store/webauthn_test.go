package store

import (
	"reflect"
	"testing"
	"time"

	"mossward/internal/model"
)

func TestWebAuthnCredentialListRetainsAuthenticatorState(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	user := model.User{ID: "webauthn-admin", Email: "admin@example.test", DisplayName: "Admin",
		Role: model.RoleAdministrator, Status: model.UserActive, MFARequired: true, CreatedAt: now, UpdatedAt: now}
	if err := repository.BootstrapAdministrator(user, "password-hash",
		model.BootstrapMFA{TOTPSecretCiphertext: []byte("encrypted-totp")},
		model.AuditEvent{OccurredAt: now, ActorID: user.ID, Action: "identity.bootstrap.completed", Severity: model.AuditInfo}); err != nil {
		t.Fatal(err)
	}
	lastUsed := now.Add(time.Minute)
	credential := model.WebAuthnCredential{ID: []byte("credential-id"), UserID: user.ID, Name: "Security key",
		CredentialCiphertext: []byte("encrypted-credential"), CreatedAt: now, LastUsedAt: &lastUsed,
		SignCount: 9, BackupEligible: true, BackupState: true}
	if err := repository.CreateWebAuthnCredential(credential); err != nil {
		t.Fatal(err)
	}
	if err := repository.UpdateWebAuthnCredential(credential); err != nil {
		t.Fatal(err)
	}
	credentials, err := repository.ListWebAuthnCredentials(user.ID)
	if err != nil || len(credentials) != 1 {
		t.Fatalf("list WebAuthn credentials: %#v %v", credentials, err)
	}
	stored := credentials[0]
	if stored.SignCount != credential.SignCount || stored.BackupEligible != credential.BackupEligible ||
		stored.BackupState != credential.BackupState || stored.LastUsedAt == nil || !stored.LastUsedAt.Equal(lastUsed) ||
		!reflect.DeepEqual(stored.CredentialCiphertext, credential.CredentialCiphertext) {
		t.Fatalf("WebAuthn authenticator state changed: %#v", stored)
	}
}
