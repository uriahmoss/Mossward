package auth

import (
	"errors"
	"testing"

	wa "github.com/go-webauthn/webauthn/webauthn"
	"mossward/internal/model"
)

func TestWebAuthnManagerRequiresValidRelyingPartyConfiguration(t *testing.T) {
	if _, err := NewWebAuthnManager("localhost", []string{"http://localhost:8080"}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewWebAuthnManager("", nil); err == nil {
		t.Fatal("expected invalid relying-party configuration to fail")
	}
}

func TestWebAuthnManagerEnforcesOriginAndVerificationPolicy(t *testing.T) {
	manager, err := NewWebAuthnManager("mossward.example", []string{"https://mossward.example"})
	if err != nil {
		t.Fatal(err)
	}
	config := manager.relyingParty.Config
	if config.RPAllowCrossOrigin || len(config.RPOrigins) != 1 || config.RPOrigins[0] != "https://mossward.example" {
		t.Fatalf("unexpected origin policy: %#v", config)
	}
	if config.AuthenticatorSelection.UserVerification != "required" {
		t.Fatalf("user verification policy = %q", config.AuthenticatorSelection.UserVerification)
	}
}

func TestWebAuthnCeremonyKindCannotBeSubstituted(t *testing.T) {
	service, _ := testService(t)
	user := completeTestBootstrap(t, service, BootstrapRequest{Email: "admin@example.com", DisplayName: "Admin",
		Password: "correct horse battery staple"})
	token, err := service.BeginWebAuthnCeremony(user.ID, model.CeremonyWebAuthnRegister,
		&wa.SessionData{Challenge: "challenge", Expires: service.now().Add(webAuthnCeremonyLifetime)})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.ConsumeWebAuthnCeremony(token, model.CeremonyWebAuthnLogin); !errors.Is(err, ErrWebAuthnCeremonyExpired) {
		t.Fatalf("expected ceremony-kind substitution rejection, got %v", err)
	}
	if _, _, err := service.ConsumeWebAuthnCeremony(token, model.CeremonyWebAuthnRegister); err != nil {
		t.Fatalf("kind mismatch should not consume valid ceremony: %v", err)
	}
}

func TestWebAuthnCredentialCiphertextTamperingIsRejected(t *testing.T) {
	service, repository := testService(t)
	user := completeTestBootstrap(t, service, BootstrapRequest{Email: "admin@example.com", DisplayName: "Admin",
		Password: "correct horse battery staple"})
	if err := repository.CreateWebAuthnCredential(model.WebAuthnCredential{ID: []byte("tampered"), UserID: user.ID,
		Name: "Tampered", CredentialCiphertext: []byte("not-authenticated-ciphertext"), CreatedAt: service.now()}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.WebAuthnCredentials(user.ID); err == nil {
		t.Fatal("expected tampered credential ciphertext to be rejected")
	}
}
