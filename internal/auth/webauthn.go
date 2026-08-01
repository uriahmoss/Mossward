package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
	"mossward/internal/model"
	"mossward/internal/store"
)

const webAuthnCeremonyLifetime = 5 * time.Minute

var ErrWebAuthnCeremonyExpired = errors.New("WebAuthn ceremony expired or was already used")

type WebAuthnManager struct {
	relyingParty *wa.WebAuthn
}

type NamedWebAuthnCredential struct {
	Name       string
	Credential wa.Credential
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

type webAuthnUser struct {
	user        model.User
	credentials []wa.Credential
}

func (u webAuthnUser) WebAuthnID() []byte                   { return []byte(u.user.ID) }
func (u webAuthnUser) WebAuthnName() string                 { return u.user.Email }
func (u webAuthnUser) WebAuthnDisplayName() string          { return u.user.DisplayName }
func (u webAuthnUser) WebAuthnCredentials() []wa.Credential { return u.credentials }

func (s *Service) BeginWebAuthnRegistration(user model.User) (*protocol.CredentialCreation, string, error) {
	credentials, err := s.WebAuthnCredentials(user.ID)
	if err != nil {
		return nil, "", err
	}
	waCredentials := make([]wa.Credential, 0, len(credentials))
	for _, credential := range credentials {
		waCredentials = append(waCredentials, credential.Credential)
	}
	creation, session, err := s.webauthn.relyingParty.BeginRegistration(
		webAuthnUser{user: user, credentials: waCredentials}, wa.WithExclusions(credentialDescriptors(waCredentials)))
	if err != nil {
		return nil, "", fmt.Errorf("begin WebAuthn registration: %w", err)
	}
	token, err := s.BeginWebAuthnCeremony(user.ID, model.CeremonyWebAuthnRegister, session)
	return creation, token, err
}

func (s *Service) FinishWebAuthnRegistration(user model.User, token, name string, request *http.Request) error {
	session, ceremonyUserID, err := s.ConsumeWebAuthnCeremony(token, model.CeremonyWebAuthnRegister)
	if err != nil {
		return err
	}
	if ceremonyUserID != user.ID {
		return ErrWebAuthnCeremonyExpired
	}
	credentials, err := s.WebAuthnCredentials(user.ID)
	if err != nil {
		return err
	}
	waCredentials := make([]wa.Credential, 0, len(credentials))
	for _, credential := range credentials {
		waCredentials = append(waCredentials, credential.Credential)
	}
	credential, err := s.webauthn.relyingParty.FinishRegistration(
		webAuthnUser{user: user, credentials: waCredentials}, *session, request)
	if err != nil {
		return fmt.Errorf("finish WebAuthn registration: %w", err)
	}
	return s.StoreWebAuthnCredential(user.ID, name, credential)
}

func (s *Service) RemoveWebAuthnCredential(userID, encodedID string) error {
	id, err := hex.DecodeString(encodedID)
	if err != nil || len(id) == 0 {
		return errors.New("invalid WebAuthn credential identifier")
	}
	removed, err := s.store.DeleteWebAuthnCredential(userID, id)
	if err != nil {
		return err
	}
	if !removed {
		return store.ErrIdentityNotFound
	}
	return nil
}

func (s *Service) BeginWebAuthnLogin(email, password, sourceIP string) (*protocol.CredentialAssertion, string, error) {
	keys := loginThrottleKeys(email, sourceIP)
	blocked, err := s.loginBlocked(keys)
	if err != nil {
		return nil, "", err
	}
	if blocked {
		return nil, "", ErrLoginRateLimited
	}
	user, err := s.VerifyLocalPassword(email, password)
	if err != nil {
		s.recordLoginFailure(keys, sourceIP)
		return nil, "", ErrInvalidCredentials
	}
	credentials, err := s.webAuthnUser(user)
	if err != nil || len(credentials.credentials) == 0 {
		s.recordLoginFailure(keys, sourceIP)
		return nil, "", ErrInvalidCredentials
	}
	assertion, session, err := s.webauthn.relyingParty.BeginLogin(credentials)
	if err != nil {
		return nil, "", fmt.Errorf("begin WebAuthn login: %w", err)
	}
	token, err := s.BeginWebAuthnCeremony(user.ID, model.CeremonyWebAuthnLogin, session)
	return assertion, token, err
}

func (s *Service) FinishWebAuthnLogin(ceremonyToken, sourceIP, userAgent string, request *http.Request) (model.User, string, error) {
	session, userID, err := s.ConsumeWebAuthnCeremony(ceremonyToken, model.CeremonyWebAuthnLogin)
	if err != nil {
		return model.User{}, "", err
	}
	identity, err := s.store.LocalIdentityByID(userID)
	if err != nil || identity.User.Status != model.UserActive {
		return model.User{}, "", ErrInvalidCredentials
	}
	user, err := s.webAuthnUser(identity.User)
	if err != nil {
		return model.User{}, "", err
	}
	credential, err := s.webauthn.relyingParty.FinishLogin(user, *session, request)
	if err != nil {
		s.recordLoginFailure(loginThrottleKeys(identity.User.Email, sourceIP), sourceIP)
		return model.User{}, "", ErrInvalidCredentials
	}
	if err := s.updateWebAuthnCredential(identity.User.ID, credential); err != nil {
		return model.User{}, "", err
	}
	keys := loginThrottleKeys(identity.User.Email, sourceIP)
	if err := s.store.ClearLoginFailures(keys...); err != nil {
		return model.User{}, "", err
	}
	token, err := s.CreateSession(identity.User, sourceIP, userAgent, s.now())
	return identity.User, token, err
}

func (s *Service) webAuthnUser(user model.User) (webAuthnUser, error) {
	named, err := s.WebAuthnCredentials(user.ID)
	if err != nil {
		return webAuthnUser{}, err
	}
	credentials := make([]wa.Credential, 0, len(named))
	for _, credential := range named {
		credentials = append(credentials, credential.Credential)
	}
	return webAuthnUser{user: user, credentials: credentials}, nil
}

func (s *Service) updateWebAuthnCredential(userID string, credential *wa.Credential) error {
	encoded, err := json.Marshal(credential)
	if err != nil {
		return fmt.Errorf("encode updated WebAuthn credential: %w", err)
	}
	ciphertext, err := s.secrets.Encrypt(encoded)
	if err != nil {
		return fmt.Errorf("encrypt updated WebAuthn credential: %w", err)
	}
	now := s.now()
	return s.store.UpdateWebAuthnCredential(model.WebAuthnCredential{ID: credential.ID, UserID: userID,
		CredentialCiphertext: ciphertext, LastUsedAt: &now, SignCount: credential.Authenticator.SignCount,
		BackupEligible: credential.Flags.BackupEligible, BackupState: credential.Flags.BackupState})
}

func credentialDescriptors(credentials []wa.Credential) []protocol.CredentialDescriptor {
	descriptors := make([]protocol.CredentialDescriptor, 0, len(credentials))
	for _, credential := range credentials {
		descriptors = append(descriptors, credential.Descriptor())
	}
	return descriptors
}

func (s *Service) StoreWebAuthnCredential(userID, name string, credential *wa.Credential) error {
	name = strings.TrimSpace(name)
	if userID == "" || name == "" || credential == nil || len(credential.ID) == 0 {
		return errors.New("user, credential name, and credential are required")
	}
	encoded, err := json.Marshal(credential)
	if err != nil {
		return fmt.Errorf("encode WebAuthn credential: %w", err)
	}
	ciphertext, err := s.secrets.Encrypt(encoded)
	if err != nil {
		return fmt.Errorf("encrypt WebAuthn credential: %w", err)
	}
	return s.store.CreateWebAuthnCredential(model.WebAuthnCredential{
		ID: credential.ID, UserID: userID, Name: name,
		CredentialCiphertext: ciphertext, CreatedAt: s.now(),
	})
}

func (s *Service) WebAuthnCredentials(userID string) ([]NamedWebAuthnCredential, error) {
	records, err := s.store.ListWebAuthnCredentials(userID)
	if err != nil {
		return nil, err
	}
	credentials := make([]NamedWebAuthnCredential, 0, len(records))
	for _, record := range records {
		encoded, err := s.secrets.Decrypt(record.CredentialCiphertext)
		if err != nil {
			return nil, fmt.Errorf("decrypt WebAuthn credential: %w", err)
		}
		var credential wa.Credential
		if err := json.Unmarshal(encoded, &credential); err != nil {
			return nil, fmt.Errorf("decode WebAuthn credential: %w", err)
		}
		credentials = append(credentials, NamedWebAuthnCredential{
			Name: record.Name, Credential: credential,
			CreatedAt: record.CreatedAt, LastUsedAt: record.LastUsedAt,
		})
	}
	return credentials, nil
}

func (s *Service) BeginWebAuthnCeremony(userID string, kind model.AuthenticationCeremonyKind, data *wa.SessionData) (string, error) {
	if data == nil || !validWebAuthnCeremonyKind(kind) {
		return "", errors.New("valid WebAuthn ceremony data and kind are required")
	}
	if kind == model.CeremonyWebAuthnRegister && userID == "" {
		return "", errors.New("WebAuthn registration requires a user")
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("encode WebAuthn ceremony: %w", err)
	}
	ciphertext, err := s.secrets.Encrypt(encoded)
	if err != nil {
		return "", fmt.Errorf("encrypt WebAuthn ceremony: %w", err)
	}
	token := make([]byte, sessionTokenBytes)
	if _, err := rand.Read(token); err != nil {
		return "", fmt.Errorf("generate WebAuthn ceremony token: %w", err)
	}
	hash := sha256.Sum256(token)
	now := s.now()
	expiresAt := now.Add(webAuthnCeremonyLifetime)
	if !data.Expires.IsZero() && data.Expires.Before(expiresAt) {
		expiresAt = data.Expires
	}
	ceremony := model.AuthenticationCeremony{IDHash: hash[:], UserID: userID, Kind: kind,
		StateCiphertext: ciphertext, CreatedAt: now, ExpiresAt: expiresAt}
	if err := s.store.CreateAuthenticationCeremony(ceremony); err != nil {
		return "", err
	}
	return hex.EncodeToString(token), nil
}

func (s *Service) ConsumeWebAuthnCeremony(token string, kind model.AuthenticationCeremonyKind) (*wa.SessionData, string, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(token))
	if err != nil || len(raw) != sessionTokenBytes || !validWebAuthnCeremonyKind(kind) {
		return nil, "", ErrWebAuthnCeremonyExpired
	}
	hash := sha256.Sum256(raw)
	ceremony, err := s.store.ConsumeAuthenticationCeremony(hash[:], kind)
	if errors.Is(err, store.ErrCeremonyNotFound) {
		return nil, "", ErrWebAuthnCeremonyExpired
	}
	if err != nil {
		return nil, "", err
	}
	if !s.now().Before(ceremony.ExpiresAt) {
		return nil, "", ErrWebAuthnCeremonyExpired
	}
	encoded, err := s.secrets.Decrypt(ceremony.StateCiphertext)
	if err != nil {
		return nil, "", fmt.Errorf("decrypt WebAuthn ceremony: %w", err)
	}
	var data wa.SessionData
	if err := json.Unmarshal(encoded, &data); err != nil {
		return nil, "", fmt.Errorf("decode WebAuthn ceremony: %w", err)
	}
	return &data, ceremony.UserID, nil
}

func validWebAuthnCeremonyKind(kind model.AuthenticationCeremonyKind) bool {
	return kind == model.CeremonyWebAuthnRegister || kind == model.CeremonyWebAuthnLogin || kind == model.CeremonyOIDC
}

func NewWebAuthnManager(rpID string, origins []string) (*WebAuthnManager, error) {
	relyingParty, err := wa.New(&wa.Config{
		RPID:                   rpID,
		RPDisplayName:          "Mossward",
		RPOrigins:              origins,
		RPAllowCrossOrigin:     false,
		AttestationPreference:  protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{UserVerification: protocol.VerificationRequired},
	})
	if err != nil {
		return nil, fmt.Errorf("initialize WebAuthn relying party: %w", err)
	}
	return &WebAuthnManager{relyingParty: relyingParty}, nil
}
