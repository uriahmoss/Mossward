package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"strings"
	"sync"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"mossward/internal/model"
	"mossward/internal/store"
)

const (
	identifierBytes       = 16
	sessionTokenBytes     = 32
	recentMFALifetime     = 10 * time.Minute
	bootstrapLifetime     = 10 * time.Minute
	recoveryCodeCount     = 10
	recoveryCodeBytes     = 10
	totpPeriodSeconds     = 30
	loginFailureWindow    = 15 * time.Minute
	loginFailureThreshold = 5
	loginBaseBlock        = time.Minute
	loginMaximumBlock     = 15 * time.Minute
)

var ErrInvalidCredentials = errors.New("invalid email or password")
var ErrLoginRateLimited = errors.New("too many login attempts; try again later")

type IdentityStore interface {
	IdentityInitialized() (bool, error)
	BootstrapAdministrator(model.User, string, model.BootstrapMFA, model.AuditEvent) error
	LocalIdentityByEmail(string) (model.LocalIdentity, error)
	LocalIdentityByID(string) (model.LocalIdentity, error)
	CreateSession(model.Session, model.AuditEvent) error
	SessionUser([]byte, time.Time) (model.User, error)
	DeleteSession([]byte, model.AuditEvent) error
	TOTPSecret(string) ([]byte, int64, error)
	ConsumeTOTPCounter(string, int64) (bool, error)
	ConsumeRecoveryCode(string, []byte, time.Time, model.AuditEvent) (bool, error)
	LoginThrottle([]byte, time.Time) (time.Time, bool, error)
	RecordLoginFailure([]byte, time.Time, time.Duration, int, time.Duration, time.Duration) (time.Time, error)
	ClearLoginFailures(...[]byte) error
	AppendAuditEvent(model.AuditEvent) error
	ListUserSessions(string, []byte, time.Time) ([]model.SessionInfo, error)
	RevokeUserSession(string, string, model.AuditEvent) error
	RevokeOtherUserSessions(string, []byte, model.AuditEvent) error
	CreateWebAuthnCredential(model.WebAuthnCredential) error
	ListWebAuthnCredentials(string) ([]model.WebAuthnCredential, error)
	CreateAuthenticationCeremony(model.AuthenticationCeremony) error
	ConsumeAuthenticationCeremony([]byte, model.AuthenticationCeremonyKind) (model.AuthenticationCeremony, error)
	SessionMFAVerifiedAt([]byte, string, time.Time) (*time.Time, error)
	UpdateSessionMFAVerifiedAt([]byte, string, time.Time) error
	DeleteWebAuthnCredential(string, []byte) (bool, error)
	UpdateWebAuthnCredential(model.WebAuthnCredential) error
	ListUsers() ([]model.User, error)
	UpdateUserAccess(string, model.UserRole, model.UserStatus, time.Time, model.AuditEvent) error
	CreateInvitation(model.Invitation, model.AuditEvent) error
	ListInvitations(time.Time) ([]model.Invitation, error)
	InvitationByTokenHash([]byte, time.Time) (model.Invitation, error)
	AcceptLocalInvitation(model.Invitation, model.User, string, model.BootstrapMFA, time.Time, model.AuditEvent) error
	UpsertOIDCProvider(model.OIDCProviderRecord, model.AuditEvent) error
	ListOIDCProviders() ([]model.OIDCProviderRecord, error)
	OIDCProvider(string) (model.OIDCProviderRecord, error)
	MarkOIDCProviderTested(string, time.Time, model.AuditEvent) error
	SetOIDCProviderEnabled(string, bool, time.Time, model.AuditEvent) error
	ResolveOIDCUser(model.OIDCProvider, model.OIDCClaims, model.UserRole, time.Time, model.AuditEvent) (model.User, error)
	AuthenticationPolicy() (model.AuthenticationPolicy, error)
	SaveAuthenticationPolicy(model.AuthenticationPolicy, time.Time, model.AuditEvent) error
	ListAuditEvents(model.AuditQuery) ([]model.AuditEvent, error)
}

func (s *Service) HasRecentMFA(userID, token string) (bool, error) {
	hash, err := sessionTokenHash(token)
	if err != nil {
		return false, store.ErrIdentityNotFound
	}
	verifiedAt, err := s.store.SessionMFAVerifiedAt(hash, userID, s.now())
	if err != nil || verifiedAt == nil {
		return false, err
	}
	return s.now().Sub(*verifiedAt) <= recentMFALifetime, nil
}

func (s *Service) RefreshMFA(user model.User, token, code, sourceIP string) error {
	verifiedAt, err := s.verifySecondFactor(user.ID, code, sourceIP)
	if err != nil {
		return ErrInvalidCredentials
	}
	hash, err := sessionTokenHash(token)
	if err != nil {
		return store.ErrIdentityNotFound
	}
	return s.store.UpdateSessionMFAVerifiedAt(hash, user.ID, verifiedAt)
}

type Service struct {
	store             IdentityStore
	now               func() time.Time
	secrets           *SecretBox
	pendingMu         sync.Mutex
	pending           map[string]pendingBootstrap
	pendingInvites    map[string]pendingInvitation
	dummyPasswordHash string
	webauthn          *WebAuthnManager
}

type BootstrapRequest struct {
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
	SourceIP    string `json:"-"`
}

type BootstrapEnrollment struct {
	Token      string    `json:"token"`
	Secret     string    `json:"secret"`
	OTPAuthURL string    `json:"otpauth_url"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type pendingBootstrap struct {
	request   BootstrapRequest
	secret    string
	expiresAt time.Time
}

func NewService(identityStore IdentityStore, secrets *SecretBox, webauthn *WebAuthnManager) (*Service, error) {
	dummyHash, err := HashPassword("Mossward timing equalization value")
	if err != nil {
		return nil, fmt.Errorf("initialize password verifier: %w", err)
	}
	return &Service{store: identityStore, secrets: secrets, pending: make(map[string]pendingBootstrap), pendingInvites: make(map[string]pendingInvitation),
		dummyPasswordHash: dummyHash, webauthn: webauthn, now: func() time.Time { return time.Now().UTC() }}, nil
}

func (s *Service) Initialized() (bool, error) { return s.store.IdentityInitialized() }

func (s *Service) BeginBootstrap(request BootstrapRequest) (BootstrapEnrollment, error) {
	initialized, err := s.store.IdentityInitialized()
	if err != nil {
		return BootstrapEnrollment{}, err
	}
	if initialized {
		return BootstrapEnrollment{}, store.ErrAlreadyInitialized
	}
	email, err := validEmail(request.Email)
	if err != nil {
		return BootstrapEnrollment{}, err
	}
	displayName := strings.TrimSpace(request.DisplayName)
	if displayName == "" {
		return BootstrapEnrollment{}, errors.New("display name is required")
	}
	if _, err := HashPassword(request.Password); err != nil {
		return BootstrapEnrollment{}, err
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "Mossward", AccountName: email})
	if err != nil {
		return BootstrapEnrollment{}, fmt.Errorf("generate TOTP enrollment: %w", err)
	}
	token, err := randomHex(sessionTokenBytes)
	if err != nil {
		return BootstrapEnrollment{}, err
	}
	expiresAt := s.now().Add(bootstrapLifetime)
	request.Email, request.DisplayName = email, displayName
	s.pendingMu.Lock()
	s.pending = map[string]pendingBootstrap{token: {request: request, secret: key.Secret(), expiresAt: expiresAt}}
	s.pendingMu.Unlock()
	return BootstrapEnrollment{Token: token, Secret: key.Secret(), OTPAuthURL: key.URL(), ExpiresAt: expiresAt}, nil
}

func (s *Service) CompleteBootstrap(token, passcode string) (model.User, []string, error) {
	pending, err := s.takePendingBootstrap(token)
	if err != nil {
		return model.User{}, nil, err
	}
	valid, err := totp.ValidateCustom(strings.TrimSpace(passcode), pending.secret, s.now(), totp.ValidateOpts{
		Period: totpPeriodSeconds, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil || !valid {
		return model.User{}, nil, errors.New("invalid authenticator code")
	}
	passwordHash, err := HashPassword(pending.request.Password)
	if err != nil {
		return model.User{}, nil, err
	}
	userID, err := randomHex(identifierBytes)
	if err != nil {
		return model.User{}, nil, err
	}
	encryptedSecret, err := s.secrets.Encrypt([]byte(pending.secret))
	if err != nil {
		return model.User{}, nil, err
	}
	recoveryCodes, recoveryHashes, err := generateRecoveryCodes()
	if err != nil {
		return model.User{}, nil, err
	}
	now := s.now()
	user := model.User{ID: userID, Email: pending.request.Email, DisplayName: pending.request.DisplayName, Role: model.RoleAdministrator,
		Status: model.UserActive, MFARequired: true, CreatedAt: now, UpdatedAt: now}
	event := model.AuditEvent{OccurredAt: now, ActorID: user.ID, Action: "identity.bootstrap.completed",
		Severity: model.AuditInfo, TargetType: "user", TargetID: user.ID, SourceIP: pending.request.SourceIP,
		Details: jsonObject(map[string]any{"authentication": "local", "role": user.Role})}
	mfa := model.BootstrapMFA{TOTPSecretCiphertext: encryptedSecret, RecoveryCodeHashes: recoveryHashes}
	if err := s.store.BootstrapAdministrator(user, passwordHash, mfa, event); err != nil {
		return model.User{}, nil, err
	}
	return user, recoveryCodes, nil
}

func (s *Service) takePendingBootstrap(token string) (pendingBootstrap, error) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	pending, ok := s.pending[token]
	delete(s.pending, token)
	if !ok || !s.now().Before(pending.expiresAt) {
		return pendingBootstrap{}, errors.New("bootstrap enrollment expired")
	}
	return pending, nil
}

func generateRecoveryCodes() ([]string, [][]byte, error) {
	codes := make([]string, 0, recoveryCodeCount)
	hashes := make([][]byte, 0, recoveryCodeCount)
	for range recoveryCodeCount {
		code, err := randomHex(recoveryCodeBytes)
		if err != nil {
			return nil, nil, err
		}
		display := code[:10] + "-" + code[10:]
		hash := sha256.Sum256([]byte(display))
		codes, hashes = append(codes, display), append(hashes, hash[:])
	}
	return codes, hashes, nil
}

func (s *Service) VerifyLocalPassword(email, password string) (model.User, error) {
	identity, err := s.store.LocalIdentityByEmail(email)
	if errors.Is(err, store.ErrIdentityNotFound) {
		_, _ = VerifyPassword(s.dummyPasswordHash, password)
		return model.User{}, ErrInvalidCredentials
	}
	if err != nil {
		return model.User{}, err
	}
	if identity.User.Status != model.UserActive || identity.PasswordHash == "" {
		return model.User{}, ErrInvalidCredentials
	}
	valid, err := VerifyPassword(identity.PasswordHash, password)
	if err != nil {
		return model.User{}, fmt.Errorf("verify stored password: %w", err)
	}
	if !valid {
		return model.User{}, ErrInvalidCredentials
	}
	return identity.User, nil
}

func (s *Service) AuthenticateLocal(email, password, passcode, sourceIP, userAgent string) (model.User, string, error) {
	keys := loginThrottleKeys(email, sourceIP)
	blocked, err := s.loginBlocked(keys)
	if err != nil {
		return model.User{}, "", err
	}
	if blocked {
		return model.User{}, "", ErrLoginRateLimited
	}
	user, err := s.VerifyLocalPassword(email, password)
	if err != nil {
		s.recordLoginFailure(keys, sourceIP)
		return model.User{}, "", err
	}
	policy, err := s.store.AuthenticationPolicy()
	if err != nil {
		return model.User{}, "", err
	}
	var verifiedAt time.Time
	if policy.MFARequired[user.Role] {
		verifiedAt, err = s.verifySecondFactor(user.ID, passcode, sourceIP)
		if err != nil {
			s.recordLoginFailure(keys, sourceIP)
			return model.User{}, "", ErrInvalidCredentials
		}
	}
	if err := s.store.ClearLoginFailures(keys...); err != nil {
		return model.User{}, "", err
	}
	token, err := s.CreateSession(user, sourceIP, userAgent, verifiedAt)
	if err != nil {
		return model.User{}, "", err
	}
	return user, token, nil
}

func (s *Service) loginBlocked(keys [][]byte) (bool, error) {
	for _, key := range keys {
		_, blocked, err := s.store.LoginThrottle(key, s.now())
		if err != nil {
			return false, err
		}
		if blocked {
			return true, nil
		}
	}
	return false, nil
}

func (s *Service) recordLoginFailure(keys [][]byte, sourceIP string) {
	now := s.now()
	for _, key := range keys {
		if _, err := s.store.RecordLoginFailure(key, now, loginFailureWindow, loginFailureThreshold, loginBaseBlock, loginMaximumBlock); err != nil {
			slog.Warn("Could not update login throttle", "error", err)
		}
	}
	if err := s.store.AppendAuditEvent(model.AuditEvent{OccurredAt: now, Action: "identity.login.failed",
		Severity: model.AuditWarning, TargetType: "authentication", SourceIP: sourceIP,
		Details: jsonObject(map[string]any{"reason": "invalid_credentials"})}); err != nil {
		slog.Warn("Could not record failed login audit event", "error", err)
	}
}

func loginThrottleKeys(email, sourceIP string) [][]byte {
	account := sha256.Sum256([]byte("account:" + strings.ToLower(strings.TrimSpace(email))))
	source := sha256.Sum256([]byte("source:" + sourceIP))
	return [][]byte{account[:], source[:]}
}

func (s *Service) verifySecondFactor(userID, value, sourceIP string) (time.Time, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	if strings.Contains(value, "-") {
		return s.verifyRecoveryCode(userID, value, sourceIP)
	}
	return s.verifyTOTP(userID, value)
}

func (s *Service) verifyRecoveryCode(userID, code, sourceIP string) (time.Time, error) {
	now := s.now()
	hash := sha256.Sum256([]byte(code))
	event := model.AuditEvent{OccurredAt: now, ActorID: userID, Action: "identity.recovery_code.used",
		Severity: model.AuditWarning, TargetType: "user", TargetID: userID, SourceIP: sourceIP,
		Details: jsonObject(map[string]any{"remaining_action": "review account MFA methods"})}
	used, err := s.store.ConsumeRecoveryCode(userID, hash[:], now, event)
	if err != nil {
		return time.Time{}, err
	}
	if !used {
		return time.Time{}, errors.New("invalid recovery code")
	}
	return now, nil
}

func (s *Service) verifyTOTP(userID, passcode string) (time.Time, error) {
	ciphertext, _, err := s.store.TOTPSecret(userID)
	if err != nil {
		return time.Time{}, err
	}
	secret, err := s.secrets.Decrypt(ciphertext)
	if err != nil {
		return time.Time{}, err
	}
	now := s.now()
	counter, valid := matchingTOTPCounter(string(secret), strings.TrimSpace(passcode), now)
	if !valid {
		return time.Time{}, errors.New("invalid authenticator code")
	}
	consumed, err := s.store.ConsumeTOTPCounter(userID, counter)
	if err != nil {
		return time.Time{}, err
	}
	if !consumed {
		return time.Time{}, errors.New("authenticator code was already used")
	}
	return now, nil
}

func matchingTOTPCounter(secret, passcode string, now time.Time) (int64, bool) {
	for offset := -1; offset <= 1; offset++ {
		candidateTime := now.Add(time.Duration(offset*totpPeriodSeconds) * time.Second)
		candidate, err := totp.GenerateCodeCustom(secret, candidateTime, totp.ValidateOpts{
			Period: totpPeriodSeconds, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if err == nil && subtle.ConstantTimeCompare([]byte(candidate), []byte(passcode)) == 1 {
			return candidateTime.Unix() / totpPeriodSeconds, true
		}
	}
	return 0, false
}

func (s *Service) CreateSession(user model.User, sourceIP, userAgent string, mfaVerifiedAt time.Time) (string, error) {
	token := make([]byte, sessionTokenBytes)
	if _, err := rand.Read(token); err != nil {
		return "", fmt.Errorf("generate session token: %w", err)
	}
	now := s.now()
	publicID, err := randomHex(identifierBytes)
	if err != nil {
		return "", err
	}
	tokenHash := sha256.Sum256(token)
	userAgentHash := sha256.Sum256([]byte(userAgent))
	policy, err := s.store.AuthenticationPolicy()
	if err != nil {
		return "", err
	}
	lifetime := time.Duration(policy.SessionLifetimeMinutes) * time.Minute
	var verifiedAt *time.Time
	if !mfaVerifiedAt.IsZero() {
		verifiedAt = &mfaVerifiedAt
	}
	session := model.Session{IDHash: tokenHash[:], PublicID: publicID, UserID: user.ID, CreatedAt: now,
		ExpiresAt: now.Add(lifetime), LastSeenAt: now, MFAVerifiedAt: verifiedAt,
		SourceIP: sourceIP, UserAgentHash: userAgentHash[:]}
	event := model.AuditEvent{OccurredAt: now, ActorID: user.ID, Action: "identity.login.succeeded",
		Severity: model.AuditInfo, TargetType: "session", SourceIP: sourceIP, Details: "{}"}
	if err := s.store.CreateSession(session, event); err != nil {
		return "", err
	}
	return hex.EncodeToString(token), nil
}

func (s *Service) Sessions(userID, currentToken string) ([]model.SessionInfo, error) {
	hash, err := sessionTokenHash(currentToken)
	if err != nil {
		return nil, store.ErrIdentityNotFound
	}
	return s.store.ListUserSessions(userID, hash, s.now())
}

func (s *Service) RevokeSession(user model.User, publicID, sourceIP string) error {
	event := model.AuditEvent{OccurredAt: s.now(), ActorID: user.ID, Action: "identity.session.revoked",
		Severity: model.AuditInfo, TargetType: "session", TargetID: publicID, SourceIP: sourceIP, Details: "{}"}
	return s.store.RevokeUserSession(user.ID, publicID, event)
}

func (s *Service) RevokeOtherSessions(user model.User, currentToken, sourceIP string) error {
	hash, err := sessionTokenHash(currentToken)
	if err != nil {
		return store.ErrIdentityNotFound
	}
	event := model.AuditEvent{OccurredAt: s.now(), ActorID: user.ID, Action: "identity.sessions.revoked_others",
		Severity: model.AuditInfo, TargetType: "user", TargetID: user.ID, SourceIP: sourceIP, Details: "{}"}
	return s.store.RevokeOtherUserSessions(user.ID, hash, event)
}

func (s *Service) SessionUser(token string) (model.User, error) {
	hash, err := sessionTokenHash(token)
	if err != nil {
		return model.User{}, store.ErrIdentityNotFound
	}
	return s.store.SessionUser(hash, s.now())
}

func (s *Service) Logout(token, sourceIP string) error {
	hash, err := sessionTokenHash(token)
	if err != nil {
		return nil
	}
	user, err := s.store.SessionUser(hash, s.now())
	if err != nil {
		return nil
	}
	event := model.AuditEvent{OccurredAt: s.now(), ActorID: user.ID, Action: "identity.logout",
		Severity: model.AuditInfo, TargetType: "session", SourceIP: sourceIP, Details: "{}"}
	return s.store.DeleteSession(hash, event)
}

func validEmail(raw string) (string, error) {
	email := strings.ToLower(strings.TrimSpace(raw))
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email || !strings.Contains(email, "@") {
		return "", errors.New("valid email address is required")
	}
	return email, nil
}

func randomHex(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate identifier: %w", err)
	}
	return hex.EncodeToString(value), nil
}

func sessionTokenHash(token string) ([]byte, error) {
	raw, err := hex.DecodeString(token)
	if err != nil || len(raw) != sessionTokenBytes {
		return nil, errors.New("invalid session token")
	}
	hash := sha256.Sum256(raw)
	return hash[:], nil
}

func jsonObject(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}
