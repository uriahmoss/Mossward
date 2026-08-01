package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"mossward/internal/model"
	"mossward/internal/store"
)

const invitationLifetime = 72 * time.Hour

type InvitationResult struct {
	Invitation model.Invitation `json:"invitation"`
	Token      string           `json:"token"`
}

type pendingInvitation struct {
	invitation  model.Invitation
	displayName string
	password    string
	secret      string
	expiresAt   time.Time
}

func (s *Service) BeginLocalInvitation(token, displayName, password string) (BootstrapEnrollment, error) {
	rawToken, err := hex.DecodeString(strings.TrimSpace(token))
	if err != nil || len(rawToken) != sessionTokenBytes {
		return BootstrapEnrollment{}, store.ErrIdentityNotFound
	}
	hash := sha256.Sum256(rawToken)
	invitation, err := s.store.InvitationByTokenHash(hash[:], s.now())
	if err != nil || invitation.IdentityKind != model.IdentityLocal {
		return BootstrapEnrollment{}, store.ErrIdentityNotFound
	}
	displayName = strings.TrimSpace(displayName)
	if displayName == "" {
		return BootstrapEnrollment{}, errors.New("display name is required")
	}
	if _, err := HashPassword(password); err != nil {
		return BootstrapEnrollment{}, err
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "Mossward", AccountName: invitation.Email})
	if err != nil {
		return BootstrapEnrollment{}, err
	}
	pendingToken, err := randomHex(sessionTokenBytes)
	if err != nil {
		return BootstrapEnrollment{}, err
	}
	expiresAt := s.now().Add(bootstrapLifetime)
	s.pendingMu.Lock()
	s.pendingInvites[pendingToken] = pendingInvitation{invitation: invitation, displayName: displayName,
		password: password, secret: key.Secret(), expiresAt: expiresAt}
	s.pendingMu.Unlock()
	return BootstrapEnrollment{Token: pendingToken, Secret: key.Secret(), OTPAuthURL: key.URL(), ExpiresAt: expiresAt}, nil
}

func (s *Service) CompleteLocalInvitation(token, passcode, sourceIP string) (model.User, []string, error) {
	s.pendingMu.Lock()
	pending, ok := s.pendingInvites[token]
	delete(s.pendingInvites, token)
	s.pendingMu.Unlock()
	if !ok || !s.now().Before(pending.expiresAt) {
		return model.User{}, nil, errors.New("invitation enrollment expired")
	}
	valid, err := totp.ValidateCustom(strings.TrimSpace(passcode), pending.secret, s.now(), totp.ValidateOpts{
		Period: totpPeriodSeconds, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil || !valid {
		return model.User{}, nil, errors.New("invalid authenticator code")
	}
	passwordHash, err := HashPassword(pending.password)
	if err != nil {
		return model.User{}, nil, err
	}
	userID, err := randomHex(identifierBytes)
	if err != nil {
		return model.User{}, nil, err
	}
	secret, err := s.secrets.Encrypt([]byte(pending.secret))
	if err != nil {
		return model.User{}, nil, err
	}
	codes, hashes, err := generateRecoveryCodes()
	if err != nil {
		return model.User{}, nil, err
	}
	now := s.now()
	user := model.User{ID: userID, Email: pending.invitation.Email, DisplayName: pending.displayName,
		Role: pending.invitation.Role, Status: model.UserActive, MFARequired: true, CreatedAt: now, UpdatedAt: now}
	event := model.AuditEvent{OccurredAt: now, ActorID: user.ID, Action: "identity.invitation.accepted",
		Severity: model.AuditInfo, TargetType: "user", TargetID: user.ID, SourceIP: sourceIP, Details: "{}"}
	mfa := model.BootstrapMFA{TOTPSecretCiphertext: secret, RecoveryCodeHashes: hashes}
	if err := s.store.AcceptLocalInvitation(pending.invitation, user, passwordHash, mfa, now, event); err != nil {
		return model.User{}, nil, err
	}
	return user, codes, nil
}

func (s *Service) Users() ([]model.User, error) {
	return s.store.ListUsers()
}

func (s *Service) Invitations() ([]model.Invitation, error) {
	return s.store.ListInvitations(s.now())
}

func (s *Service) InviteUser(actor model.User, email string, role model.UserRole, kind model.IdentityKind, sourceIP string) (InvitationResult, error) {
	normalizedEmail, err := validEmail(email)
	if err != nil {
		return InvitationResult{}, err
	}
	if !validRole(role) || !validIdentityKind(kind) {
		return InvitationResult{}, errors.New("valid role and identity kind are required")
	}
	tokenBytes := make([]byte, sessionTokenBytes)
	if _, err := rand.Read(tokenBytes); err != nil {
		return InvitationResult{}, err
	}
	id, err := randomHex(identifierBytes)
	if err != nil {
		return InvitationResult{}, err
	}
	hash := sha256.Sum256(tokenBytes)
	now := s.now()
	invitation := model.Invitation{ID: id, Email: normalizedEmail, Role: role, IdentityKind: kind,
		InvitedBy: actor.ID, ExpiresAt: now.Add(invitationLifetime), CreatedAt: now, TokenHash: hash[:]}
	event := model.AuditEvent{OccurredAt: now, ActorID: actor.ID, Action: "identity.invitation.created",
		Severity: model.AuditInfo, TargetType: "invitation", TargetID: id, SourceIP: sourceIP,
		Details: jsonObject(map[string]any{"email": normalizedEmail, "role": role, "identity_kind": kind})}
	if err := s.store.CreateInvitation(invitation, event); err != nil {
		return InvitationResult{}, err
	}
	return InvitationResult{Invitation: invitation, Token: hex.EncodeToString(tokenBytes)}, nil
}

func (s *Service) UpdateUserAccess(actor model.User, userID string, role model.UserRole, status model.UserStatus, sourceIP string) error {
	if !validRole(role) || (status != model.UserActive && status != model.UserDisabled) {
		return errors.New("valid role and account status are required")
	}
	now := s.now()
	event := model.AuditEvent{OccurredAt: now, ActorID: actor.ID, Action: "identity.user.access_updated",
		Severity: model.AuditWarning, TargetType: "user", TargetID: userID, SourceIP: sourceIP,
		Details: jsonObject(map[string]any{"role": role, "status": status})}
	return s.store.UpdateUserAccess(userID, role, status, now, event)
}

func validRole(role model.UserRole) bool {
	return role == model.RoleAdministrator || role == model.RoleAnalyst || role == model.RoleViewer
}

func validIdentityKind(kind model.IdentityKind) bool {
	return kind == model.IdentityLocal || kind == model.IdentitySSO
}
