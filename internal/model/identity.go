package model

import "time"

type UserRole string

const (
	RoleAdministrator UserRole = "administrator"
	RoleAnalyst       UserRole = "analyst"
	RoleViewer        UserRole = "viewer"
)

type UserStatus string

const (
	UserInvited  UserStatus = "invited"
	UserActive   UserStatus = "active"
	UserDisabled UserStatus = "disabled"
)

type IdentityKind string

const (
	IdentityLocal IdentityKind = "local"
	IdentitySSO   IdentityKind = "sso"
)

type ProvisioningMode string

const (
	ProvisionInviteOnly ProvisioningMode = "invite_only"
	ProvisionJIT        ProvisioningMode = "jit"
)

type MFAKind string

const (
	MFATOTP     MFAKind = "totp"
	MFAWebAuthn MFAKind = "webauthn"
)

type User struct {
	ID          string     `json:"id"`
	Email       string     `json:"email"`
	DisplayName string     `json:"display_name"`
	Role        UserRole   `json:"role"`
	Status      UserStatus `json:"status"`
	MFARequired bool       `json:"mfa_required"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
}

type LocalIdentity struct {
	User         User
	PasswordHash string
}

type Invitation struct {
	ID           string       `json:"id"`
	Email        string       `json:"email"`
	Role         UserRole     `json:"role"`
	IdentityKind IdentityKind `json:"identity_kind"`
	InvitedBy    string       `json:"invited_by"`
	ExpiresAt    time.Time    `json:"expires_at"`
	AcceptedAt   *time.Time   `json:"accepted_at,omitempty"`
	CreatedAt    time.Time    `json:"created_at"`
	TokenHash    []byte       `json:"-"`
}

type Session struct {
	PublicID      string
	IDHash        []byte
	UserID        string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	LastSeenAt    time.Time
	MFAVerifiedAt *time.Time
	SourceIP      string
	UserAgentHash []byte
}

type SessionInfo struct {
	ID            string     `json:"id"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
	LastSeenAt    time.Time  `json:"last_seen_at"`
	MFAVerifiedAt *time.Time `json:"mfa_verified_at,omitempty"`
	SourceIP      string     `json:"source_ip"`
	Current       bool       `json:"current"`
}

type BootstrapMFA struct {
	TOTPSecretCiphertext []byte
	RecoveryCodeHashes   [][]byte
}

type WebAuthnCredential struct {
	ID                   []byte
	UserID               string
	Name                 string
	CredentialCiphertext []byte
	CreatedAt            time.Time
	LastUsedAt           *time.Time
	SignCount            uint32
	BackupEligible       bool
	BackupState          bool
}

type AuthenticationCeremonyKind string

const (
	CeremonyWebAuthnRegister AuthenticationCeremonyKind = "webauthn_register"
	CeremonyWebAuthnLogin    AuthenticationCeremonyKind = "webauthn_login"
	CeremonyOIDC             AuthenticationCeremonyKind = "oidc"
)

type OIDCClaims struct {
	UserID   string
	Subject  string
	Email    string
	Name     string
	TenantID string
	Groups   []string
}

type AuthenticationCeremony struct {
	IDHash          []byte
	UserID          string
	Kind            AuthenticationCeremonyKind
	StateCiphertext []byte
	ExpiresAt       time.Time
	CreatedAt       time.Time
}

type OIDCProvider struct {
	ID                  string              `json:"id"`
	Name                string              `json:"name"`
	IssuerURL           string              `json:"issuer_url"`
	ClientID            string              `json:"client_id"`
	ProvisioningMode    ProvisioningMode    `json:"provisioning_mode"`
	AllowedTenantID     string              `json:"allowed_tenant_id,omitempty"`
	AllowedEmailDomains []string            `json:"allowed_email_domains,omitempty"`
	AllowedGroups       []string            `json:"allowed_groups,omitempty"`
	DefaultRole         UserRole            `json:"default_role"`
	Enabled             bool                `json:"enabled"`
	RedirectURL         string              `json:"redirect_url"`
	RoleMappings        map[string]UserRole `json:"role_mappings,omitempty"`
	TestedAt            *time.Time          `json:"tested_at,omitempty"`
	CreatedAt           time.Time           `json:"created_at"`
	UpdatedAt           time.Time           `json:"updated_at"`
}

type OIDCProviderRecord struct {
	Provider               OIDCProvider
	ClientSecretCiphertext []byte
}

type AuditSeverity string

const (
	AuditInfo    AuditSeverity = "info"
	AuditWarning AuditSeverity = "warning"
	AuditError   AuditSeverity = "error"
)

type AuditEvent struct {
	ID         int64         `json:"id"`
	OccurredAt time.Time     `json:"occurred_at"`
	ActorID    string        `json:"actor_id,omitempty"`
	Action     string        `json:"action"`
	Severity   AuditSeverity `json:"severity"`
	TargetType string        `json:"target_type,omitempty"`
	TargetID   string        `json:"target_id,omitempty"`
	SourceIP   string        `json:"source_ip,omitempty"`
	Details    string        `json:"details,omitempty"`
}

type AuthenticationPolicy struct {
	SessionLifetimeMinutes int               `json:"session_lifetime_minutes"`
	AuditRetentionDays     int               `json:"audit_retention_days"`
	MFARequired            map[UserRole]bool `json:"mfa_required"`
}

type AuditQuery struct {
	Text     string
	Severity AuditSeverity
	Limit    int
}
