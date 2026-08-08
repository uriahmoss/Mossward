package model

import "time"

type EndpointStatus string
type CollectorID string

const (
	EndpointActive  EndpointStatus = "active"
	EndpointRevoked EndpointStatus = "revoked"

	CollectorOperatingSystem   CollectorID = "operating_system"
	CollectorInstalledSoftware CollectorID = "installed_software"
	CollectorListeningServices CollectorID = "listening_services"
	CollectorSecurityPosture   CollectorID = "security_posture"
)

type Endpoint struct {
	ID                string          `json:"id"`
	Name              string          `json:"name"`
	Status            EndpointStatus  `json:"status"`
	CertificateSerial string          `json:"certificate_serial"`
	CertificatePEM    string          `json:"-"`
	EnrolledAt        time.Time       `json:"enrolled_at"`
	ExpiresAt         time.Time       `json:"expires_at"`
	LastSeenAt        *time.Time      `json:"last_seen_at,omitempty"`
	RenewedAt         *time.Time      `json:"renewed_at,omitempty"`
	RevokedAt         *time.Time      `json:"revoked_at,omitempty"`
	RevocationReason  string          `json:"revocation_reason,omitempty"`
	AllowedCollectors []CollectorID   `json:"allowed_collectors"`
	Alerts            []EndpointAlert `json:"alerts"`
}

type AgentCheckIn struct {
	SchemaVersion       int           `json:"schema_version"`
	SupportedCollectors []CollectorID `json:"supported_collectors"`
}

type AgentCheckInResponse struct {
	Status            string        `json:"status"`
	EndpointID        string        `json:"endpoint_id"`
	ServerTime        time.Time     `json:"server_time"`
	AllowedCollectors []CollectorID `json:"allowed_collectors"`
}

type EndpointAlert struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

type AgentEnrollmentToken struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	TokenHash []byte     `json:"-"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
}
