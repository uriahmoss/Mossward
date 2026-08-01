package model

import "time"

type EndpointStatus string

const (
	EndpointActive  EndpointStatus = "active"
	EndpointRevoked EndpointStatus = "revoked"
)

type Endpoint struct {
	ID                string         `json:"id"`
	Name              string         `json:"name"`
	Status            EndpointStatus `json:"status"`
	CertificateSerial string         `json:"certificate_serial"`
	CertificatePEM    string         `json:"-"`
	EnrolledAt        time.Time      `json:"enrolled_at"`
	ExpiresAt         time.Time      `json:"expires_at"`
	LastSeenAt        *time.Time     `json:"last_seen_at,omitempty"`
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
