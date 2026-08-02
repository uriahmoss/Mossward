package model

import "time"

type ScannerWorker struct {
	ID                 string          `json:"id"`
	Name               string          `json:"name"`
	Status             EndpointStatus  `json:"status"`
	CertificateSerial  string          `json:"certificate_serial"`
	CertificatePEM     string          `json:"-"`
	AllowedCIDRs       []string        `json:"allowed_cidrs"`
	AllowedPorts       []int           `json:"allowed_ports"`
	MaxConcurrent      int             `json:"max_concurrent"`
	RateLimitPerSecond int             `json:"rate_limit_per_second"`
	EnrolledAt         time.Time       `json:"enrolled_at"`
	ExpiresAt          time.Time       `json:"expires_at"`
	LastSeenAt         *time.Time      `json:"last_seen_at,omitempty"`
	RevokedAt          *time.Time      `json:"revoked_at,omitempty"`
	RevocationReason   string          `json:"revocation_reason,omitempty"`
	Alerts             []EndpointAlert `json:"alerts"`
}

type WorkerEnrollmentToken struct {
	ID                 string     `json:"id"`
	Name               string     `json:"name"`
	TokenHash          []byte     `json:"-"`
	AllowedCIDRs       []string   `json:"allowed_cidrs"`
	AllowedPorts       []int      `json:"allowed_ports"`
	MaxConcurrent      int        `json:"max_concurrent"`
	RateLimitPerSecond int        `json:"rate_limit_per_second"`
	CreatedBy          string     `json:"created_by"`
	CreatedAt          time.Time  `json:"created_at"`
	ExpiresAt          time.Time  `json:"expires_at"`
	UsedAt             *time.Time `json:"used_at,omitempty"`
}
