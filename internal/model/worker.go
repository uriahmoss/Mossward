package model

import "time"

type ScannerWorker struct {
	ID                   string             `json:"id"`
	Name                 string             `json:"name"`
	SiteID               string             `json:"site_id,omitempty"`
	Status               EndpointStatus     `json:"status"`
	CertificateSerial    string             `json:"certificate_serial"`
	CertificatePEM       string             `json:"-"`
	AllowedCIDRs         []string           `json:"allowed_cidrs"`
	AllowedPorts         []int              `json:"allowed_ports"`
	MaxConcurrent        int                `json:"max_concurrent"`
	RateLimitPerSecond   int                `json:"rate_limit_per_second"`
	EnrolledAt           time.Time          `json:"enrolled_at"`
	ExpiresAt            time.Time          `json:"expires_at"`
	LastSeenAt           *time.Time         `json:"last_seen_at,omitempty"`
	SoftwareVersion      string             `json:"software_version,omitempty"`
	OperatingSystem      string             `json:"operating_system,omitempty"`
	Architecture         string             `json:"architecture,omitempty"`
	Capabilities         []WorkerCapability `json:"capabilities"`
	AvailableConcurrency int                `json:"available_concurrency"`
	Health               WorkerHealth       `json:"health,omitempty"`
	HealthMessage        string             `json:"health_message,omitempty"`
	RevokedAt            *time.Time         `json:"revoked_at,omitempty"`
	RevocationReason     string             `json:"revocation_reason,omitempty"`
	Alerts               []EndpointAlert    `json:"alerts"`
}

type WorkerCapability string

const (
	WorkerCapabilityTCPConnect            WorkerCapability = "tcp_connect"
	WorkerCapabilityServiceIdentification WorkerCapability = "service_identification"
	WorkerCapabilityHTTP                  WorkerCapability = "http_configuration"
	WorkerCapabilityTLS                   WorkerCapability = "tls_configuration"
	WorkerCapabilitySSH                   WorkerCapability = "ssh_configuration"
)

type WorkerHealth string

const (
	WorkerHealthHealthy  WorkerHealth = "healthy"
	WorkerHealthDegraded WorkerHealth = "degraded"
)

type WorkerHeartbeat struct {
	SchemaVersion        int                `json:"schema_version"`
	SoftwareVersion      string             `json:"software_version"`
	OperatingSystem      string             `json:"operating_system"`
	Architecture         string             `json:"architecture"`
	Capabilities         []WorkerCapability `json:"capabilities"`
	AvailableConcurrency int                `json:"available_concurrency"`
	Health               WorkerHealth       `json:"health"`
	HealthMessage        string             `json:"health_message,omitempty"`
}

type WorkerEnrollmentToken struct {
	ID                 string     `json:"id"`
	Name               string     `json:"name"`
	SiteID             string     `json:"site_id,omitempty"`
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
