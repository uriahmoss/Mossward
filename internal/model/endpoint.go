package model

import (
	"encoding/json"
	"time"

	"mossward/internal/agentmodule"
)

type EndpointStatus string
type CollectorID string

const (
	EndpointActive  EndpointStatus = "active"
	EndpointRevoked EndpointStatus = "revoked"

	CollectorOperatingSystem   CollectorID = "operating_system"
	CollectorInstalledSoftware CollectorID = "installed_software"
	CollectorListeningServices CollectorID = "listening_services"
	CollectorSecurityPosture   CollectorID = "security_posture"
	CollectorNetworkTelemetry  CollectorID = "network_telemetry"
)

type Endpoint struct {
	ID                string                     `json:"id"`
	Name              string                     `json:"name"`
	Status            EndpointStatus             `json:"status"`
	CertificateSerial string                     `json:"certificate_serial"`
	CertificatePEM    string                     `json:"-"`
	EnrolledAt        time.Time                  `json:"enrolled_at"`
	ExpiresAt         time.Time                  `json:"expires_at"`
	LastSeenAt        *time.Time                 `json:"last_seen_at,omitempty"`
	RenewedAt         *time.Time                 `json:"renewed_at,omitempty"`
	RevokedAt         *time.Time                 `json:"revoked_at,omitempty"`
	RevocationReason  string                     `json:"revocation_reason,omitempty"`
	AllowedCollectors []CollectorID              `json:"allowed_collectors"`
	NetworkExclusions NetworkTelemetryExclusions `json:"network_telemetry_exclusions"`
	SoftwareVersion   string                     `json:"software_version,omitempty"`
	OperatingSystem   string                     `json:"operating_system,omitempty"`
	Architecture      string                     `json:"architecture,omitempty"`
	Alerts            []EndpointAlert            `json:"alerts"`
}

type AgentCheckIn struct {
	SchemaVersion       int                         `json:"schema_version"`
	SoftwareVersion     string                      `json:"software_version"`
	OperatingSystem     string                      `json:"operating_system"`
	Architecture        string                      `json:"architecture"`
	SupportedCollectors []CollectorID               `json:"supported_collectors"`
	ModuleHealth        []agentmodule.Health        `json:"module_health,omitempty"`
	OSInventory         *EndpointOSInventory        `json:"os_inventory,omitempty"`
	SoftwareInventory   *EndpointSoftwareInventory  `json:"software_inventory,omitempty"`
	ListeningInventory  *EndpointListeningInventory `json:"listening_inventory,omitempty"`
	PostureInventory    *EndpointPostureInventory   `json:"posture_inventory,omitempty"`
	NetworkInventory    *EndpointNetworkInventory   `json:"network_inventory,omitempty"`
	IntegritySnapshot   *AgentIntegritySnapshot     `json:"integrity_snapshot,omitempty"`
}

type AgentIntegritySnapshot struct {
	ExecutableSHA256    string    `json:"executable_sha256"`
	ConfigurationSHA256 string    `json:"configuration_sha256"`
	IdentitySHA256      string    `json:"identity_sha256"`
	ObservedAt          time.Time `json:"observed_at"`
}

type AgentIntegrityEvent struct {
	ID             int64     `json:"id"`
	EndpointID     string    `json:"endpoint_id"`
	Component      string    `json:"component"`
	PreviousSHA256 string    `json:"previous_sha256"`
	CurrentSHA256  string    `json:"current_sha256"`
	ObservedAt     time.Time `json:"observed_at"`
	ReceivedAt     time.Time `json:"received_at"`
}

type EndpointOSInventory struct {
	EndpointID   string          `json:"endpoint_id,omitempty"`
	Family       string          `json:"family"`
	Name         string          `json:"name"`
	Version      string          `json:"version"`
	Build        string          `json:"build,omitempty"`
	Kernel       string          `json:"kernel"`
	Architecture string          `json:"architecture"`
	Patches      []EndpointPatch `json:"patches"`
	CollectedAt  time.Time       `json:"collected_at"`
	ReceivedAt   time.Time       `json:"received_at,omitempty"`
}

type EndpointPatch struct {
	ID          string     `json:"id"`
	Description string     `json:"description,omitempty"`
	InstalledAt *time.Time `json:"installed_at,omitempty"`
}

type EndpointSoftwareInventory struct {
	EndpointID  string              `json:"endpoint_id,omitempty"`
	Items       []InstalledSoftware `json:"items"`
	CollectedAt time.Time           `json:"collected_at"`
	ReceivedAt  time.Time           `json:"received_at,omitempty"`
}

type InstalledSoftware struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Publisher    string `json:"publisher,omitempty"`
	Architecture string `json:"architecture,omitempty"`
	Source       string `json:"source"`
}

type EndpointListeningInventory struct {
	EndpointID  string             `json:"endpoint_id,omitempty"`
	Services    []ListeningService `json:"services"`
	CollectedAt time.Time          `json:"collected_at"`
	ReceivedAt  time.Time          `json:"received_at,omitempty"`
}

type ListeningService struct {
	Protocol    string `json:"protocol"`
	Address     string `json:"address"`
	Port        int    `json:"port"`
	ProcessID   int    `json:"process_id,omitempty"`
	ProcessName string `json:"process_name,omitempty"`
	Executable  string `json:"executable,omitempty"`
}

type EndpointPostureInventory struct {
	EndpointID  string            `json:"endpoint_id,omitempty"`
	Evidence    []PostureEvidence `json:"evidence"`
	CollectedAt time.Time         `json:"collected_at"`
	ReceivedAt  time.Time         `json:"received_at,omitempty"`
}

type PostureEvidence struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type EndpointCVEMatch struct {
	EndpointID     string    `json:"endpoint_id"`
	CVEID          string    `json:"cve_id"`
	Product        string    `json:"product"`
	Version        string    `json:"version"`
	PackageSource  string    `json:"package_source"`
	Severity       string    `json:"severity"`
	CVSSScore      float64   `json:"cvss_score"`
	Description    string    `json:"description"`
	Confidence     string    `json:"confidence"`
	Evidence       string    `json:"evidence"`
	KnownExploited bool      `json:"known_exploited"`
	SourceURL      string    `json:"source_url"`
	MatchedAt      time.Time `json:"matched_at"`
}

type EndpointNetworkInventory struct {
	EndpointID  string              `json:"endpoint_id,omitempty"`
	Connections []NetworkConnection `json:"connections"`
	CollectedAt time.Time           `json:"collected_at"`
	ReceivedAt  time.Time           `json:"received_at,omitempty"`
}

type NetworkConnection struct {
	Protocol       string `json:"protocol"`
	LocalAddress   string `json:"local_address"`
	LocalPort      int    `json:"local_port"`
	RemoteAddress  string `json:"remote_address"`
	RemotePort     int    `json:"remote_port"`
	ProcessID      int    `json:"process_id,omitempty"`
	ProcessName    string `json:"process_name,omitempty"`
	Executable     string `json:"executable,omitempty"`
	RemoteHostname string `json:"remote_hostname,omitempty"`
	HostnameSource string `json:"hostname_source,omitempty"`
	TLSServerName  string `json:"tls_server_name,omitempty"`
	Direction      string `json:"direction"`
}

type NetworkExclusionKind string

const (
	NetworkExcludeProcessName NetworkExclusionKind = "process_name"
	NetworkExcludeExecutable  NetworkExclusionKind = "executable"
	NetworkExcludeIP          NetworkExclusionKind = "ip"
	NetworkExcludeCIDR        NetworkExclusionKind = "cidr"
	NetworkExcludeHostname    NetworkExclusionKind = "hostname"
)

type NetworkTelemetryExclusion struct {
	Kind  NetworkExclusionKind `json:"kind"`
	Value string               `json:"value"`
}

type NetworkTelemetryExclusions struct {
	Applications []NetworkTelemetryExclusion `json:"applications"`
	Destinations []NetworkTelemetryExclusion `json:"destinations"`
}

type ThreatIndicatorType string

const (
	ThreatIndicatorIP       ThreatIndicatorType = "ip"
	ThreatIndicatorHostname ThreatIndicatorType = "hostname"
)

type ThreatIndicator struct {
	ID         string              `json:"id"`
	Type       ThreatIndicatorType `json:"type"`
	Value      string              `json:"value"`
	Source     string              `json:"source"`
	Confidence string              `json:"confidence"`
	ObservedAt time.Time           `json:"observed_at"`
	ExpiresAt  time.Time           `json:"expires_at"`
	Enabled    bool                `json:"enabled"`
	CreatedBy  string              `json:"created_by"`
	CreatedAt  time.Time           `json:"created_at"`
	UpdatedAt  time.Time           `json:"updated_at"`
}

type EndpointIndicatorMatch struct {
	EndpointID     string              `json:"endpoint_id"`
	IndicatorID    string              `json:"indicator_id"`
	IndicatorType  ThreatIndicatorType `json:"indicator_type"`
	IndicatorValue string              `json:"indicator_value"`
	Source         string              `json:"source"`
	Confidence     string              `json:"confidence"`
	ExpiresAt      time.Time           `json:"expires_at"`
	RemoteAddress  string              `json:"remote_address"`
	RemoteHostname string              `json:"remote_hostname,omitempty"`
	ProcessName    string              `json:"process_name,omitempty"`
	Executable     string              `json:"executable,omitempty"`
	MatchedAt      time.Time           `json:"matched_at"`
}

type AgentCheckInResponse struct {
	Status            string                     `json:"status"`
	EndpointID        string                     `json:"endpoint_id"`
	ServerTime        time.Time                  `json:"server_time"`
	AllowedCollectors []CollectorID              `json:"allowed_collectors"`
	NetworkExclusions NetworkTelemetryExclusions `json:"network_telemetry_exclusions"`
	UpdateEnvelope    json.RawMessage            `json:"update_envelope,omitempty"`
	ModuleOffers      []agentmodule.Offer        `json:"module_offers,omitempty"`
}

type EndpointAlert struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

type EndpointHeartbeatSettings struct {
	Enabled            bool      `json:"enabled"`
	MissedAfterMinutes int       `json:"missed_after_minutes"`
	StaleAfterMinutes  int       `json:"stale_after_minutes"`
	UpdatedBy          string    `json:"updated_by,omitempty"`
	UpdatedAt          time.Time `json:"updated_at,omitempty"`
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
