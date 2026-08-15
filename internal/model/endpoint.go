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
	SoftwareVersion   string          `json:"software_version,omitempty"`
	OperatingSystem   string          `json:"operating_system,omitempty"`
	Architecture      string          `json:"architecture,omitempty"`
	Alerts            []EndpointAlert `json:"alerts"`
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

type AgentCheckInResponse struct {
	Status            string              `json:"status"`
	EndpointID        string              `json:"endpoint_id"`
	ServerTime        time.Time           `json:"server_time"`
	AllowedCollectors []CollectorID       `json:"allowed_collectors"`
	UpdateEnvelope    json.RawMessage     `json:"update_envelope,omitempty"`
	ModuleOffers      []agentmodule.Offer `json:"module_offers,omitempty"`
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
