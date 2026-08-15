package model

import "time"

type Asset struct {
	ID               string                `json:"id"`
	Name             string                `json:"name"`
	Address          string                `json:"address"`
	FirstSeen        time.Time             `json:"first_seen"`
	LastSeen         time.Time             `json:"last_seen"`
	LastScanID       string                `json:"last_scan_id"`
	Names            []string              `json:"names"`
	Addresses        []AssetAddress        `json:"addresses"`
	Owner            string                `json:"owner"`
	Environment      string                `json:"environment"`
	Classification   string                `json:"classification"`
	AgentEligibility AssetAgentEligibility `json:"agent_eligibility"`
	Lifecycle        AssetLifecycle        `json:"lifecycle"`
}

type AgentEligibilityStatus string

const (
	AgentEligibilityUnknown    AgentEligibilityStatus = "unknown"
	AgentEligibilityEligible   AgentEligibilityStatus = "eligible"
	AgentEligibilityIneligible AgentEligibilityStatus = "ineligible"
)

type AssetAgentEligibility struct {
	Status    AgentEligibilityStatus `json:"status"`
	Reason    string                 `json:"reason,omitempty"`
	UpdatedBy string                 `json:"updated_by,omitempty"`
	UpdatedAt *time.Time             `json:"updated_at,omitempty"`
}

type AssetAgentEligibilityUpdate struct {
	Status AgentEligibilityStatus `json:"status"`
	Reason string                 `json:"reason"`
}

type AssetLifecycleStatus string

const (
	AssetActive  AssetLifecycleStatus = "active"
	AssetStale   AssetLifecycleStatus = "stale"
	AssetRetired AssetLifecycleStatus = "retired"
)

type AssetLifecycle struct {
	Status           AssetLifecycleStatus `json:"status"`
	RetiredAt        *time.Time           `json:"retired_at,omitempty"`
	RetiredBy        string               `json:"retired_by,omitempty"`
	RetirementReason string               `json:"retirement_reason,omitempty"`
}

type AssetLifecycleUpdate struct {
	Status AssetLifecycleStatus `json:"status"`
	Reason string               `json:"reason"`
}

type AssetAgingSettings struct {
	StaleAfterDays int `json:"stale_after_days"`
}

type AssetMergeRequest struct {
	SurvivorID         string `json:"survivor_id"`
	MergedID           string `json:"merged_id"`
	NameFrom           string `json:"name_from"`
	AddressFrom        string `json:"address_from"`
	OwnerFrom          string `json:"owner_from"`
	EnvironmentFrom    string `json:"environment_from"`
	ClassificationFrom string `json:"classification_from"`
	LifecycleFrom      string `json:"lifecycle_from"`
}

type AssetMetadata struct {
	Owner          string `json:"owner"`
	Environment    string `json:"environment"`
	Classification string `json:"classification"`
}

type AssetAddress struct {
	Address    string    `json:"address"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	LastScanID string    `json:"last_scan_id"`
}

type AssetDetail struct {
	Asset
	Services []AssetService  `json:"services"`
	Evidence []AssetEvidence `json:"evidence"`
}

type EvidenceSourceType string

const (
	EvidenceSourceScanner  EvidenceSourceType = "scanner"
	EvidenceSourceEndpoint EvidenceSourceType = "endpoint"
)

type EvidenceProvenance struct {
	SourceType  EvidenceSourceType `json:"source_type"`
	SourceID    string             `json:"source_id"`
	RecordType  string             `json:"record_type"`
	RecordID    string             `json:"record_id"`
	CollectedAt time.Time          `json:"collected_at"`
}

type AssetEvidence struct {
	ID      string `json:"id"`
	AssetID string `json:"asset_id"`
	ScanID  string `json:"scan_id,omitempty"`
	Address string `json:"address,omitempty"`
	Summary string `json:"summary"`
	EvidenceProvenance
}

type AssetServiceState string

const (
	AssetServiceObserved    AssetServiceState = "observed"
	AssetServiceNotObserved AssetServiceState = "not_observed"
	AssetServiceStale       AssetServiceState = "stale"
)

type AssetService struct {
	Address          string              `json:"address"`
	Port             int                 `json:"port"`
	Protocol         string              `json:"protocol"`
	Product          string              `json:"product,omitempty"`
	Version          string              `json:"version,omitempty"`
	Confidence       string              `json:"confidence"`
	State            AssetServiceState   `json:"state"`
	FirstSeen        time.Time           `json:"first_seen"`
	LastSeen         time.Time           `json:"last_seen"`
	LastChecked      time.Time           `json:"last_checked"`
	LastScanID       string              `json:"last_scan_id"`
	ObservationCount int                 `json:"observation_count"`
	Events           []AssetServiceEvent `json:"events"`
}
type AssetServiceEvent struct {
	ObservationID string             `json:"observation_id"`
	ScanID        string             `json:"scan_id"`
	Product       string             `json:"product,omitempty"`
	Version       string             `json:"version,omitempty"`
	Confidence    string             `json:"confidence"`
	ObservedAt    time.Time          `json:"observed_at"`
	FindingIDs    []string           `json:"finding_ids"`
	CVEIDs        []string           `json:"cve_ids"`
	Provenance    EvidenceProvenance `json:"provenance"`
}
