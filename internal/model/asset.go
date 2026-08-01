package model

import "time"

type Asset struct {
	ID             string         `json:"id"`
	Name           string         `json:"name"`
	Address        string         `json:"address"`
	FirstSeen      time.Time      `json:"first_seen"`
	LastSeen       time.Time      `json:"last_seen"`
	LastScanID     string         `json:"last_scan_id"`
	Names          []string       `json:"names"`
	Addresses      []AssetAddress `json:"addresses"`
	Owner          string         `json:"owner"`
	Environment    string         `json:"environment"`
	Classification string         `json:"classification"`
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
	Services []AssetService `json:"services"`
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
	ObservationID string    `json:"observation_id"`
	ScanID        string    `json:"scan_id"`
	Product       string    `json:"product,omitempty"`
	Version       string    `json:"version,omitempty"`
	Confidence    string    `json:"confidence"`
	ObservedAt    time.Time `json:"observed_at"`
	FindingIDs    []string  `json:"finding_ids"`
	CVEIDs        []string  `json:"cve_ids"`
}
