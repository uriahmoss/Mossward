package model

import "time"

type EndpointCoverageSettings struct {
	Enabled   bool      `json:"enabled"`
	UpdatedBy string    `json:"updated_by,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

type EndpointCoverageGap struct {
	AssetID        string    `json:"asset_id"`
	Name           string    `json:"name"`
	Address        string    `json:"address"`
	LastSeen       time.Time `json:"last_seen"`
	Reason         string    `json:"reason"`
	Classification string    `json:"classification"`
}

type EndpointCoverageReport struct {
	Enabled     bool                  `json:"enabled"`
	EvaluatedAt time.Time             `json:"evaluated_at"`
	Gaps        []EndpointCoverageGap `json:"gaps"`
}
