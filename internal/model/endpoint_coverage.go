package model

import "time"

type EndpointCoverageSettings struct {
	Enabled   bool      `json:"enabled"`
	UpdatedBy string    `json:"updated_by,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

type EndpointCoverageGap struct {
	AssetID           string                 `json:"asset_id"`
	Name              string                 `json:"name"`
	Address           string                 `json:"address"`
	LastSeen          time.Time              `json:"last_seen"`
	Reason            string                 `json:"reason"`
	Eligibility       AgentEligibilityStatus `json:"eligibility"`
	EligibilityReason string                 `json:"eligibility_reason,omitempty"`
}

type EndpointCoverageReport struct {
	Enabled      bool                  `json:"enabled"`
	EvaluatedAt  time.Time             `json:"evaluated_at"`
	Gaps         []EndpointCoverageGap `json:"gaps"`
	Unclassified []EndpointCoverageGap `json:"unclassified"`
}

type CoverageDiscoveryPolicy struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CIDRs     []string  `json:"cidrs"`
	Enabled   bool      `json:"enabled"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedBy string    `json:"updated_by"`
	UpdatedAt time.Time `json:"updated_at"`
}
