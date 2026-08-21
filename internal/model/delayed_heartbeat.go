package model

import "time"

type DelayedHeartbeatPolicy struct {
	TargetType             MaintenanceTargetType `json:"target_type"`
	TargetID               string                `json:"target_id"`
	AllowDelayedHeartbeats bool                  `json:"allow_delayed_heartbeats"`
	Reason                 string                `json:"reason"`
	UpdatedBy              string                `json:"updated_by"`
	UpdatedAt              time.Time             `json:"updated_at"`
}

type DelayedHeartbeatPolicyRequest struct {
	AllowDelayedHeartbeats bool   `json:"allow_delayed_heartbeats"`
	Reason                 string `json:"reason"`
}

type ResolvedDelayedHeartbeatPolicy struct {
	EndpointID             string   `json:"endpoint_id"`
	AllowDelayedHeartbeats bool     `json:"allow_delayed_heartbeats"`
	Source                 string   `json:"source"`
	SourceIDs              []string `json:"source_ids"`
	Conflict               bool     `json:"conflict"`
}
