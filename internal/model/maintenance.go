package model

import "time"

type MaintenanceTargetType string

const (
	MaintenanceTargetEndpoint MaintenanceTargetType = "endpoint"
	MaintenanceTargetGroup    MaintenanceTargetType = "group"
)

type EndpointMaintenanceWindow struct {
	ID          string                `json:"id"`
	Name        string                `json:"name"`
	TargetType  MaintenanceTargetType `json:"target_type"`
	TargetID    string                `json:"target_id"`
	StartsAt    time.Time             `json:"starts_at"`
	EndsAt      time.Time             `json:"ends_at"`
	Reason      string                `json:"reason"`
	CreatedBy   string                `json:"created_by"`
	CreatedAt   time.Time             `json:"created_at"`
	CancelledBy string                `json:"cancelled_by,omitempty"`
	CancelledAt *time.Time            `json:"cancelled_at,omitempty"`
}
