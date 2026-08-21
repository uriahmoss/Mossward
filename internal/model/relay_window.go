package model

import "time"

type RelayUploadWindow struct {
	ID          string                `json:"id"`
	Name        string                `json:"name"`
	TargetType  MaintenanceTargetType `json:"target_type"`
	TargetID    string                `json:"target_id"`
	Timezone    string                `json:"timezone"`
	Days        []time.Weekday        `json:"days"`
	StartMinute int                   `json:"start_minute"`
	EndMinute   int                   `json:"end_minute"`
	Enabled     bool                  `json:"enabled"`
	Reason      string                `json:"reason"`
	CreatedBy   string                `json:"created_by"`
	CreatedAt   time.Time             `json:"created_at"`
	UpdatedBy   string                `json:"updated_by"`
	UpdatedAt   time.Time             `json:"updated_at"`
}
