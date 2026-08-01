package model

import "time"

type AssetGroup struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Description   string    `json:"description"`
	AssetIDs      []string  `json:"asset_ids"`
	ScanPolicyIDs []string  `json:"scan_policy_ids"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type ReusableScanPolicy struct {
	ID                  string     `json:"id"`
	Name                string     `json:"name"`
	ScopePolicyID       string     `json:"scope_policy_id"`
	GroupIDs            []string   `json:"group_ids"`
	Ports               []int      `json:"ports"`
	Enabled             bool       `json:"enabled"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
	ScheduleKind        string     `json:"schedule_kind"`
	ScheduleExpression  string     `json:"schedule_expression"`
	ScheduleTimezone    string     `json:"schedule_timezone"`
	WindowStart         string     `json:"window_start"`
	WindowEnd           string     `json:"window_end"`
	RunMissed           bool       `json:"run_missed"`
	LongRunAlertSeconds int64      `json:"long_run_alert_seconds"`
	NextRunAt           *time.Time `json:"next_run_at,omitempty"`
	LastScheduledAt     *time.Time `json:"last_scheduled_at,omitempty"`
}

type GroupOverlap struct {
	AssetID  string   `json:"asset_id"`
	GroupIDs []string `json:"existing_group_ids"`
}
