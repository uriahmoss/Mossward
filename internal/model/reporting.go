package model

import "time"

type FindingExceptionStatus string

const (
	ExceptionPending  FindingExceptionStatus = "pending"
	ExceptionApproved FindingExceptionStatus = "approved"
	ExceptionRejected FindingExceptionStatus = "rejected"
)

type FindingException struct {
	ID             string                 `json:"id"`
	FindingID      string                 `json:"finding_id"`
	Reason         string                 `json:"reason"`
	Status         FindingExceptionStatus `json:"status"`
	RequestedBy    string                 `json:"requested_by"`
	ApprovedBy     string                 `json:"approved_by,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
	ExpiresAt      *time.Time             `json:"expires_at,omitempty"`
	ReminderDays   int                    `json:"reminder_days"`
	LastReminderAt *time.Time             `json:"last_reminder_at,omitempty"`
}
type EvidenceRetentionSettings struct {
	RetentionDays int       `json:"retention_days"`
	UpdatedAt     time.Time `json:"updated_at"`
}
type ReportingSummary struct {
	GeneratedAt      time.Time             `json:"generated_at"`
	TotalScans       int                   `json:"total_scans"`
	TotalFindings    int                   `json:"total_findings"`
	OpenFindings     int                   `json:"open_findings"`
	ResolvedFindings int                   `json:"resolved_findings"`
	AcceptedRisk     int                   `json:"accepted_risk"`
	Severity         map[string]int        `json:"severity"`
	Trend            []ReportingTrendPoint `json:"trend"`
}
type ReportingTrendPoint struct {
	Date     string `json:"date"`
	Findings int    `json:"findings"`
	Resolved int    `json:"resolved"`
}
