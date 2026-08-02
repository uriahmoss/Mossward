package model

import "time"

type WorkerJobStatus string

const (
	WorkerJobPending   WorkerJobStatus = "pending"
	WorkerJobLeased    WorkerJobStatus = "leased"
	WorkerJobCompleted WorkerJobStatus = "completed"
	WorkerJobCanceled  WorkerJobStatus = "canceled"
	WorkerJobExpired   WorkerJobStatus = "expired"
)

type WorkerJob struct {
	SchemaVersion        int                `json:"schema_version"`
	ID                   string             `json:"id"`
	WorkerID             string             `json:"worker_id"`
	ScanID               string             `json:"scan_id"`
	IssuedAt             time.Time          `json:"issued_at"`
	ExpiresAt            time.Time          `json:"expires_at"`
	Targets              []Target           `json:"targets"`
	Ports                []int              `json:"ports"`
	MaxConcurrent        int                `json:"max_concurrent"`
	RateLimitPerSecond   int                `json:"rate_limit_per_second"`
	RequiredCapabilities []WorkerCapability `json:"required_capabilities"`
	Status               WorkerJobStatus    `json:"status"`
}

type SignedWorkerJob struct {
	Algorithm string    `json:"algorithm"`
	KeyID     string    `json:"key_id"`
	Job       WorkerJob `json:"job"`
	Signature string    `json:"signature"`
}

type WorkerJobLease struct {
	Envelope  SignedWorkerJob `json:"envelope"`
	Token     string          `json:"lease_token"`
	ExpiresAt time.Time       `json:"lease_expires_at"`
}
