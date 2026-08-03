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
	SiteID               string             `json:"site_id,omitempty"`
	IssuedAt             time.Time          `json:"issued_at"`
	ExpiresAt            time.Time          `json:"expires_at"`
	Targets              []Target           `json:"targets"`
	Ports                []int              `json:"ports"`
	MaxConcurrent        int                `json:"max_concurrent"`
	RateLimitPerSecond   int                `json:"rate_limit_per_second"`
	RequiredCapabilities []WorkerCapability `json:"required_capabilities"`
	Resume               *WorkerJobResume   `json:"resume,omitempty"`
	Status               WorkerJobStatus    `json:"status"`
}

type WorkerJobResume struct {
	PreviousWorkerID     string             `json:"previous_worker_id"`
	Completed            []WorkerCheckpoint `json:"completed"`
	NextEvidenceSequence uint64             `json:"next_evidence_sequence"`
}

type WorkerJobResumeCandidate struct {
	Envelope             SignedWorkerJob
	Completed            []WorkerCheckpoint
	NextEvidenceSequence uint64
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

type WorkerJobResultOutcome string

const (
	WorkerJobResultSucceeded WorkerJobResultOutcome = "succeeded"
	WorkerJobResultFailed    WorkerJobResultOutcome = "failed"
	WorkerJobResultCanceled  WorkerJobResultOutcome = "canceled"
)

type WorkerJobResult struct {
	SchemaVersion int                    `json:"schema_version"`
	ID            string                 `json:"result_id"`
	JobID         string                 `json:"job_id"`
	LeaseToken    string                 `json:"lease_token"`
	Outcome       WorkerJobResultOutcome `json:"outcome"`
	CompletedAt   time.Time              `json:"completed_at"`
}

type WorkerJobResultReceipt struct {
	ResultID    string                 `json:"result_id"`
	JobID       string                 `json:"job_id"`
	WorkerID    string                 `json:"worker_id"`
	Outcome     WorkerJobResultOutcome `json:"outcome"`
	CompletedAt time.Time              `json:"completed_at"`
	AcceptedAt  time.Time              `json:"accepted_at"`
}

type WorkerJobLoad struct {
	ActiveJobs          int `json:"active_jobs"`
	ReservedConcurrency int `json:"reserved_concurrency"`
}
