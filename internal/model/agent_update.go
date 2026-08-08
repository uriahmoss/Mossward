package model

import "time"

type AgentUpdateStatus string

const (
	AgentUpdateStaged   AgentUpdateStatus = "staged"
	AgentUpdateApproved AgentUpdateStatus = "approved"
	AgentUpdateRevoked  AgentUpdateStatus = "revoked"
)

type AgentUpdateRelease struct {
	ID               string            `json:"id"`
	Version          string            `json:"version"`
	OperatingSystem  string            `json:"operating_system"`
	Architecture     string            `json:"architecture"`
	ArtifactSHA256   string            `json:"artifact_sha256"`
	ArtifactSize     int64             `json:"artifact_size"`
	SigningKeyID     string            `json:"signing_key_id"`
	Envelope         []byte            `json:"-"`
	Status           AgentUpdateStatus `json:"status"`
	CreatedBy        string            `json:"created_by"`
	CreatedAt        time.Time         `json:"created_at"`
	ApprovedBy       string            `json:"approved_by,omitempty"`
	ApprovedAt       *time.Time        `json:"approved_at,omitempty"`
	RevokedBy        string            `json:"revoked_by,omitempty"`
	RevokedAt        *time.Time        `json:"revoked_at,omitempty"`
	RevocationReason string            `json:"revocation_reason,omitempty"`
}

type AgentUpdateAssignment struct {
	EndpointID  string     `json:"endpoint_id"`
	ReleaseID   string     `json:"release_id"`
	Status      string     `json:"status"`
	AssignedBy  string     `json:"assigned_by"`
	AssignedAt  time.Time  `json:"assigned_at"`
	OfferedAt   *time.Time `json:"offered_at,omitempty"`
	InstalledAt *time.Time `json:"installed_at,omitempty"`
}
