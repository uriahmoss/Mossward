package agentmodule

import "time"

type Publisher struct {
	KeyID     string    `json:"key_id"`
	Name      string    `json:"name"`
	PublicKey []byte    `json:"-"`
	Enabled   bool      `json:"enabled"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

type ReleaseStatus string

const (
	ReleaseStaged   ReleaseStatus = "staged"
	ReleaseApproved ReleaseStatus = "approved"
	ReleaseRevoked  ReleaseStatus = "revoked"
)

type Release struct {
	ID               string        `json:"id"`
	Manifest         Manifest      `json:"manifest"`
	Envelope         []byte        `json:"-"`
	Status           ReleaseStatus `json:"status"`
	CreatedBy        string        `json:"created_by"`
	CreatedAt        time.Time     `json:"created_at"`
	ApprovedBy       string        `json:"approved_by,omitempty"`
	ApprovedAt       *time.Time    `json:"approved_at,omitempty"`
	RevokedBy        string        `json:"revoked_by,omitempty"`
	RevokedAt        *time.Time    `json:"revoked_at,omitempty"`
	RevocationReason string        `json:"revocation_reason,omitempty"`
}

type Assignment struct {
	ID          string    `json:"id"`
	ReleaseID   string    `json:"release_id"`
	TargetType  string    `json:"target_type"`
	TargetID    string    `json:"target_id"`
	RingPercent int       `json:"ring_percent"`
	Enabled     bool      `json:"enabled"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
}

type Health struct {
	ModuleID   string    `json:"module_id"`
	Version    string    `json:"version"`
	Healthy    bool      `json:"healthy"`
	CrashCount int       `json:"crash_count"`
	Error      string    `json:"error,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
}

type Offer struct {
	ReleaseID string `json:"release_id"`
	Envelope  []byte `json:"envelope"`
	Disabled  bool   `json:"disabled,omitempty"`
}
