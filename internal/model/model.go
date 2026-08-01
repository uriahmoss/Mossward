package model

import (
	"encoding/json"
	"fmt"
	"time"
)

type ScanStatus string

const (
	StatusQueued    ScanStatus = "queued"
	StatusRunning   ScanStatus = "running"
	StatusCompleted ScanStatus = "completed"
	StatusFailed    ScanStatus = "failed"
)

type Finding struct {
	ID          string    `json:"id"`
	CheckID     string    `json:"check_id"`
	Target      string    `json:"target"`
	Address     string    `json:"address"`
	Port        int       `json:"port"`
	Service     string    `json:"service"`
	Severity    string    `json:"severity"`
	Title       string    `json:"title"`
	Evidence    string    `json:"evidence"`
	Remediation string    `json:"remediation"`
	ObservedAt  time.Time `json:"observed_at"`
}

type ServiceObservation struct {
	ID         string            `json:"id"`
	Target     string            `json:"target"`
	Address    string            `json:"address"`
	Port       int               `json:"port"`
	Protocol   string            `json:"protocol"`
	Product    string            `json:"product,omitempty"`
	Version    string            `json:"version,omitempty"`
	Confidence string            `json:"confidence"`
	Evidence   string            `json:"evidence"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	ObservedAt time.Time         `json:"observed_at"`
}

type Target struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

func (t *Target) UnmarshalJSON(data []byte) error {
	var legacy string
	if err := json.Unmarshal(data, &legacy); err == nil {
		t.Name = legacy
		t.Address = legacy
		return nil
	}
	type target Target
	var value target
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("decode target: %w", err)
	}
	if value.Name == "" || value.Address == "" {
		return fmt.Errorf("target name and address are required")
	}
	*t = Target(value)
	return nil
}

type Scan struct {
	ID            string               `json:"id"`
	Name          string               `json:"name"`
	Targets       []Target             `json:"targets"`
	Ports         []int                `json:"ports"`
	Status        ScanStatus           `json:"status"`
	Error         string               `json:"error,omitempty"`
	Observations  []ServiceObservation `json:"observations"`
	Findings      []Finding            `json:"findings"`
	CVEMatches    []CVEMatch           `json:"cve_matches"`
	TotalChecks   int                  `json:"total_checks"`
	DoneChecks    int                  `json:"done_checks"`
	CreatedAt     time.Time            `json:"created_at"`
	StartedAt     *time.Time           `json:"started_at,omitempty"`
	CompletedAt   *time.Time           `json:"completed_at,omitempty"`
	ScopePolicyID string               `json:"scope_policy_id,omitempty"`
	MaxConcurrent int                  `json:"max_concurrent,omitempty"`
}

type CVERecord struct {
	ID             string            `json:"id"`
	Description    string            `json:"description"`
	PublishedAt    time.Time         `json:"published_at"`
	ModifiedAt     time.Time         `json:"modified_at"`
	CVSSScore      float64           `json:"cvss_score"`
	CVSSVector     string            `json:"cvss_vector,omitempty"`
	Severity       string            `json:"severity"`
	KnownExploited bool              `json:"known_exploited"`
	SourceURL      string            `json:"source_url"`
	Products       []AffectedProduct `json:"products"`
	References     []CVEReference    `json:"references"`
}

type AffectedProduct struct {
	CPE23                 string `json:"cpe23"`
	Part                  string `json:"part"`
	Vendor                string `json:"vendor"`
	Product               string `json:"product"`
	Version               string `json:"version,omitempty"`
	VersionStartIncluding string `json:"version_start_including,omitempty"`
	VersionStartExcluding string `json:"version_start_excluding,omitempty"`
	VersionEndIncluding   string `json:"version_end_including,omitempty"`
	VersionEndExcluding   string `json:"version_end_excluding,omitempty"`
	Vulnerable            bool   `json:"vulnerable"`
}

type CVEReference struct {
	URL    string `json:"url"`
	Source string `json:"source,omitempty"`
}

type CVEMatch struct {
	CVEID          string    `json:"cve_id"`
	ObservationID  string    `json:"observation_id"`
	Target         string    `json:"target"`
	Address        string    `json:"address"`
	Port           int       `json:"port"`
	Product        string    `json:"product"`
	Version        string    `json:"version"`
	Severity       string    `json:"severity"`
	CVSSScore      float64   `json:"cvss_score"`
	Description    string    `json:"description"`
	Confidence     string    `json:"confidence"`
	Evidence       string    `json:"evidence"`
	KnownExploited bool      `json:"known_exploited"`
	SourceURL      string    `json:"source_url"`
	MatchedAt      time.Time `json:"matched_at"`
}

type CVENewsItem struct {
	ID             string    `json:"id"`
	Description    string    `json:"description"`
	PublishedAt    time.Time `json:"published_at"`
	CVSSScore      float64   `json:"cvss_score"`
	Severity       string    `json:"severity"`
	KnownExploited bool      `json:"known_exploited"`
	SourceURL      string    `json:"source_url"`
	Relevance      string    `json:"relevance"`
	Evidence       string    `json:"evidence,omitempty"`
}

type FeedStatus struct {
	Source       string     `json:"source"`
	Status       string     `json:"status"`
	LastStarted  *time.Time `json:"last_started,omitempty"`
	LastSuccess  *time.Time `json:"last_success,omitempty"`
	Records      int        `json:"records"`
	Error        string     `json:"error,omitempty"`
	DatabaseCVEs int        `json:"database_cves"`
}

type CreateScanRequest struct {
	Name          string   `json:"name"`
	Targets       []string `json:"targets"`
	Ports         []int    `json:"ports"`
	ScopePolicyID string   `json:"scope_policy_id"`
}

type ScopePolicy struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	AllowedCIDRs  []string  `json:"allowed_cidrs"`
	AllowedPorts  []int     `json:"allowed_ports"`
	MaxTargets    int       `json:"max_targets"`
	MaxConcurrent int       `json:"max_concurrent"`
	Enabled       bool      `json:"enabled"`
	CreatedBy     string    `json:"created_by,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}
