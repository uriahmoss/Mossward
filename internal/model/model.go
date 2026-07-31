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
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Targets     []Target   `json:"targets"`
	Ports       []int      `json:"ports"`
	Status      ScanStatus `json:"status"`
	Error       string     `json:"error,omitempty"`
	Findings    []Finding  `json:"findings"`
	TotalChecks int        `json:"total_checks"`
	DoneChecks  int        `json:"done_checks"`
	CreatedAt   time.Time  `json:"created_at"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

type CreateScanRequest struct {
	Name    string   `json:"name"`
	Targets []string `json:"targets"`
	Ports   []int    `json:"ports"`
}
