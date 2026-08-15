package agentmodule

import "encoding/json"

type HostRequest struct {
	SchemaVersion int             `json:"schema_version"`
	ModuleID      string          `json:"module_id"`
	Permissions   []Permission    `json:"permissions"`
	Input         json.RawMessage `json:"input"`
}

type HostResult struct {
	SchemaVersion int             `json:"schema_version"`
	ModuleID      string          `json:"module_id"`
	Healthy       bool            `json:"healthy"`
	Evidence      json.RawMessage `json:"evidence,omitempty"`
	Error         string          `json:"error,omitempty"`
}
