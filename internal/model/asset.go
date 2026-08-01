package model

import "time"

type Asset struct {
	ID             string         `json:"id"`
	Name           string         `json:"name"`
	Address        string         `json:"address"`
	FirstSeen      time.Time      `json:"first_seen"`
	LastSeen       time.Time      `json:"last_seen"`
	LastScanID     string         `json:"last_scan_id"`
	Names          []string       `json:"names"`
	Addresses      []AssetAddress `json:"addresses"`
	Owner          string         `json:"owner"`
	Environment    string         `json:"environment"`
	Classification string         `json:"classification"`
}

type AssetMetadata struct {
	Owner          string `json:"owner"`
	Environment    string `json:"environment"`
	Classification string `json:"classification"`
}

type AssetAddress struct {
	Address    string    `json:"address"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	LastScanID string    `json:"last_scan_id"`
}
