package model

import "time"

type WorkerEvidenceBatch struct {
	SchemaVersion int                  `json:"schema_version"`
	ID            string               `json:"batch_id"`
	WorkerID      string               `json:"worker_id"`
	JobID         string               `json:"job_id"`
	ScanID        string               `json:"scan_id"`
	Sequence      uint64               `json:"sequence"`
	Final         bool                 `json:"final"`
	CollectedAt   time.Time            `json:"collected_at"`
	Observations  []ServiceObservation `json:"observations"`
	Findings      []Finding            `json:"findings"`
	Checkpoints   []WorkerCheckpoint   `json:"checkpoints"`
}

type WorkerCheckpoint struct {
	Address     string    `json:"address"`
	Port        int       `json:"port"`
	CompletedAt time.Time `json:"completed_at"`
}

type SignedWorkerEvidenceBatch struct {
	Algorithm         string              `json:"algorithm"`
	CertificateSerial string              `json:"certificate_serial"`
	Batch             WorkerEvidenceBatch `json:"batch"`
	Signature         string              `json:"signature"`
}
