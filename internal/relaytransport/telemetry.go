package relaytransport

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

type HealthState string

const (
	HealthHealthy  HealthState = "healthy"
	HealthDegraded HealthState = "degraded"
	HealthCritical HealthState = "critical"
)

type TelemetryCounters struct {
	AcceptedFrames     uint64 `json:"accepted_frames"`
	AcknowledgedFrames uint64 `json:"acknowledged_frames"`
	DuplicateFrames    uint64 `json:"duplicate_frames"`
	CapacityRejections uint64 `json:"capacity_rejections"`
	ExpiredFrames      uint64 `json:"expired_frames"`
	IntegrityFailures  uint64 `json:"integrity_failures"`
}

type TelemetryReport struct {
	SchemaVersion             int               `json:"schema_version"`
	RelayID                   string            `json:"relay_id"`
	Sequence                  uint64            `json:"sequence"`
	Health                    HealthState       `json:"health"`
	QueueItems                int               `json:"queue_items"`
	QueueBytes                int64             `json:"queue_bytes"`
	QueueItemLimit            int               `json:"queue_item_limit"`
	QueueByteLimit            int64             `json:"queue_byte_limit"`
	QueueItemUtilization      int               `json:"queue_item_utilization_basis_points"`
	QueueByteUtilization      int               `json:"queue_byte_utilization_basis_points"`
	OldestFrameAgeSeconds     int64             `json:"oldest_frame_age_seconds"`
	Counters                  TelemetryCounters `json:"counters"`
	LastServerAcknowledgement time.Time         `json:"last_server_acknowledgement,omitempty"`
	ObservedAt                time.Time         `json:"observed_at"`
}

type SignedTelemetry struct {
	Report    TelemetryReport `json:"report"`
	Signature []byte          `json:"signature"`
}

type TelemetryMonitor struct {
	mu                        sync.Mutex
	counters                  TelemetryCounters
	lastServerAcknowledgement time.Time
	sequence                  uint64
}

func (m *TelemetryMonitor) RecordEnqueue(result error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case result == nil:
		m.counters.AcceptedFrames++
	case errors.Is(result, ErrQueueDuplicate):
		m.counters.DuplicateFrames++
	case errors.Is(result, ErrQueueFull):
		m.counters.CapacityRejections++
	}
}

func (m *TelemetryMonitor) RecordAcknowledgement(result error, observedAt time.Time) {
	if result != nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counters.AcknowledgedFrames++
	m.lastServerAcknowledgement = observedAt.UTC()
}

func (m *TelemetryMonitor) RecordExpired(count int64) {
	if count <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counters.ExpiredFrames += uint64(count)
}

func (m *TelemetryMonitor) RecordIntegrityFailure() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counters.IntegrityFailures++
}

func (m *TelemetryMonitor) Report(relayID string, stats QueueStats, limits QueueLimits, observedAt time.Time) (TelemetryReport, error) {
	if relayID == "" || observedAt.IsZero() {
		return TelemetryReport{}, errors.New("relay telemetry identity and observation time are required")
	}
	if err := validateQueueLimits(limits); err != nil {
		return TelemetryReport{}, err
	}
	m.mu.Lock()
	m.sequence++
	sequence := m.sequence
	counters := m.counters
	lastAcknowledgement := m.lastServerAcknowledgement
	m.mu.Unlock()
	report := TelemetryReport{SchemaVersion: 1, RelayID: relayID, Sequence: sequence, QueueItems: stats.Items, QueueBytes: stats.Bytes,
		QueueItemLimit: limits.MaxItems, QueueByteLimit: limits.MaxBytes, Counters: counters,
		LastServerAcknowledgement: lastAcknowledgement, ObservedAt: observedAt.UTC()}
	report.QueueItemUtilization = utilizationBasisPoints(int64(stats.Items), int64(limits.MaxItems))
	report.QueueByteUtilization = utilizationBasisPoints(stats.Bytes, limits.MaxBytes)
	if !stats.OldestFrame.IsZero() && observedAt.After(stats.OldestFrame) {
		report.OldestFrameAgeSeconds = int64(observedAt.Sub(stats.OldestFrame).Seconds())
	}
	report.Health = classifyRelayHealth(report)
	return report, nil
}

func SignTelemetry(report TelemetryReport, key *ecdsa.PrivateKey) (SignedTelemetry, error) {
	if key == nil {
		return SignedTelemetry{}, errors.New("relay telemetry signing key is required")
	}
	digest, err := telemetryDigest(report)
	if err != nil {
		return SignedTelemetry{}, err
	}
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest)
	if err != nil {
		return SignedTelemetry{}, err
	}
	return SignedTelemetry{Report: report, Signature: signature}, nil
}

func VerifyTelemetry(signed SignedTelemetry, key *ecdsa.PublicKey, now time.Time) error {
	if key == nil || signed.Report.SchemaVersion != 1 || signed.Report.RelayID == "" || signed.Report.Sequence == 0 || signed.Report.ObservedAt.IsZero() {
		return errors.New("relay telemetry envelope is invalid")
	}
	if signed.Report.ObservedAt.After(now.Add(5*time.Minute)) || signed.Report.ObservedAt.Before(now.Add(-24*time.Hour)) {
		return errors.New("relay telemetry observation time is outside the accepted window")
	}
	digest, err := telemetryDigest(signed.Report)
	if err != nil {
		return err
	}
	if !ecdsa.VerifyASN1(key, digest, signed.Signature) {
		return errors.New("relay telemetry signature verification failed")
	}
	return nil
}

func telemetryDigest(report TelemetryReport) ([]byte, error) {
	encoded, err := json.Marshal(report)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(encoded)
	return digest[:], nil
}

func utilizationBasisPoints(used, limit int64) int {
	if used <= 0 || limit <= 0 {
		return 0
	}
	if used >= limit {
		return 10000
	}
	return int(used * 10000 / limit)
}

func classifyRelayHealth(report TelemetryReport) HealthState {
	if report.Counters.IntegrityFailures > 0 {
		return HealthCritical
	}
	if report.Counters.CapacityRejections > 0 || report.QueueItemUtilization >= 9000 || report.QueueByteUtilization >= 9000 {
		return HealthDegraded
	}
	return HealthHealthy
}
