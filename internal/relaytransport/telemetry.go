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
	DroppedRecords     uint64 `json:"dropped_records"`
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
	QueueMaximumAgeSeconds    int64             `json:"queue_maximum_age_seconds"`
	QueueItemUtilization      int               `json:"queue_item_utilization_basis_points"`
	QueueByteUtilization      int               `json:"queue_byte_utilization_basis_points"`
	QueueRoutineItems         int               `json:"queue_routine_items"`
	QueueElevatedItems        int               `json:"queue_elevated_items"`
	QueueCriticalItems        int               `json:"queue_critical_items"`
	QueueLeasedItems          int               `json:"queue_leased_items"`
	OldestFrameAgeSeconds     int64             `json:"oldest_frame_age_seconds"`
	Counters                  TelemetryCounters `json:"counters"`
	Path                      *PathVisibility   `json:"path,omitempty"`
	LastServerAcknowledgement time.Time         `json:"last_server_acknowledgement,omitempty"`
	LastUploadAttempt         time.Time         `json:"last_upload_attempt,omitempty"`
	LastSuccessfulUpload      time.Time         `json:"last_successful_upload,omitempty"`
	ObservedAt                time.Time         `json:"observed_at"`
}

type PathVisibility struct {
	RouteID                     string    `json:"route_id"`
	Kind                        RouteKind `json:"kind"`
	RelayEndpointID             string    `json:"relay_endpoint_id,omitempty"`
	PreviousRouteID             string    `json:"previous_route_id,omitempty"`
	TransitionReason            string    `json:"transition_reason"`
	SelectedAt                  time.Time `json:"selected_at"`
	LastEndToEndAcknowledgement time.Time `json:"last_end_to_end_acknowledgement,omitempty"`
}

type SignedTelemetry struct {
	Report    TelemetryReport `json:"report"`
	Signature []byte          `json:"signature"`
}

type TelemetryMonitor struct {
	mu                        sync.Mutex
	counters                  TelemetryCounters
	lastServerAcknowledgement time.Time
	lastUploadAttempt         time.Time
	lastSuccessfulUpload      time.Time
	path                      *PathVisibility
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
	m.lastSuccessfulUpload = observedAt.UTC()
	if m.path != nil {
		m.path.LastEndToEndAcknowledgement = observedAt.UTC()
	}
}

func (m *TelemetryMonitor) RecordUploadAttempt(observedAt time.Time) {
	if observedAt.IsZero() {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastUploadAttempt = observedAt.UTC()
}

func (m *TelemetryMonitor) RecordDropped(count uint64) {
	if count == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counters.DroppedRecords += count
}

func (m *TelemetryMonitor) RecordRouteDecision(decision RouteDecision) error {
	path := PathVisibility{RouteID: decision.Route.ID, Kind: decision.Route.Kind, RelayEndpointID: decision.Route.RelayEndpointID,
		PreviousRouteID: decision.PreviousRouteID, TransitionReason: decision.Reason, SelectedAt: decision.SelectedAt.UTC()}
	if err := validatePathVisibility(path); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.path = &path
	return nil
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
	lastUploadAttempt := m.lastUploadAttempt
	lastSuccessfulUpload := m.lastSuccessfulUpload
	path := clonePathVisibility(m.path)
	m.mu.Unlock()
	report := TelemetryReport{SchemaVersion: 1, RelayID: relayID, Sequence: sequence, QueueItems: stats.Items, QueueBytes: stats.Bytes,
		QueueItemLimit: limits.MaxItems, QueueByteLimit: limits.MaxBytes, QueueMaximumAgeSeconds: int64(limits.MaxAge.Seconds()),
		QueueRoutineItems: stats.RoutineItems, QueueElevatedItems: stats.ElevatedItems, QueueCriticalItems: stats.CriticalItems,
		QueueLeasedItems: stats.LeasedItems, Counters: counters, Path: path, LastServerAcknowledgement: lastAcknowledgement,
		LastUploadAttempt: lastUploadAttempt, LastSuccessfulUpload: lastSuccessfulUpload, ObservedAt: observedAt.UTC()}
	report.QueueItemUtilization = utilizationBasisPoints(int64(stats.Items), int64(limits.MaxItems))
	report.QueueByteUtilization = utilizationBasisPoints(stats.Bytes, limits.MaxBytes)
	if !stats.OldestFrame.IsZero() && observedAt.After(stats.OldestFrame) {
		report.OldestFrameAgeSeconds = int64(observedAt.Sub(stats.OldestFrame).Seconds())
	}
	report.Health = classifyRelayHealth(report)
	return report, nil
}

func validatePathVisibility(path PathVisibility) error {
	if path.RouteID == "" || len(path.RouteID) > maximumRouteIDLength || len(path.RelayEndpointID) > maximumRouteIDLength || len(path.PreviousRouteID) > maximumRouteIDLength || path.SelectedAt.IsZero() {
		return errors.New("relay path visibility is invalid")
	}
	switch path.Kind {
	case RouteRelay:
		if path.RelayEndpointID == "" {
			return errors.New("relayed path requires an approved relay identity")
		}
	case RouteDirect:
		if path.RelayEndpointID != "" {
			return errors.New("direct path cannot identify a relay")
		}
	default:
		return errors.New("relay path kind is invalid")
	}
	switch path.TransitionReason {
	case "approved_initial_route", "approved_failover", "active_route_healthy", "server_selected_approved_route":
		return nil
	default:
		return errors.New("relay path transition reason is invalid")
	}
}

func clonePathVisibility(path *PathVisibility) *PathVisibility {
	if path == nil {
		return nil
	}
	cloned := *path
	return &cloned
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
	if signed.Report.Path != nil {
		if err := validatePathVisibility(*signed.Report.Path); err != nil {
			return err
		}
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
	if report.Counters.CapacityRejections > 0 || report.Counters.ExpiredFrames > 0 || report.Counters.DroppedRecords > 0 || report.QueueItemUtilization >= 9000 || report.QueueByteUtilization >= 9000 {
		return HealthDegraded
	}
	return HealthHealthy
}
