package relaytransport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func TestTelemetryReportsCapacityAndSignedHealthWithoutMessageContent(t *testing.T) {
	now := time.Now().UTC()
	monitor := &TelemetryMonitor{}
	monitor.RecordEnqueue(nil)
	monitor.RecordEnqueue(ErrQueueDuplicate)
	monitor.RecordEnqueue(ErrQueueFull)
	monitor.RecordAcknowledgement(nil, now.Add(-time.Minute))
	report, err := monitor.Report("relay-1", QueueStats{Items: 9, Bytes: 90, OldestFrame: now.Add(-time.Hour)},
		QueueLimits{MaxItems: 10, MaxBytes: 100, MaxAge: time.Hour}, now)
	if err != nil {
		t.Fatal(err)
	}
	if report.Health != HealthDegraded || report.Sequence != 1 || report.QueueItemUtilization != 9000 || report.QueueByteUtilization != 9000 || report.OldestFrameAgeSeconds != 3600 {
		t.Fatalf("unexpected relay telemetry report: %#v", report)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignTelemetry(report, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyTelemetry(signed, &key.PublicKey, now); err != nil {
		t.Fatal(err)
	}
	signed.Report.QueueBytes++
	if err := VerifyTelemetry(signed, &key.PublicKey, now); err == nil {
		t.Fatal("altered relay telemetry was accepted")
	}
}

func TestTelemetryTreatsTamperEvidenceAsCritical(t *testing.T) {
	monitor := &TelemetryMonitor{}
	monitor.RecordIntegrityFailure()
	report, err := monitor.Report("relay-1", QueueStats{}, QueueLimits{MaxItems: 10, MaxBytes: 100, MaxAge: time.Hour}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if report.Health != HealthCritical || report.Counters.IntegrityFailures != 1 {
		t.Fatalf("tamper telemetry was not critical: %#v", report)
	}
	monitor.RecordEnqueue(errors.New("unrelated failure"))
	if report.Counters.CapacityRejections != 0 {
		t.Fatal("unrelated failure changed capacity telemetry")
	}
}

func TestTelemetryShowsDirectAndRelayedPaths(t *testing.T) {
	now := time.Now().UTC()
	monitor := &TelemetryMonitor{}
	relayed := RouteDecision{Route: ApprovedRoute{ID: "primary", Kind: RouteRelay, RelayEndpointID: "relay-1"},
		Reason: "approved_initial_route", SelectedAt: now.Add(-time.Minute)}
	if err := monitor.RecordRouteDecision(relayed); err != nil {
		t.Fatal(err)
	}
	monitor.RecordAcknowledgement(nil, now)
	report, err := monitor.Report("relay-1", QueueStats{}, QueueLimits{MaxItems: 10, MaxBytes: 100, MaxAge: time.Hour}, now)
	if err != nil || report.Path == nil || report.Path.Kind != RouteRelay || report.Path.RelayEndpointID != "relay-1" || report.Path.LastEndToEndAcknowledgement.IsZero() {
		t.Fatalf("relayed path visibility = %#v, error = %v", report.Path, err)
	}
	direct := RouteDecision{Route: ApprovedRoute{ID: "direct", Kind: RouteDirect}, PreviousRouteID: "primary",
		Reason: "approved_failover", SelectedAt: now}
	if err := monitor.RecordRouteDecision(direct); err != nil {
		t.Fatal(err)
	}
	report, err = monitor.Report("relay-1", QueueStats{}, QueueLimits{MaxItems: 10, MaxBytes: 100, MaxAge: time.Hour}, now)
	if err != nil || report.Path == nil || report.Path.Kind != RouteDirect || report.Path.RelayEndpointID != "" || report.Path.PreviousRouteID != "primary" {
		t.Fatalf("direct path visibility = %#v, error = %v", report.Path, err)
	}
}

func TestVerifyTelemetryRejectsSignedInvalidPath(t *testing.T) {
	now := time.Now().UTC()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	report := TelemetryReport{SchemaVersion: 1, RelayID: "relay-1", Sequence: 1, ObservedAt: now,
		Path: &PathVisibility{RouteID: "invalid", Kind: RouteDirect, RelayEndpointID: "must-not-exist", TransitionReason: "approved_failover", SelectedAt: now}}
	signed, err := SignTelemetry(report, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyTelemetry(signed, &key.PublicKey, now); err == nil {
		t.Fatal("signed invalid direct path was accepted")
	}
}
