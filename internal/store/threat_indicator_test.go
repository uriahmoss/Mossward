package store

import (
	"testing"
	"time"

	"mossward/internal/model"
)

func TestThreatIndicatorsCorrelateExactActiveNetworkContext(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	insertActiveTestEndpoint(t, repository, now)
	inventory := model.EndpointNetworkInventory{CollectedAt: now, Connections: []model.NetworkConnection{
		{RemoteAddress: "198.51.100.10", RemoteHostname: "service.example.test", ProcessName: "client", Executable: "/usr/bin/client"},
		{RemoteAddress: "198.51.100.11", RemoteHostname: "sub.service.example.test"},
	}}
	if err := repository.RecordEndpointNetworkInventory("endpoint-1", inventory, now); err != nil {
		t.Fatal(err)
	}
	for _, indicator := range []model.ThreatIndicator{
		{ID: "ip", Type: model.ThreatIndicatorIP, Value: "198.51.100.10", Source: "test feed", Confidence: "high", ObservedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Enabled: true, CreatedBy: "admin", CreatedAt: now, UpdatedAt: now},
		{ID: "host", Type: model.ThreatIndicatorHostname, Value: "service.example.test", Source: "test feed", Confidence: "medium", ObservedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Enabled: true, CreatedBy: "admin", CreatedAt: now, UpdatedAt: now},
		{ID: "expired", Type: model.ThreatIndicatorIP, Value: "198.51.100.11", Source: "old feed", Confidence: "low", ObservedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour), Enabled: true, CreatedBy: "admin", CreatedAt: now, UpdatedAt: now},
	} {
		event := model.AuditEvent{OccurredAt: now, Action: "test", Severity: model.AuditInfo, TargetType: "threat_indicator", TargetID: indicator.ID}
		if err := repository.UpsertThreatIndicator(indicator, now, event); err != nil {
			t.Fatal(err)
		}
	}
	matches, err := repository.EndpointIndicatorMatches("endpoint-1", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 2 {
		t.Fatalf("matches = %#v, want exact IP and exact hostname matches", matches)
	}
	if matches[0].ProcessName != "client" || matches[0].Source != "test feed" {
		t.Fatalf("match evidence = %#v", matches[0])
	}
}

func TestThreatIndicatorMatchesAreRemovedWithNetworkSnapshot(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	insertActiveTestEndpoint(t, repository, now)
	indicator := model.ThreatIndicator{ID: "ip", Type: model.ThreatIndicatorIP, Value: "198.51.100.10", Source: "test", Confidence: "high", ObservedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Enabled: true, CreatedBy: "admin", CreatedAt: now, UpdatedAt: now}
	event := model.AuditEvent{OccurredAt: now, Action: "test", Severity: model.AuditInfo, TargetType: "threat_indicator", TargetID: indicator.ID}
	if err := repository.UpsertThreatIndicator(indicator, now, event); err != nil {
		t.Fatal(err)
	}
	if err := repository.RecordEndpointNetworkInventory("endpoint-1", model.EndpointNetworkInventory{CollectedAt: now, Connections: []model.NetworkConnection{{RemoteAddress: indicator.Value}}}, now); err != nil {
		t.Fatal(err)
	}
	if err := repository.RecordEndpointNetworkInventory("endpoint-1", model.EndpointNetworkInventory{CollectedAt: now.Add(time.Minute)}, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	matches, err := repository.EndpointIndicatorMatches("endpoint-1", now.Add(time.Minute))
	if err != nil || len(matches) != 0 {
		t.Fatalf("matches after replacement = %#v, error = %v", matches, err)
	}
}

func insertActiveTestEndpoint(t *testing.T, repository *SQLiteStore, now time.Time) {
	t.Helper()
	_, err := repository.db.Exec(`INSERT INTO endpoints(id,name,status,certificate_serial,certificate_pem,enrolled_at,expires_at) VALUES('endpoint-1','Host','active','serial','cert',?,?)`, formatTime(now), formatTime(now.Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
}
