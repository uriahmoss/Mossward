package store

import (
	"testing"
	"time"

	"mossward/internal/model"
)

func TestEndpointCoverageIsOptInAndReportsOnlyUnlinkedAssets(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, asset := range []struct{ id, address string }{{"linked", "192.0.2.10"}, {"missing", "192.0.2.11"}, {"retired", "192.0.2.12"}} {
		_, err := repository.db.Exec(`INSERT INTO assets(id,name,address,first_seen,last_seen,last_scan_id) VALUES(?,?,?,?,?,'scan')`, asset.id, asset.id, asset.address, formatTime(now), formatTime(now))
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := repository.db.Exec(`UPDATE assets SET lifecycle_status='retired' WHERE id='retired'`); err != nil {
		t.Fatal(err)
	}
	_, err := repository.db.Exec(`INSERT INTO endpoints(id,name,status,certificate_serial,certificate_pem,enrolled_at,expires_at,asset_id) VALUES('endpoint','Endpoint','active','serial','cert',?,?, 'linked')`, formatTime(now), formatTime(now.Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	report, err := repository.EndpointCoverageReport(now)
	if err != nil || report.Enabled || len(report.Gaps) != 0 {
		t.Fatalf("disabled coverage report = %#v, error = %v", report, err)
	}
	settings := model.EndpointCoverageSettings{Enabled: true, UpdatedBy: "admin", UpdatedAt: now}
	event := model.AuditEvent{OccurredAt: now, Action: "endpoint.coverage.updated", Severity: model.AuditInfo, TargetType: "endpoint_coverage", TargetID: "global"}
	if err := repository.SetEndpointCoverageSettings(settings, event); err != nil {
		t.Fatal(err)
	}
	report, err = repository.EndpointCoverageReport(now)
	if err != nil || !report.Enabled || len(report.Gaps) != 0 || len(report.Unclassified) != 1 || report.Unclassified[0].AssetID != "missing" {
		t.Fatalf("enabled coverage report = %#v, error = %v", report, err)
	}
	eligibility := model.AssetAgentEligibilityUpdate{Status: model.AgentEligibilityEligible, Reason: "managed workstation"}
	eligibilityEvent := model.AuditEvent{OccurredAt: now, Action: "asset.agent_eligibility.updated", Severity: model.AuditInfo, TargetType: "asset", TargetID: "missing"}
	if err := repository.UpdateAssetAgentEligibility("missing", eligibility, eligibilityEvent); err != nil {
		t.Fatal(err)
	}
	report, err = repository.EndpointCoverageReport(now)
	if err != nil || len(report.Gaps) != 1 || len(report.Unclassified) != 0 || report.Gaps[0].AssetID != "missing" {
		t.Fatalf("classified coverage report = %#v, error = %v", report, err)
	}
	eligibility = model.AssetAgentEligibilityUpdate{Status: model.AgentEligibilityIneligible, Reason: "network appliance"}
	if err := repository.UpdateAssetAgentEligibility("missing", eligibility, eligibilityEvent); err != nil {
		t.Fatal(err)
	}
	report, err = repository.EndpointCoverageReport(now)
	if err != nil || len(report.Gaps) != 0 || len(report.Unclassified) != 0 {
		t.Fatalf("ineligible coverage report = %#v, error = %v", report, err)
	}
	var count int
	if err := repository.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE action='endpoint.coverage.updated'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("coverage audit count = %d, error = %v", count, err)
	}
}
