package store

import (
	"mossward/internal/model"
	"testing"
	"time"
)

func TestAssetServiceHistoryTracksObservedAndNotObserved(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	cve := model.CVERecord{ID: "CVE-2026-0001", Description: "Test", PublishedAt: now, ModifiedAt: now, Severity: "critical", SourceURL: "https://example.test/cve"}
	if err := repository.UpsertCVEs([]model.CVERecord{cve}); err != nil {
		t.Fatal(err)
	}
	first := serviceHistoryScan("scan-one", "observation-one", now, true)
	first.Findings = []model.Finding{{ID: "finding-one", Address: "192.0.2.70", Port: 443, ObservedAt: now}}
	first.CVEMatches = []model.CVEMatch{{CVEID: cve.ID, ObservationID: "observation-one", Address: "192.0.2.70", Port: 443, MatchedAt: now}}
	if err := repository.Save(first); err != nil {
		t.Fatal(err)
	}
	assets, _ := repository.ListAssets()
	detail, err := repository.AssetDetail(assets[0].ID, now)
	if err != nil || len(detail.Services) != 1 {
		t.Fatalf("missing service history: %#v %v", detail, err)
	}
	service := detail.Services[0]
	if service.State != "observed" || service.ObservationCount != 1 || len(service.Events) != 1 || len(service.Events[0].FindingIDs) != 1 || len(service.Events[0].CVEIDs) != 1 {
		t.Fatalf("unexpected first service state: %#v", service)
	}
	second := serviceHistoryScan("scan-two", "", now.Add(time.Hour), false)
	if err := repository.Save(second); err != nil {
		t.Fatal(err)
	}
	detail, _ = repository.AssetDetail(assets[0].ID, now.Add(time.Hour))
	if detail.Services[0].State != "not_observed" || detail.Services[0].ObservationCount != 1 {
		t.Fatalf("service absence was overstated or history changed: %#v", detail.Services[0])
	}
	third := serviceHistoryScan("scan-three", "observation-three", now.Add(2*time.Hour), true)
	third.Observations[0].Product = "nginx"
	third.Observations[0].Version = "1.26"
	if err := repository.Save(third); err != nil {
		t.Fatal(err)
	}
	detail, _ = repository.AssetDetail(assets[0].ID, now.Add(2*time.Hour))
	if detail.Services[0].State != "observed" || detail.Services[0].ObservationCount != 2 || len(detail.Services[0].Events) != 2 || detail.Services[0].Version != "1.26" {
		t.Fatalf("service did not return to observed: %#v", detail.Services[0])
	}
}

func TestAssetServiceBecomesStaleByAge(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if err := repository.Save(serviceHistoryScan("scan", "observation", now, true)); err != nil {
		t.Fatal(err)
	}
	assets, _ := repository.ListAssets()
	detail, err := repository.AssetDetail(assets[0].ID, now.Add(31*24*time.Hour))
	if err != nil || detail.Services[0].State != "stale" {
		t.Fatalf("old observation was not marked stale: %#v %v", detail, err)
	}
}

func serviceHistoryScan(id, observationID string, at time.Time, observed bool) model.Scan {
	scan := model.Scan{ID: id, Name: "Exposure", Status: model.StatusCompleted, CreatedAt: at, CompletedAt: &at, Targets: []model.Target{{Name: "host.example.test", Address: "192.0.2.70"}}, Ports: []int{443}}
	if observed {
		scan.Observations = []model.ServiceObservation{{ID: observationID, Target: "host.example.test", Address: "192.0.2.70", Port: 443, Protocol: "https", Confidence: "high", Evidence: "reachable", ObservedAt: at}}
	}
	return scan
}
