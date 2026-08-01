package store

import (
	"testing"
	"time"

	"mossward/internal/model"
)

func TestCompletedScanMaintainsDurableAsset(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	scan := model.Scan{ID: "scan-one", Name: "Discovery", Status: model.StatusCompleted, CreatedAt: now,
		CompletedAt: &now, Observations: []model.ServiceObservation{{ID: "observation-one", Target: "host.example.test",
			Address: "192.0.2.10", Port: 443, Protocol: "https", Confidence: "high", Evidence: "reachable", ObservedAt: now}}}
	if err := repository.Save(scan); err != nil {
		t.Fatal(err)
	}
	assets, err := repository.ListAssets()
	if err != nil || len(assets) != 1 {
		t.Fatalf("unexpected asset inventory: %#v %v", assets, err)
	}
	assetID := assets[0].ID
	if assets[0].Name != "host.example.test" || assets[0].LastScanID != scan.ID {
		t.Fatalf("unexpected asset: %#v", assets[0])
	}
	if _, err := repository.db.Exec(`DELETE FROM scans WHERE id=?`, scan.ID); err != nil {
		t.Fatal(err)
	}
	assets, err = repository.ListAssets()
	if err != nil || len(assets) != 1 || assets[0].ID != assetID {
		t.Fatalf("asset did not survive scan deletion: %#v %v", assets, err)
	}
}

func TestIncompleteScanDoesNotCreateAsset(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	scan := model.Scan{ID: "scan-running", Name: "Discovery", Status: model.StatusRunning, CreatedAt: now,
		Observations: []model.ServiceObservation{{ID: "observation-running", Target: "host", Address: "192.0.2.20",
			Port: 80, Protocol: "http", Confidence: "high", Evidence: "reachable", ObservedAt: now}}}
	if err := repository.Save(scan); err != nil {
		t.Fatal(err)
	}
	assets, err := repository.ListAssets()
	if err != nil || len(assets) != 0 {
		t.Fatalf("incomplete scan created assets: %#v %v", assets, err)
	}
}

func TestExactFQDNCorrelatesMultipleAddresses(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	first := completedAssetScan("scan-one", "observation-one", "Host.Example.Test.", "192.0.2.30", now)
	second := completedAssetScan("scan-two", "observation-two", "host.example.test", "192.0.2.31", now.Add(time.Hour))
	if err := repository.Save(first); err != nil {
		t.Fatal(err)
	}
	if err := repository.Save(second); err != nil {
		t.Fatal(err)
	}
	assets, err := repository.ListAssets()
	if err != nil || len(assets) != 1 {
		t.Fatalf("FQDN addresses were not correlated: %#v %v", assets, err)
	}
	if len(assets[0].Addresses) != 2 || len(assets[0].Names) != 1 || assets[0].LastScanID != second.ID {
		t.Fatalf("unexpected correlated identity: %#v", assets[0])
	}
}

func TestAmbiguousLabelsDoNotCorrelateAddresses(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	first := completedAssetScan("scan-one", "observation-one", "local-host", "192.0.2.40", now)
	second := completedAssetScan("scan-two", "observation-two", "local-host", "192.0.2.41", now.Add(time.Hour))
	if err := repository.Save(first); err != nil {
		t.Fatal(err)
	}
	if err := repository.Save(second); err != nil {
		t.Fatal(err)
	}
	assets, err := repository.ListAssets()
	if err != nil || len(assets) != 2 {
		t.Fatalf("ambiguous labels were merged: %#v %v", assets, err)
	}
}

func completedAssetScan(scanID, observationID, name, address string, observedAt time.Time) model.Scan {
	return model.Scan{ID: scanID, Name: "Discovery", Status: model.StatusCompleted, CreatedAt: observedAt,
		CompletedAt: &observedAt, Observations: []model.ServiceObservation{{ID: observationID, Target: name,
			Address: address, Port: 443, Protocol: "https", Confidence: "high", Evidence: "reachable", ObservedAt: observedAt}}}
}

func TestAssetMetadataRoundTripAndAudit(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if err := repository.Save(completedAssetScan("scan", "observation", "host.example.test", "192.0.2.50", now)); err != nil {
		t.Fatal(err)
	}
	assets, err := repository.ListAssets()
	if err != nil || len(assets) != 1 {
		t.Fatalf("unexpected assets: %#v %v", assets, err)
	}
	metadata := model.AssetMetadata{Owner: "Infrastructure", Environment: "Production", Classification: "Critical"}
	event := model.AuditEvent{OccurredAt: now, Action: "asset.metadata.updated", Severity: model.AuditInfo,
		TargetType: "asset", TargetID: assets[0].ID, Details: "{}"}
	if err := repository.UpdateAssetMetadata(assets[0].ID, metadata, event); err != nil {
		t.Fatal(err)
	}
	assets, err = repository.ListAssets()
	if err != nil || assets[0].Owner != metadata.Owner || assets[0].Environment != metadata.Environment ||
		assets[0].Classification != metadata.Classification {
		t.Fatalf("asset metadata did not round-trip: %#v %v", assets, err)
	}
	events, err := repository.ListAuditEvents(model.AuditQuery{Text: "asset.metadata.updated", Limit: 10})
	if err != nil || len(events) != 1 {
		t.Fatalf("metadata audit event missing: %#v %v", events, err)
	}
}
