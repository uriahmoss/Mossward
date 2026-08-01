package store

import (
	"errors"
	"fmt"
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

func TestAssetLifecycleRetirementAndRestoreAreAudited(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if err := repository.Save(completedAssetScan("scan", "observation", "host.example.test", "192.0.2.60", now)); err != nil {
		t.Fatal(err)
	}
	assets, err := repository.ListAssets()
	if err != nil || len(assets) != 1 || assets[0].Lifecycle.Status != model.AssetActive {
		t.Fatalf("new asset was not active: %#v %v", assets, err)
	}
	retirement := model.AssetLifecycleUpdate{Status: model.AssetRetired, Reason: "Device decommissioned"}
	event := model.AuditEvent{OccurredAt: now.Add(time.Hour), Action: "asset.retired",
		Severity: model.AuditInfo, TargetType: "asset", TargetID: assets[0].ID, Details: "{}"}
	if err := repository.UpdateAssetLifecycle(assets[0].ID, retirement, event); err != nil {
		t.Fatal(err)
	}
	assets, err = repository.ListAssets()
	if err != nil || assets[0].Lifecycle.Status != model.AssetRetired || assets[0].Lifecycle.RetiredAt == nil ||
		assets[0].Lifecycle.RetiredBy != "" || assets[0].Lifecycle.RetirementReason != retirement.Reason {
		t.Fatalf("retirement did not round-trip: %#v %v", assets, err)
	}
	restoreEvent := event
	restoreEvent.Action = "asset.restored"
	restoreEvent.OccurredAt = now.Add(2 * time.Hour)
	if err := repository.UpdateAssetLifecycle(assets[0].ID, model.AssetLifecycleUpdate{Status: model.AssetActive}, restoreEvent); err != nil {
		t.Fatal(err)
	}
	assets, err = repository.ListAssets()
	if err != nil || assets[0].Lifecycle.Status != model.AssetActive || assets[0].Lifecycle.RetiredAt != nil ||
		assets[0].Lifecycle.RetiredBy != "" || assets[0].Lifecycle.RetirementReason != "" {
		t.Fatalf("restore did not clear retirement: %#v %v", assets, err)
	}
	events, err := repository.ListAuditEvents(model.AuditQuery{Text: "asset.", Limit: 10})
	if err != nil || len(events) != 2 {
		t.Fatalf("asset lifecycle audit events missing: %#v %v", events, err)
	}
}

func TestAssetAgingDefaultsToThirtyDaysAndIsConfigurable(t *testing.T) {
	repository := openTestStore(t)
	settings, err := repository.AssetAgingSettings()
	if err != nil || settings.StaleAfterDays != 30 {
		t.Fatalf("unexpected default asset aging: %#v %v", settings, err)
	}
	observedAt := time.Now().UTC().Add(-10 * 24 * time.Hour)
	if err := repository.Save(completedAssetScan("scan", "observation", "aging.example.test", "192.0.2.80", observedAt)); err != nil {
		t.Fatal(err)
	}
	assets, err := repository.ListAssets()
	if err != nil || assets[0].Lifecycle.Status != model.AssetActive {
		t.Fatalf("asset aged before default threshold: %#v %v", assets, err)
	}
	event := model.AuditEvent{OccurredAt: time.Now().UTC(), Action: "asset.aging.updated", Severity: model.AuditInfo, Details: "{}"}
	if err := repository.UpdateAssetAgingSettings(model.AssetAgingSettings{StaleAfterDays: 5}, event); err != nil {
		t.Fatal(err)
	}
	assets, err = repository.ListAssets()
	if err != nil || assets[0].Lifecycle.Status != model.AssetStale {
		t.Fatalf("configured aging threshold was not applied: %#v %v", assets, err)
	}
}

func TestMergeAssetsPreservesHistoryAndSelectedValues(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	first := completedAssetScan("scan-one", "observation-one", "first", "192.0.2.90", now)
	second := completedAssetScan("scan-two", "observation-two", "second", "192.0.2.91", now.Add(time.Hour))
	first.Observations[0].Port = 80
	second.Observations[0].Port = 443
	if err := repository.Save(first); err != nil {
		t.Fatal(err)
	}
	if err := repository.Save(second); err != nil {
		t.Fatal(err)
	}
	assets, err := repository.ListAssets()
	if err != nil || len(assets) != 2 {
		t.Fatalf("merge fixtures missing: %#v %v", assets, err)
	}
	firstAsset, secondAsset := assets[1], assets[0]
	if _, err := repository.db.Exec(`INSERT INTO users(id,email,display_name,role,status,created_at,updated_at) VALUES('merge-admin','merge@example.test','Merge Admin','administrator','active',?,?)`, formatTime(now), formatTime(now)); err != nil {
		t.Fatal(err)
	}
	groupEvent := model.AuditEvent{OccurredAt: now, ActorID: "merge-admin", Action: "test", Severity: model.AuditInfo, Details: "{}"}
	for index, assetID := range []string{firstAsset.ID, secondAsset.ID} {
		groupID := fmt.Sprintf("merge-group-%d", index)
		if err := repository.UpsertAssetGroup(model.AssetGroup{ID: groupID, Name: groupID, CreatedAt: now, UpdatedAt: now}, groupEvent); err != nil {
			t.Fatal(err)
		}
		if err := repository.AddAssetGroupMember(groupID, assetID, "merge-admin", now, groupEvent); err != nil {
			t.Fatal(err)
		}
	}
	metadata := model.AssetMetadata{Owner: "New owner", Environment: "Production", Classification: "Critical"}
	if err := repository.UpdateAssetMetadata(secondAsset.ID, metadata, model.AuditEvent{OccurredAt: now, Action: "asset.metadata.updated", Severity: model.AuditInfo, Details: "{}"}); err != nil {
		t.Fatal(err)
	}
	request := model.AssetMergeRequest{SurvivorID: firstAsset.ID, MergedID: secondAsset.ID, NameFrom: secondAsset.ID,
		AddressFrom: secondAsset.ID, OwnerFrom: secondAsset.ID, EnvironmentFrom: secondAsset.ID,
		ClassificationFrom: secondAsset.ID, LifecycleFrom: secondAsset.ID}
	event := model.AuditEvent{OccurredAt: now.Add(2 * time.Hour), Action: "asset.merged", Severity: model.AuditWarning, Details: "{}"}
	if err := repository.MergeAssets(request, event); err != nil {
		t.Fatal(err)
	}
	assets, err = repository.ListAssets()
	if err != nil || len(assets) != 1 || assets[0].ID != firstAsset.ID || assets[0].Name != secondAsset.Name ||
		assets[0].Owner != metadata.Owner || len(assets[0].Addresses) != 2 {
		t.Fatalf("merged asset values or identity history missing: %#v %v", assets, err)
	}
	detail, err := repository.AssetDetail(firstAsset.ID, now.Add(2*time.Hour))
	if err != nil || len(detail.Services) != 2 || len(detail.Evidence) != 2 {
		t.Fatalf("merged service or evidence history missing: %#v %v", detail, err)
	}
	memberships, err := repository.AssetGroupMemberships(firstAsset.ID)
	if err != nil || len(memberships) != 2 {
		t.Fatalf("merged group memberships missing: %#v %v", memberships, err)
	}
	if _, err := repository.AssetDetail(secondAsset.ID, now); !errors.Is(err, ErrAssetNotFound) {
		t.Fatalf("merged-away asset still exists: %v", err)
	}
}
