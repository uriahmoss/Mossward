package store

import (
	"testing"
	"time"

	"mossward/internal/model"
)

func TestEndpointCVECorrelationRequiresNormalizedProductAndVersion(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, err := repository.db.Exec(`INSERT INTO endpoints(id,name,status,certificate_serial,certificate_pem,enrolled_at,expires_at) VALUES('endpoint-1','Host','active','serial','cert',?,?)`, formatTime(now), formatTime(now.Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	record := model.CVERecord{ID: "CVE-TEST-1", Description: "test", PublishedAt: now, ModifiedAt: now, CVSSScore: 9.8, Severity: "critical", SourceURL: "https://example.test/cve",
		Products: []model.AffectedProduct{{Vendor: "openssl", Product: "openssl", VersionStartIncluding: "3.0.0", VersionEndExcluding: "3.0.2", Vulnerable: true}}}
	if err := repository.UpsertCVEs([]model.CVERecord{record}); err != nil {
		t.Fatal(err)
	}
	inventory := model.EndpointSoftwareInventory{CollectedAt: now, Items: []model.InstalledSoftware{{Name: "openssl", Version: "3.0.1", Source: "dpkg"}, {Name: "unmapped-package", Version: "1.0.0", Source: "dpkg"}}}
	if err := repository.RecordEndpointSoftwareInventory("endpoint-1", inventory, now); err != nil {
		t.Fatal(err)
	}
	matches, err := repository.EndpointCVEMatches("endpoint-1")
	if err != nil || len(matches) != 1 {
		t.Fatalf("endpoint CVE matches = %#v, error = %v", matches, err)
	}
	if matches[0].CVEID != record.ID || matches[0].Confidence != "medium" || matches[0].PackageSource != "dpkg" {
		t.Fatalf("endpoint CVE match = %#v", matches[0])
	}
}

func TestEndpointCVERefreshRemovesNoLongerAffectedVersion(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, err := repository.db.Exec(`INSERT INTO endpoints(id,name,status,certificate_serial,certificate_pem,enrolled_at,expires_at) VALUES('endpoint-1','Host','active','serial','cert',?,?)`, formatTime(now), formatTime(now.Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	record := model.CVERecord{ID: "CVE-TEST-1", Description: "test", PublishedAt: now, ModifiedAt: now, Severity: "high", SourceURL: "https://example.test/cve",
		Products: []model.AffectedProduct{{Vendor: "haxx", Product: "curl", VersionEndExcluding: "8.0.0", Vulnerable: true}}}
	if err := repository.UpsertCVEs([]model.CVERecord{record}); err != nil {
		t.Fatal(err)
	}
	inventory := model.EndpointSoftwareInventory{CollectedAt: now, Items: []model.InstalledSoftware{{Name: "curl", Version: "7.9.0", Source: "rpm"}}}
	if err := repository.RecordEndpointSoftwareInventory("endpoint-1", inventory, now); err != nil {
		t.Fatal(err)
	}
	inventory.Items[0].Version = "8.1.0"
	if err := repository.RecordEndpointSoftwareInventory("endpoint-1", inventory, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	matches, err := repository.EndpointCVEMatches("endpoint-1")
	if err != nil || len(matches) != 0 {
		t.Fatalf("stale endpoint CVE matches = %#v, error = %v", matches, err)
	}
}
