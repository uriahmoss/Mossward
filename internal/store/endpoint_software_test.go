package store

import (
	"testing"
	"time"

	"mossward/internal/model"
)

func TestEndpointSoftwareInventoryReplacesSnapshot(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, err := repository.db.Exec(`INSERT INTO endpoints(id,name,status,certificate_serial,certificate_pem,enrolled_at,expires_at) VALUES('endpoint-1','Host','active','serial','cert',?,?)`, formatTime(now), formatTime(now.Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	inventory := model.EndpointSoftwareInventory{CollectedAt: now, Items: []model.InstalledSoftware{{Name: "openssl", Version: "3.0.0", Architecture: "amd64", Source: "dpkg"}}}
	if err := repository.RecordEndpointSoftwareInventory("endpoint-1", inventory, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	stored, err := repository.EndpointSoftwareInventory("endpoint-1")
	if err != nil || len(stored.Items) != 1 || stored.Items[0].Name != "openssl" {
		t.Fatalf("software inventory = %#v, error = %v", stored, err)
	}
	inventory.Items = []model.InstalledSoftware{{Name: "curl", Version: "8.0.0", Source: "dpkg"}}
	if err := repository.RecordEndpointSoftwareInventory("endpoint-1", inventory, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	stored, err = repository.EndpointSoftwareInventory("endpoint-1")
	if err != nil || len(stored.Items) != 1 || stored.Items[0].Name != "curl" {
		t.Fatalf("replaced software inventory = %#v, error = %v", stored, err)
	}
}
