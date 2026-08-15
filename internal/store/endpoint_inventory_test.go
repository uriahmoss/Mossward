package store

import (
	"testing"
	"time"

	"mossward/internal/model"
)

func TestEndpointOSInventoryReplacesPatchSnapshot(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, err := repository.db.Exec(`INSERT INTO endpoints(id,name,status,certificate_serial,certificate_pem,enrolled_at,expires_at) VALUES('endpoint-1','Host','active','serial','cert',?,?)`, formatTime(now), formatTime(now.Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	installedAt := now.Add(-24 * time.Hour)
	inventory := model.EndpointOSInventory{Family: "linux", Name: "Example Linux", Version: "1", Build: "1.2", Kernel: "6.1.0", Architecture: "amd64", CollectedAt: now,
		Patches: []model.EndpointPatch{{ID: "kernel:6.1.0", Description: "Kernel patch level", InstalledAt: &installedAt}}}
	if err := repository.RecordEndpointOSInventory("endpoint-1", inventory, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	stored, err := repository.EndpointOSInventory("endpoint-1")
	if err != nil {
		t.Fatal(err)
	}
	if stored.EndpointID != "endpoint-1" || stored.Kernel != "6.1.0" || len(stored.Patches) != 1 || stored.Patches[0].InstalledAt == nil {
		t.Fatalf("stored OS inventory = %#v", stored)
	}
	inventory.Patches = []model.EndpointPatch{{ID: "kernel:6.1.1"}}
	if err := repository.RecordEndpointOSInventory("endpoint-1", inventory, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	stored, err = repository.EndpointOSInventory("endpoint-1")
	if err != nil || len(stored.Patches) != 1 || stored.Patches[0].ID != "kernel:6.1.1" {
		t.Fatalf("replaced OS inventory = %#v, error = %v", stored, err)
	}
}
