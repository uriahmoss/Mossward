package store

import (
	"testing"
	"time"

	"mossward/internal/model"
)

func TestEndpointPostureInventoryPreservesExplicitUnknown(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, err := repository.db.Exec(`INSERT INTO endpoints(id,name,status,certificate_serial,certificate_pem,enrolled_at,expires_at) VALUES('endpoint-1','Host','active','serial','cert',?,?)`, formatTime(now), formatTime(now.Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	inventory := model.EndpointPostureInventory{CollectedAt: now, Evidence: []model.PostureEvidence{{ID: "secure_boot", Title: "Secure Boot", Status: "unknown", Detail: "State unavailable"}}}
	if err := repository.RecordEndpointPostureInventory("endpoint-1", inventory, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	stored, err := repository.EndpointPostureInventory("endpoint-1")
	if err != nil || len(stored.Evidence) != 1 || stored.Evidence[0].Status != "unknown" {
		t.Fatalf("posture inventory = %#v, error = %v", stored, err)
	}
}
