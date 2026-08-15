package store

import (
	"testing"
	"time"

	"mossward/internal/model"
)

func TestEndpointNetworkInventoryReplacesMetadataSnapshot(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, err := repository.db.Exec(`INSERT INTO endpoints(id,name,status,certificate_serial,certificate_pem,enrolled_at,expires_at) VALUES('endpoint-1','Host','active','serial','cert',?,?)`, formatTime(now), formatTime(now.Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	inventory := model.EndpointNetworkInventory{CollectedAt: now, Connections: []model.NetworkConnection{{Protocol: "tcp", LocalAddress: "10.0.0.2", LocalPort: 50000, RemoteAddress: "198.51.100.10", RemotePort: 443, ProcessID: 10, ProcessName: "client", Direction: "outbound_candidate"}}}
	if err := repository.RecordEndpointNetworkInventory("endpoint-1", inventory, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	stored, err := repository.EndpointNetworkInventory("endpoint-1")
	if err != nil || len(stored.Connections) != 1 || stored.Connections[0].RemotePort != 443 {
		t.Fatalf("network inventory = %#v, error = %v", stored, err)
	}
	inventory.Connections = nil
	if err := repository.RecordEndpointNetworkInventory("endpoint-1", inventory, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	stored, err = repository.EndpointNetworkInventory("endpoint-1")
	if err != nil || len(stored.Connections) != 0 {
		t.Fatalf("replaced network inventory = %#v, error = %v", stored, err)
	}
}
