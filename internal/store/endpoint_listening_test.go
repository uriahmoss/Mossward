package store

import (
	"testing"
	"time"

	"mossward/internal/model"
)

func TestEndpointListeningInventoryReplacesSnapshot(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, err := repository.db.Exec(`INSERT INTO endpoints(id,name,status,certificate_serial,certificate_pem,enrolled_at,expires_at) VALUES('endpoint-1','Host','active','serial','cert',?,?)`, formatTime(now), formatTime(now.Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	inventory := model.EndpointListeningInventory{CollectedAt: now, Services: []model.ListeningService{{Protocol: "tcp", Address: "0.0.0.0", Port: 443, ProcessID: 10, ProcessName: "server"}}}
	if err := repository.RecordEndpointListeningInventory("endpoint-1", inventory, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	stored, err := repository.EndpointListeningInventory("endpoint-1")
	if err != nil || len(stored.Services) != 1 || stored.Services[0].ProcessName != "server" {
		t.Fatalf("listening inventory = %#v, error = %v", stored, err)
	}
	inventory.Services = []model.ListeningService{{Protocol: "udp", Address: "::", Port: 53, ProcessID: 20, ProcessName: "dns"}}
	if err := repository.RecordEndpointListeningInventory("endpoint-1", inventory, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	stored, err = repository.EndpointListeningInventory("endpoint-1")
	if err != nil || len(stored.Services) != 1 || stored.Services[0].Port != 53 {
		t.Fatalf("replaced listening inventory = %#v, error = %v", stored, err)
	}
}
