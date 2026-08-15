package store

import (
	"strings"
	"testing"
	"time"

	"mossward/internal/model"
)

func TestEndpointIntegrityBaselineEmitsOnlyChangedComponents(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, err := repository.db.Exec(`INSERT INTO endpoints(id,name,status,certificate_serial,certificate_pem,enrolled_at,expires_at) VALUES('endpoint','Endpoint','active','serial','cert',?,?)`, formatTime(now), formatTime(now.Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	hashA, hashB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	snapshot := model.AgentIntegritySnapshot{ExecutableSHA256: hashA, ConfigurationSHA256: hashA, IdentitySHA256: hashA, ObservedAt: now}
	if err := repository.RecordEndpointIntegritySnapshot("endpoint", snapshot, now); err != nil {
		t.Fatal(err)
	}
	events, err := repository.EndpointIntegrityEvents("endpoint")
	if err != nil || len(events) != 0 {
		t.Fatalf("baseline events = %#v, error = %v", events, err)
	}
	snapshot.ConfigurationSHA256 = hashB
	snapshot.ObservedAt = now.Add(time.Minute)
	if err := repository.RecordEndpointIntegritySnapshot("endpoint", snapshot, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	events, err = repository.EndpointIntegrityEvents("endpoint")
	if err != nil || len(events) != 1 || events[0].Component != "configuration" || events[0].PreviousSHA256 != hashA || events[0].CurrentSHA256 != hashB {
		t.Fatalf("change events = %#v, error = %v", events, err)
	}
}
