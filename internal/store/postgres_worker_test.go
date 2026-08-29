package store

import (
	"reflect"
	"testing"
	"time"

	"mossward/internal/model"
)

func TestPostgreSQLWorkerScopeRoundTrip(t *testing.T) {
	wantCIDRs := []string{"192.0.2.0/24", "2001:db8::/32"}
	wantPorts := []int{22, 443}
	cidrs, ports, err := encodePostgreSQLWorkerScope(wantCIDRs, wantPorts)
	if err != nil {
		t.Fatal(err)
	}
	var gotCIDRs []string
	var gotPorts []int
	if err := decodePostgreSQLWorkerScope(cidrs, ports, &gotCIDRs, &gotPorts); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotCIDRs, wantCIDRs) || !reflect.DeepEqual(gotPorts, wantPorts) {
		t.Fatalf("worker scope did not round-trip: CIDRs=%v ports=%v", gotCIDRs, gotPorts)
	}
}

func TestDecodePostgreSQLWorkerScopeRejectsMalformedJSON(t *testing.T) {
	var cidrs []string
	var ports []int
	if err := decodePostgreSQLWorkerScope("not-json", "[]", &cidrs, &ports); err == nil {
		t.Fatal("malformed worker scope was accepted")
	}
}

func TestPostgreSQLWorkerJobRoundTrip(t *testing.T) {
	want := model.SignedWorkerJob{
		Algorithm: "Ed25519",
		KeyID:     "worker-job-key",
		Job: model.WorkerJob{
			SchemaVersion: 1,
			ID:            "job-1",
			WorkerID:      "worker-1",
			ScanID:        "scan-1",
			IssuedAt:      time.Date(2026, time.August, 29, 1, 0, 0, 0, time.UTC),
			ExpiresAt:     time.Date(2026, time.August, 29, 2, 0, 0, 0, time.UTC),
			MaxConcurrent: 4,
			Status:        model.WorkerJobPending,
		},
		Signature: "signature",
	}
	encoded, err := encodePostgreSQLWorkerJob(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodePostgreSQLWorkerJob(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("worker job did not round-trip: %#v", got)
	}
}

func TestDecodePostgreSQLWorkerJobRejectsMalformedJSON(t *testing.T) {
	if _, err := decodePostgreSQLWorkerJob("not-json"); err == nil {
		t.Fatal("malformed worker job was accepted")
	}
}
