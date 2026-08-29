package store

import (
	"reflect"
	"testing"
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
