package networkpolicy

import (
	"testing"

	"mossward/internal/model"
)

func TestNormalizeAndFilterNetworkExclusions(t *testing.T) {
	policy, err := Normalize(model.NetworkTelemetryExclusions{
		Applications: []model.NetworkTelemetryExclusion{{Kind: model.NetworkExcludeProcessName, Value: " Browser "}},
		Destinations: []model.NetworkTelemetryExclusion{{Kind: model.NetworkExcludeCIDR, Value: "192.0.2.9/24"}, {Kind: model.NetworkExcludeHostname, Value: "Private.Example.Test."}},
	})
	if err != nil {
		t.Fatal(err)
	}
	connections := []model.NetworkConnection{
		{ProcessName: "browser", RemoteAddress: "198.51.100.1"},
		{ProcessName: "client", RemoteAddress: "192.0.2.20"},
		{ProcessName: "client", RemoteAddress: "198.51.100.2", RemoteHostname: "private.example.test"},
		{ProcessName: "client", RemoteAddress: "198.51.100.3", RemoteHostname: "public.example.test"},
	}
	filtered := Filter(connections, policy)
	if len(filtered) != 1 || filtered[0].RemoteAddress != "198.51.100.3" || policy.Destinations[0].Value != "192.0.2.0/24" {
		t.Fatalf("filtered connections = %#v, policy = %#v", filtered, policy)
	}
}

func TestNormalizeRejectsWildcardHostnameAndDuplicate(t *testing.T) {
	for _, policy := range []model.NetworkTelemetryExclusions{
		{Destinations: []model.NetworkTelemetryExclusion{{Kind: model.NetworkExcludeHostname, Value: "*.example.test"}}},
		{Applications: []model.NetworkTelemetryExclusion{{Kind: model.NetworkExcludeProcessName, Value: "app"}, {Kind: model.NetworkExcludeProcessName, Value: "app"}}},
	} {
		if _, err := Normalize(policy); err == nil {
			t.Fatalf("accepted invalid policy %#v", policy)
		}
	}
}
