package relayheartbeat

import (
	"testing"

	"mossward/internal/model"
)

func TestResolveDefaultsDeniedAndEndpointOverridesGroups(t *testing.T) {
	resolved := Resolve("endpoint", nil)
	if resolved.AllowDelayedHeartbeats || resolved.Source != "default_deny" {
		t.Fatalf("default delayed-heartbeat policy = %#v", resolved)
	}
	policies := []model.DelayedHeartbeatPolicy{
		{TargetType: model.MaintenanceTargetGroup, TargetID: "group", AllowDelayedHeartbeats: false},
		{TargetType: model.MaintenanceTargetEndpoint, TargetID: "endpoint", AllowDelayedHeartbeats: true},
	}
	resolved = Resolve("endpoint", policies)
	if !resolved.AllowDelayedHeartbeats || resolved.Source != "endpoint_override" || resolved.Conflict {
		t.Fatalf("endpoint override = %#v", resolved)
	}
}

func TestResolveOverlappingGroupConflictDenies(t *testing.T) {
	policies := []model.DelayedHeartbeatPolicy{
		{TargetType: model.MaintenanceTargetGroup, TargetID: "allow", AllowDelayedHeartbeats: true},
		{TargetType: model.MaintenanceTargetGroup, TargetID: "deny", AllowDelayedHeartbeats: false},
	}
	resolved := Resolve("endpoint", policies)
	if resolved.AllowDelayedHeartbeats || resolved.Source != "group_conflict_deny" || !resolved.Conflict || len(resolved.SourceIDs) != 2 {
		t.Fatalf("overlapping group resolution = %#v", resolved)
	}
}

func TestResolveAmbiguousEndpointOverridesDeny(t *testing.T) {
	policies := []model.DelayedHeartbeatPolicy{
		{TargetType: model.MaintenanceTargetEndpoint, TargetID: "endpoint", AllowDelayedHeartbeats: true},
		{TargetType: model.MaintenanceTargetEndpoint, TargetID: "endpoint", AllowDelayedHeartbeats: false},
	}
	resolved := Resolve("endpoint", policies)
	if resolved.AllowDelayedHeartbeats || resolved.Source != "endpoint_conflict_deny" || !resolved.Conflict {
		t.Fatalf("ambiguous endpoint overrides = %#v", resolved)
	}
}
