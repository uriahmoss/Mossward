package store

import (
	"testing"
	"time"

	"mossward/internal/model"
)

func TestDelayedHeartbeatPolicyInheritanceConflictAndEndpointOverride(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := repository.db.Exec(`INSERT INTO users(id,email,display_name,role,status,created_at,updated_at) VALUES('admin','admin@example.test','Admin','administrator','active',?,?)`, formatTime(now), formatTime(now)); err != nil {
		t.Fatal(err)
	}
	if err := repository.Save(completedAssetScan("scan", "observation", "endpoint.example.test", "192.0.2.62", now)); err != nil {
		t.Fatal(err)
	}
	assets, err := repository.ListAssets()
	if err != nil || len(assets) != 1 {
		t.Fatalf("test assets = %#v, error = %v", assets, err)
	}
	if _, err := repository.db.Exec(`INSERT INTO endpoints(id,name,status,certificate_serial,certificate_pem,enrolled_at,expires_at,asset_id) VALUES('endpoint','Endpoint','active','serial','cert',?,?,?)`, formatTime(now), formatTime(now.Add(time.Hour)), assets[0].ID); err != nil {
		t.Fatal(err)
	}
	event := model.AuditEvent{OccurredAt: now, ActorID: "admin", Action: "endpoint.delayed_heartbeat_policy.updated", Severity: model.AuditWarning, Details: "{}"}
	for index, allow := range []bool{true, false} {
		group := model.AssetGroup{ID: "group-" + string(rune('a'+index)), Name: "Group " + string(rune('A'+index)), CreatedAt: now, UpdatedAt: now}
		if err := repository.UpsertAssetGroup(group, event); err != nil {
			t.Fatal(err)
		}
		if err := repository.AddAssetGroupMember(group.ID, assets[0].ID, "admin", now, event); err != nil {
			t.Fatal(err)
		}
		policy := model.DelayedHeartbeatPolicy{TargetType: model.MaintenanceTargetGroup, TargetID: group.ID,
			AllowDelayedHeartbeats: allow, Reason: "test group policy", UpdatedBy: "admin", UpdatedAt: now}
		event.TargetType, event.TargetID = string(policy.TargetType), policy.TargetID
		if err := repository.UpsertDelayedHeartbeatPolicy(policy, event); err != nil {
			t.Fatal(err)
		}
	}
	resolved, err := repository.ResolveDelayedHeartbeatPolicy("endpoint")
	if err != nil || resolved.AllowDelayedHeartbeats || !resolved.Conflict || resolved.Source != "group_conflict_deny" {
		t.Fatalf("group conflict policy = %#v, error = %v", resolved, err)
	}
	override := model.DelayedHeartbeatPolicy{TargetType: model.MaintenanceTargetEndpoint, TargetID: "endpoint",
		AllowDelayedHeartbeats: true, PostWindowGraceMinutes: 15, Reason: "explicit endpoint override", UpdatedBy: "admin", UpdatedAt: now.Add(time.Minute)}
	event.TargetType, event.TargetID = string(override.TargetType), override.TargetID
	if err := repository.UpsertDelayedHeartbeatPolicy(override, event); err != nil {
		t.Fatal(err)
	}
	resolved, err = repository.ResolveDelayedHeartbeatPolicy("endpoint")
	if err != nil || !resolved.AllowDelayedHeartbeats || resolved.PostWindowGraceMinutes != 15 || resolved.Source != "endpoint_override" || resolved.Conflict {
		t.Fatalf("endpoint override policy = %#v, error = %v", resolved, err)
	}
	event.Action = "endpoint.delayed_heartbeat_policy.removed"
	if err := repository.DeleteDelayedHeartbeatPolicy(model.MaintenanceTargetEndpoint, "endpoint", event); err != nil {
		t.Fatal(err)
	}
	resolved, err = repository.ResolveDelayedHeartbeatPolicy("endpoint")
	if err != nil || resolved.AllowDelayedHeartbeats || !resolved.Conflict {
		t.Fatalf("restored inherited policy = %#v, error = %v", resolved, err)
	}
}
