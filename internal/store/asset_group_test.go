package store

import (
	"testing"
	"time"

	"mossward/internal/model"
)

func TestReusablePolicyDeduplicatesOverlappingGroupTargets(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, err := repository.db.Exec(`INSERT INTO users(id,email,display_name,role,status,created_at,updated_at) VALUES('admin','admin@example.test','Admin','administrator','active',?,?)`, formatTime(now), formatTime(now))
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Save(completedAssetScan("scan", "observation", "pc1.example.test", "192.0.2.60", now)); err != nil {
		t.Fatal(err)
	}
	assets, _ := repository.ListAssets()
	event := model.AuditEvent{OccurredAt: now, ActorID: "admin", Action: "test", Severity: model.AuditInfo, Details: "{}"}
	for _, id := range []string{"group-1", "group-2"} {
		group := model.AssetGroup{ID: id, Name: id, CreatedAt: now, UpdatedAt: now}
		if err := repository.UpsertAssetGroup(group, event); err != nil {
			t.Fatal(err)
		}
		if err := repository.AddAssetGroupMember(id, assets[0].ID, "admin", now, event); err != nil {
			t.Fatal(err)
		}
	}
	scope := model.ScopePolicy{ID: "scope", Name: "Scope", AllowedCIDRs: []string{"192.0.2.0/24"}, AllowedPorts: []int{443}, MaxTargets: 10, MaxConcurrent: 2, Enabled: true, CreatedAt: now, UpdatedAt: now}
	if err := repository.EnsureDefaultScopePolicy(scope); err != nil {
		t.Fatal(err)
	}
	policy := model.ReusableScanPolicy{ID: "policy", Name: "Servers", ScopePolicyID: scope.ID, GroupIDs: []string{"group-1", "group-2"}, Ports: []int{443}, Enabled: true, CreatedAt: now, UpdatedAt: now, RateLimitPerSecond: 10, ExecutionMode: model.ScanExecutionRemote, WorkerSiteID: "chicago-hq"}
	if err := repository.UpsertReusableScanPolicy(policy, event); err != nil {
		t.Fatal(err)
	}
	storedPolicy, err := repository.ReusableScanPolicy(policy.ID)
	if err != nil || storedPolicy.RateLimitPerSecond != policy.RateLimitPerSecond || storedPolicy.ExecutionMode != policy.ExecutionMode || storedPolicy.WorkerSiteID != policy.WorkerSiteID {
		t.Fatalf("policy execution settings did not round-trip: %#v %v", storedPolicy, err)
	}
	targets, err := repository.ReusableScanPolicyTargets(policy.ID)
	if err != nil || len(targets) != 1 || len(targets[0].GroupIDs) != 2 {
		t.Fatalf("targets were not deduplicated with provenance: %#v %v", targets, err)
	}
	groups, err := repository.ListAssetGroups()
	if err != nil || len(groups) != 2 || len(groups[0].ScanPolicyIDs) != 1 {
		t.Fatalf("reverse policy visibility missing: %#v %v", groups, err)
	}
	completed := now.Add(time.Hour)
	windowEnd := completed.Add(time.Hour)
	policyScan := model.Scan{ID: "policy-scan", Name: policy.Name, Status: model.StatusCompleted, CreatedAt: now,
		CompletedAt: &completed, Targets: targets, Ports: policy.Ports, ScopePolicyID: scope.ID, ScanPolicyID: policy.ID,
		ActiveSeconds: 120, WindowEnd: &windowEnd, Checkpoints: []model.ScanCheckpoint{{Address: targets[0].Address, Port: 443, CompletedAt: completed}}}
	if err := repository.Save(policyScan); err != nil {
		t.Fatal(err)
	}
	loaded, err := repository.Get(policyScan.ID)
	if err != nil || loaded.ScanPolicyID != policy.ID || len(loaded.Targets) != 1 || len(loaded.Targets[0].GroupIDs) != 2 || len(loaded.Checkpoints) != 1 || loaded.ActiveSeconds != 120 {
		t.Fatalf("scan group provenance did not persist: %#v %v", loaded, err)
	}
}
