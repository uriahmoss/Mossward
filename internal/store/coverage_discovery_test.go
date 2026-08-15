package store

import (
	"errors"
	"testing"
	"time"

	"mossward/internal/model"
)

func TestCoverageDiscoveryPolicyPersistsAndAuditsChanges(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	policy := model.CoverageDiscoveryPolicy{ID: "office", Name: "Office", CIDRs: []string{"192.0.2.0/24"}, Enabled: false,
		CreatedBy: "admin", CreatedAt: now, UpdatedBy: "admin", UpdatedAt: now}
	event := model.AuditEvent{OccurredAt: now, Action: "endpoint.coverage_discovery_policy.saved", Severity: model.AuditInfo, TargetType: "coverage_discovery_policy", TargetID: policy.ID}
	if err := repository.SaveCoverageDiscoveryPolicy(policy, event); err != nil {
		t.Fatal(err)
	}
	policy.Enabled = true
	policy.CreatedBy = ""
	policy.CreatedAt = time.Time{}
	policy.UpdatedAt = now.Add(time.Minute)
	if err := repository.SaveCoverageDiscoveryPolicy(policy, event); err != nil {
		t.Fatal(err)
	}
	policies, err := repository.ListCoverageDiscoveryPolicies()
	if err != nil || len(policies) != 1 || !policies[0].Enabled || policies[0].CreatedBy != "admin" {
		t.Fatalf("policies = %#v, error = %v", policies, err)
	}
	policy.ID = "missing"
	if err := repository.SaveCoverageDiscoveryPolicy(policy, event); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing policy update error = %v", err)
	}
	var count int
	if err := repository.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE action='endpoint.coverage_discovery_policy.saved'`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("policy audit count = %d, error = %v", count, err)
	}
}
