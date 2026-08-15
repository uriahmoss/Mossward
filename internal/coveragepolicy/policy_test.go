package coveragepolicy

import (
	"testing"

	"mossward/internal/model"
)

func TestNormalizeRequiresPolicyWithinGlobalScope(t *testing.T) {
	policy := model.CoverageDiscoveryPolicy{Name: " Office ", CIDRs: []string{"10.20.30.9/28"}, Enabled: true}
	normalized, err := Normalize(policy, []string{"10.20.30.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if normalized.Name != "Office" || normalized.CIDRs[0] != "10.20.30.0/28" {
		t.Fatalf("normalized policy = %#v", normalized)
	}
	policy.CIDRs = []string{"10.20.0.0/16"}
	if _, err := Normalize(policy, []string{"10.20.30.0/24"}); err == nil {
		t.Fatal("accepted a discovery policy broader than global scope")
	}
}

func TestNormalizeRejectsDuplicateOrMissingCIDRs(t *testing.T) {
	for _, cidrs := range [][]string{nil, {"192.0.2.0/24", "192.0.2.1/24"}} {
		policy := model.CoverageDiscoveryPolicy{Name: "Office", CIDRs: cidrs}
		if _, err := Normalize(policy, []string{"192.0.2.0/24"}); err == nil {
			t.Fatalf("accepted invalid CIDRs %#v", cidrs)
		}
	}
}
