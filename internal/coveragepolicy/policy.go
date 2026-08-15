package coveragepolicy

import (
	"errors"
	"net/netip"
	"strings"

	"mossward/internal/model"
)

const (
	maximumPolicyNameLength = 100
	maximumPolicyCIDRs      = 50
)

func Normalize(policy model.CoverageDiscoveryPolicy, allowedCIDRs []string) (model.CoverageDiscoveryPolicy, error) {
	policy.Name = strings.TrimSpace(policy.Name)
	if policy.Name == "" || len(policy.Name) > maximumPolicyNameLength {
		return policy, errors.New("coverage discovery policy name must be between 1 and 100 characters")
	}
	if len(policy.CIDRs) == 0 || len(policy.CIDRs) > maximumPolicyCIDRs {
		return policy, errors.New("coverage discovery policy must contain between 1 and 50 CIDRs")
	}
	allowed, err := parsePrefixes(allowedCIDRs)
	if err != nil {
		return policy, errors.New("server allowed CIDR configuration is invalid")
	}
	normalized := make([]string, 0, len(policy.CIDRs))
	seen := map[string]bool{}
	for _, raw := range policy.CIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return policy, errors.New("coverage discovery policy contains an invalid CIDR")
		}
		prefix = prefix.Masked()
		if !withinAllowedScope(prefix, allowed) {
			return policy, errors.New("coverage discovery policy exceeds the server allowed CIDR scope")
		}
		value := prefix.String()
		if seen[value] {
			return policy, errors.New("coverage discovery policy contains a duplicate CIDR")
		}
		seen[value] = true
		normalized = append(normalized, value)
	}
	policy.CIDRs = normalized
	return policy, nil
}

func parsePrefixes(values []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}

func withinAllowedScope(candidate netip.Prefix, allowed []netip.Prefix) bool {
	for _, boundary := range allowed {
		if candidate.Addr().BitLen() == boundary.Addr().BitLen() && candidate.Bits() >= boundary.Bits() && boundary.Contains(candidate.Addr()) {
			return true
		}
	}
	return false
}
