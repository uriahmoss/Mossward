package relayheartbeat

import (
	"errors"
	"sort"
	"strings"

	"mossward/internal/model"
)

const (
	maximumPolicyReasonLength = 500
	maximumPolicyTargetLength = 200
	maximumPostWindowGrace    = 24 * 60
)

func Validate(policy model.DelayedHeartbeatPolicy) error {
	if (policy.TargetType != model.MaintenanceTargetEndpoint && policy.TargetType != model.MaintenanceTargetGroup) ||
		strings.TrimSpace(policy.TargetID) == "" || len(policy.TargetID) > maximumPolicyTargetLength || strings.TrimSpace(policy.Reason) == "" || len(policy.Reason) > maximumPolicyReasonLength ||
		policy.PostWindowGraceMinutes < 0 || policy.PostWindowGraceMinutes > maximumPostWindowGrace {
		return errors.New("delayed-heartbeat policy is invalid")
	}
	if !policy.AllowDelayedHeartbeats && policy.PostWindowGraceMinutes != 0 {
		return errors.New("disabled delayed-heartbeat policy cannot define a grace period")
	}
	return nil
}

func Resolve(endpointID string, policies []model.DelayedHeartbeatPolicy) model.ResolvedDelayedHeartbeatPolicy {
	result := model.ResolvedDelayedHeartbeatPolicy{EndpointID: endpointID, Source: "default_deny", SourceIDs: []string{}}
	groups := make([]model.DelayedHeartbeatPolicy, 0, len(policies))
	endpointPolicies := []model.DelayedHeartbeatPolicy{}
	for _, policy := range policies {
		if policy.TargetType == model.MaintenanceTargetEndpoint && policy.TargetID == endpointID {
			endpointPolicies = append(endpointPolicies, policy)
			continue
		}
		if policy.TargetType == model.MaintenanceTargetGroup {
			groups = append(groups, policy)
		}
	}
	if len(endpointPolicies) > 1 {
		result.Source, result.SourceIDs, result.Conflict = "endpoint_conflict_deny", []string{endpointID}, true
		return result
	}
	if len(endpointPolicies) == 1 {
		result.AllowDelayedHeartbeats = endpointPolicies[0].AllowDelayedHeartbeats
		if result.AllowDelayedHeartbeats {
			result.PostWindowGraceMinutes = endpointPolicies[0].PostWindowGraceMinutes
		}
		result.Source, result.SourceIDs = "endpoint_override", []string{endpointID}
		return result
	}
	if len(groups) == 0 {
		return result
	}
	result.AllowDelayedHeartbeats, result.Source = true, "group_inheritance"
	result.PostWindowGraceMinutes = maximumPostWindowGrace
	seenAllow, seenDeny := false, false
	for _, group := range groups {
		result.SourceIDs = append(result.SourceIDs, group.TargetID)
		if group.AllowDelayedHeartbeats {
			seenAllow = true
			if group.PostWindowGraceMinutes < result.PostWindowGraceMinutes {
				result.PostWindowGraceMinutes = group.PostWindowGraceMinutes
			}
			continue
		}
		seenDeny = true
		result.AllowDelayedHeartbeats = false
		result.PostWindowGraceMinutes = 0
	}
	sort.Strings(result.SourceIDs)
	if seenAllow && seenDeny {
		result.Source, result.Conflict = "group_conflict_deny", true
	}
	return result
}
