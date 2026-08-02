package api

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"mossward/internal/model"
	"mossward/internal/scanner"
	"mossward/internal/scheduling"
)

const maximumPolicyChecksPerSecond = 1000

const groupTextLimit = 500

func (a *API) registerAssetGroupRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/asset-groups", a.listAssetGroups)
	mux.HandleFunc("POST /api/admin/asset-groups", a.saveAssetGroup)
	mux.HandleFunc("PUT /api/admin/asset-groups/{id}", a.saveAssetGroup)
	mux.HandleFunc("POST /api/admin/asset-groups/{id}/members/{asset}", a.addAssetGroupMember)
	mux.HandleFunc("DELETE /api/admin/asset-groups/{id}/members/{asset}", a.removeAssetGroupMember)
	mux.HandleFunc("GET /api/scan-policies", a.listReusableScanPolicies)
	mux.HandleFunc("POST /api/admin/scan-policies", a.saveReusableScanPolicy)
	mux.HandleFunc("PUT /api/admin/scan-policies/{id}", a.saveReusableScanPolicy)
	mux.HandleFunc("POST /api/scan-policies/{id}/run", a.runReusableScanPolicy)
}

func (a *API) listAssetGroups(w http.ResponseWriter, _ *http.Request) {
	groups, err := a.store.ListAssetGroups()
	if err != nil {
		writeError(w, 500, "could not list asset groups")
		return
	}
	writeJSON(w, 200, groups)
}

func (a *API) saveAssetGroup(w http.ResponseWriter, r *http.Request) {
	actor, _, ok := a.requireAdministratorWithRecentMFA(w, r)
	if !ok {
		return
	}
	var group model.AssetGroup
	if !decodeJSON(w, r, &group) {
		return
	}
	group.Name, group.Description = strings.TrimSpace(group.Name), strings.TrimSpace(group.Description)
	if group.Name == "" || len(group.Name) > 200 || len(group.Description) > groupTextLimit {
		writeError(w, 400, "group name and description are invalid")
		return
	}
	now := time.Now().UTC()
	group.ID = r.PathValue("id")
	if group.ID == "" {
		var err error
		group.ID, err = randomID()
		if err != nil {
			writeError(w, 500, "could not create group")
			return
		}
		group.CreatedAt = now
	} else {
		groups, _ := a.store.ListAssetGroups()
		for _, current := range groups {
			if current.ID == group.ID {
				group.CreatedAt = current.CreatedAt
			}
		}
	}
	if group.CreatedAt.IsZero() {
		group.CreatedAt = now
	}
	group.UpdatedAt = now
	event := model.AuditEvent{OccurredAt: now, ActorID: actor.ID, Action: "asset.group.saved", Severity: model.AuditWarning, TargetType: "asset_group", TargetID: group.ID, SourceIP: requestIP(r), Details: "{}"}
	if err := a.store.UpsertAssetGroup(group, event); err != nil {
		writeError(w, 400, "could not save asset group")
		return
	}
	writeJSON(w, 200, group)
}

func (a *API) addAssetGroupMember(w http.ResponseWriter, r *http.Request) {
	actor, _, ok := a.requireAdministratorWithRecentMFA(w, r)
	if !ok {
		return
	}
	var request struct {
		AcknowledgeOverlap bool `json:"acknowledge_overlap"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	memberships, err := a.store.AssetGroupMemberships(r.PathValue("asset"))
	if err != nil {
		writeError(w, 500, "could not inspect group memberships")
		return
	}
	overlaps := []string{}
	for _, id := range memberships {
		if id != r.PathValue("id") {
			overlaps = append(overlaps, id)
		}
	}
	if overlapRequiresAcknowledgement(overlaps, request.AcknowledgeOverlap) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "asset already belongs to other groups; explicit authorization required", "existing_group_ids": overlaps})
		return
	}
	now := time.Now().UTC()
	event := model.AuditEvent{OccurredAt: now, ActorID: actor.ID, Action: "asset.group.member.added", Severity: model.AuditWarning, TargetType: "asset_group", TargetID: r.PathValue("id"), SourceIP: requestIP(r), Details: "{}"}
	if err := a.store.AddAssetGroupMember(r.PathValue("id"), r.PathValue("asset"), actor.ID, now, event); err != nil {
		writeError(w, 400, "could not add group member")
		return
	}
	w.WriteHeader(204)
}

func overlapRequiresAcknowledgement(overlaps []string, acknowledged bool) bool {
	return len(overlaps) > 0 && !acknowledged
}

func (a *API) removeAssetGroupMember(w http.ResponseWriter, r *http.Request) {
	actor, _, ok := a.requireAdministratorWithRecentMFA(w, r)
	if !ok {
		return
	}
	now := time.Now().UTC()
	event := model.AuditEvent{OccurredAt: now, ActorID: actor.ID, Action: "asset.group.member.removed", Severity: model.AuditWarning, TargetType: "asset_group", TargetID: r.PathValue("id"), SourceIP: requestIP(r), Details: "{}"}
	if err := a.store.RemoveAssetGroupMember(r.PathValue("id"), r.PathValue("asset"), event); err != nil {
		writeError(w, 404, "group membership not found")
		return
	}
	w.WriteHeader(204)
}

func (a *API) listReusableScanPolicies(w http.ResponseWriter, r *http.Request) {
	user, ok := a.currentUser(r)
	if !ok {
		writeError(w, 401, "authentication required")
		return
	}
	items, err := a.store.ListReusableScanPolicies(user.Role != model.RoleAdministrator)
	if err != nil {
		writeError(w, 500, "could not list scan policies")
		return
	}
	writeJSON(w, 200, items)
}

func (a *API) saveReusableScanPolicy(w http.ResponseWriter, r *http.Request) {
	actor, _, ok := a.requireAdministratorWithRecentMFA(w, r)
	if !ok {
		return
	}
	var policy model.ReusableScanPolicy
	if !decodeJSON(w, r, &policy) {
		return
	}
	policy.ID = r.PathValue("id")
	if err := a.prepareReusableScanPolicy(&policy); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	now := time.Now().UTC()
	if policy.ID == "" {
		var idErr error
		policy.ID, idErr = randomID()
		if idErr != nil {
			writeError(w, http.StatusInternalServerError, "could not create scan policy")
			return
		}
		policy.CreatedAt = now
	} else if current, err := a.store.ReusableScanPolicy(policy.ID); err == nil {
		policy.CreatedAt = current.CreatedAt
	} else {
		policy.CreatedAt = now
	}
	policy.UpdatedAt = now
	event := model.AuditEvent{OccurredAt: now, ActorID: actor.ID, Action: "scanner.reusable_policy.saved", Severity: model.AuditWarning, TargetType: "scan_policy", TargetID: policy.ID, SourceIP: requestIP(r), Details: "{}"}
	if err := a.store.UpsertReusableScanPolicy(policy, event); err != nil {
		writeError(w, 400, "could not save scan policy")
		return
	}
	writeJSON(w, 200, policy)
}

func (a *API) prepareReusableScanPolicy(policy *model.ReusableScanPolicy) error {
	policy.Name = strings.TrimSpace(policy.Name)
	if policy.Name == "" || len(policy.Name) > 200 {
		return errors.New("scan policy name is invalid")
	}
	if len(policy.GroupIDs) == 0 {
		return errors.New("select at least one asset group")
	}
	if policy.RateLimitPerSecond < 0 || policy.RateLimitPerSecond > maximumPolicyChecksPerSecond {
		return fmt.Errorf("rate limit must be between 0 and %d checks per second", maximumPolicyChecksPerSecond)
	}
	scope, err := a.store.ScopePolicy(policy.ScopePolicyID)
	if err != nil || !scope.Enabled {
		return errors.New("authorization scope policy is unavailable")
	}
	allowed := map[int]bool{}
	for _, port := range scope.AllowedPorts {
		allowed[port] = true
	}
	ports := map[int]bool{}
	for _, port := range policy.Ports {
		if !allowed[port] {
			return errors.New("scan policy contains a port outside its authorization scope")
		}
		ports[port] = true
	}
	if len(ports) == 0 {
		return errors.New("select at least one port")
	}
	policy.Ports = policy.Ports[:0]
	for port := range ports {
		policy.Ports = append(policy.Ports, port)
	}
	sort.Ints(policy.Ports)
	policy.GroupIDs = uniqueStrings(policy.GroupIDs)
	return scheduling.Prepare(policy, time.Now().UTC())
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	result := []string{}
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}

func (a *API) runReusableScanPolicy(w http.ResponseWriter, r *http.Request) {
	user, ok := a.currentUser(r)
	if !ok {
		writeError(w, 401, "authentication required")
		return
	}
	if user.Role == model.RoleViewer {
		writeError(w, 403, "analyst or administrator role required")
		return
	}
	policy, err := a.store.ReusableScanPolicy(r.PathValue("id"))
	if err != nil || !policy.Enabled {
		writeError(w, 404, "scan policy not found")
		return
	}
	now := time.Now().UTC()
	insideWindow, windowEnd, err := scheduling.Window(policy, now)
	if err != nil || !insideWindow {
		writeError(w, http.StatusConflict, "scan policy is outside its maintenance window")
		return
	}
	sourceTargets, err := a.store.ReusableScanPolicyTargets(policy.ID)
	if err != nil || len(sourceTargets) == 0 {
		writeError(w, 400, "scan policy has no target addresses")
		return
	}
	scope, err := a.requestScopePolicy(policy.ScopePolicyID)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	raw := make([]string, 0, len(sourceTargets))
	provenance := map[string]model.Target{}
	for _, target := range sourceTargets {
		raw = append(raw, target.Address)
		provenance[target.Address] = target
	}
	targets, ports, err := a.scanner.ValidateWithPolicy(model.CreateScanRequest{Targets: raw, Ports: policy.Ports}, scope)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	for index := range targets {
		if source, ok := provenance[targets[index].Address]; ok {
			targets[index].Name = source.Name
			targets[index].GroupIDs = source.GroupIDs
		}
	}
	scanID, err := randomID()
	if err != nil {
		writeError(w, 500, "could not create scan")
		return
	}
	scan := model.Scan{ID: scanID, Name: policy.Name, Targets: targets, Ports: ports, Status: model.StatusQueued, Observations: []model.ServiceObservation{}, Findings: []model.Finding{}, CVEMatches: []model.CVEMatch{}, TotalChecks: len(targets) * len(ports), CreatedAt: now, ScopePolicyID: scope.ID, MaxConcurrent: scope.MaxConcurrent, ScanPolicyID: policy.ID, WindowEnd: windowEnd, RateLimitPerSecond: policy.RateLimitPerSecond}
	if err := a.scanner.Schedule(scan); errors.Is(err, scanner.ErrQueueFull) {
		writeError(w, 503, err.Error())
		return
	} else if err != nil {
		writeError(w, 500, "could not schedule scan")
		return
	}
	writeJSON(w, 202, scan)
}
