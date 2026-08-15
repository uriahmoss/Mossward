package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"mossward/internal/coveragepolicy"
	"mossward/internal/model"
	"mossward/internal/store"
)

func (a *API) registerAgentIdentityRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/admin/endpoints", a.listEndpoints)
	mux.HandleFunc("GET /api/admin/agent-enrollment-tokens", a.listAgentEnrollmentTokens)
	mux.HandleFunc("POST /api/admin/agent-enrollment-tokens", a.createAgentEnrollmentToken)
	mux.HandleFunc("POST /api/agent/enroll", a.enrollAgent)
	mux.HandleFunc("POST /api/admin/endpoints/{id}/revoke", a.revokeEndpoint)
	mux.HandleFunc("PUT /api/admin/endpoints/{id}/collectors", a.updateEndpointCollectors)
	mux.HandleFunc("PUT /api/admin/endpoints/{id}/network-exclusions", a.updateEndpointNetworkExclusions)
	mux.HandleFunc("GET /api/admin/endpoint-coverage", a.getEndpointCoverage)
	mux.HandleFunc("PUT /api/admin/endpoint-coverage/settings", a.updateEndpointCoverageSettings)
	mux.HandleFunc("GET /api/admin/endpoint-coverage/discovery-policies", a.listCoverageDiscoveryPolicies)
	mux.HandleFunc("POST /api/admin/endpoint-coverage/discovery-policies", a.createCoverageDiscoveryPolicy)
	mux.HandleFunc("PUT /api/admin/endpoint-coverage/discovery-policies/{id}", a.updateCoverageDiscoveryPolicy)
	mux.HandleFunc("GET /api/admin/endpoints/{id}/os-inventory", a.getEndpointOSInventory)
	mux.HandleFunc("GET /api/admin/endpoints/{id}/software-inventory", a.getEndpointSoftwareInventory)
	mux.HandleFunc("GET /api/admin/endpoints/{id}/listening-inventory", a.getEndpointListeningInventory)
	mux.HandleFunc("GET /api/admin/endpoints/{id}/posture-inventory", a.getEndpointPostureInventory)
	mux.HandleFunc("GET /api/admin/endpoints/{id}/cves", a.getEndpointCVEMatches)
	mux.HandleFunc("GET /api/admin/endpoints/{id}/network-inventory", a.getEndpointNetworkInventory)
	mux.HandleFunc("GET /api/admin/endpoints/{id}/indicator-matches", a.getEndpointIndicatorMatches)
	mux.HandleFunc("GET /api/admin/threat-indicators", a.listThreatIndicators)
	mux.HandleFunc("POST /api/admin/threat-indicators", a.createThreatIndicator)
	mux.HandleFunc("PUT /api/admin/threat-indicators/{id}", a.updateThreatIndicator)
	mux.HandleFunc("GET /api/admin/scanner-workers", a.listScannerWorkers)
	mux.HandleFunc("GET /api/admin/scanner-worker-dispatch", a.scannerWorkerDispatchSettings)
	mux.HandleFunc("PUT /api/admin/scanner-worker-dispatch", a.updateScannerWorkerDispatch)
	mux.HandleFunc("PUT /api/admin/scanner-workers/{id}/dispatch", a.updateScannerWorkerDispatchForWorker)
	mux.HandleFunc("POST /api/admin/scanner-worker-enrollment-tokens", a.createScannerWorkerEnrollmentToken)
	mux.HandleFunc("POST /api/scanner-workers/enroll", a.enrollScannerWorker)
	mux.HandleFunc("POST /api/admin/scanner-workers/{id}/revoke", a.revokeScannerWorker)
}

func (a *API) listCoverageDiscoveryPolicies(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdministrator(w, r); !ok {
		return
	}
	policies, err := a.store.ListCoverageDiscoveryPolicies()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list coverage discovery policies")
		return
	}
	writeJSON(w, http.StatusOK, policies)
}

func (a *API) createCoverageDiscoveryPolicy(w http.ResponseWriter, r *http.Request) {
	a.saveCoverageDiscoveryPolicy(w, r, "")
}

func (a *API) updateCoverageDiscoveryPolicy(w http.ResponseWriter, r *http.Request) {
	a.saveCoverageDiscoveryPolicy(w, r, r.PathValue("id"))
}

func (a *API) saveCoverageDiscoveryPolicy(w http.ResponseWriter, r *http.Request, id string) {
	actor, _, ok := a.requireAdministratorWithRecentMFA(w, r)
	if !ok {
		return
	}
	var policy model.CoverageDiscoveryPolicy
	if !decodeJSON(w, r, &policy) {
		return
	}
	policy.ID = id
	normalized, err := coveragepolicy.Normalize(policy, a.cfg.AllowedCIDRs)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	now := time.Now().UTC()
	if normalized.ID == "" {
		normalized.ID, err = randomID()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not create coverage discovery policy")
			return
		}
		normalized.CreatedBy = actor.ID
		normalized.CreatedAt = now
	}
	normalized.UpdatedBy = actor.ID
	normalized.UpdatedAt = now
	details, _ := json.Marshal(map[string]any{"enabled": normalized.Enabled, "cidr_count": len(normalized.CIDRs)})
	event := model.AuditEvent{OccurredAt: now, ActorID: actor.ID, Action: "endpoint.coverage_discovery_policy.saved", Severity: model.AuditInfo,
		TargetType: "coverage_discovery_policy", TargetID: normalized.ID, SourceIP: requestIP(r), Details: string(details)}
	if err := a.store.SaveCoverageDiscoveryPolicy(normalized, event); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "coverage discovery policy not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not save coverage discovery policy")
		return
	}
	status := http.StatusOK
	if id == "" {
		status = http.StatusCreated
	}
	writeJSON(w, status, normalized)
}

func (a *API) getEndpointCoverage(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdministrator(w, r); !ok {
		return
	}
	report, err := a.store.EndpointCoverageReport(time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not evaluate endpoint coverage")
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (a *API) updateEndpointCoverageSettings(w http.ResponseWriter, r *http.Request) {
	actor, _, ok := a.requireAdministratorWithRecentMFA(w, r)
	if !ok {
		return
	}
	var settings model.EndpointCoverageSettings
	if !decodeJSON(w, r, &settings) {
		return
	}
	now := time.Now().UTC()
	settings.UpdatedBy = actor.ID
	settings.UpdatedAt = now
	event := model.AuditEvent{OccurredAt: now, ActorID: actor.ID, Action: "endpoint.coverage.updated", Severity: model.AuditInfo,
		TargetType: "endpoint_coverage", TargetID: "global", SourceIP: requestIP(r), Details: "{}"}
	if err := a.store.SetEndpointCoverageSettings(settings, event); err != nil {
		writeError(w, http.StatusInternalServerError, "could not update endpoint coverage")
		return
	}
	writeJSON(w, http.StatusOK, settings)
}

func (a *API) updateEndpointNetworkExclusions(w http.ResponseWriter, r *http.Request) {
	actor, _, ok := a.requireAdministratorWithRecentMFA(w, r)
	if !ok || !a.requireAgentIdentity(w) {
		return
	}
	var exclusions model.NetworkTelemetryExclusions
	if !decodeJSON(w, r, &exclusions) {
		return
	}
	err := a.agentIdentity.SetEndpointNetworkExclusions(r.PathValue("id"), exclusions, actor.ID, requestIP(r))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "active endpoint not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) listThreatIndicators(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdministrator(w, r); !ok || !a.requireAgentIdentity(w) {
		return
	}
	indicators, err := a.agentIdentity.ThreatIndicators()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list threat indicators")
		return
	}
	writeJSON(w, http.StatusOK, indicators)
}

func (a *API) createThreatIndicator(w http.ResponseWriter, r *http.Request) {
	a.saveThreatIndicator(w, r, "")
}

func (a *API) updateThreatIndicator(w http.ResponseWriter, r *http.Request) {
	a.saveThreatIndicator(w, r, r.PathValue("id"))
}

func (a *API) saveThreatIndicator(w http.ResponseWriter, r *http.Request, id string) {
	actor, _, ok := a.requireAdministratorWithRecentMFA(w, r)
	if !ok || !a.requireAgentIdentity(w) {
		return
	}
	var indicator model.ThreatIndicator
	if !decodeJSON(w, r, &indicator) {
		return
	}
	indicator.ID = id
	saved, err := a.agentIdentity.SaveThreatIndicator(indicator, actor.ID, requestIP(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	status := http.StatusOK
	if id == "" {
		status = http.StatusCreated
	}
	writeJSON(w, status, saved)
}

func (a *API) getEndpointIndicatorMatches(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdministrator(w, r); !ok || !a.requireAgentIdentity(w) {
		return
	}
	matches, err := a.agentIdentity.IndicatorMatches(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read endpoint indicator matches")
		return
	}
	writeJSON(w, http.StatusOK, matches)
}

func (a *API) getEndpointNetworkInventory(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdministrator(w, r); !ok || !a.requireAgentIdentity(w) {
		return
	}
	inventory, err := a.agentIdentity.NetworkInventory(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "endpoint network metadata not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read endpoint network metadata")
		return
	}
	writeJSON(w, http.StatusOK, inventory)
}

func (a *API) getEndpointCVEMatches(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdministrator(w, r); !ok || !a.requireAgentIdentity(w) {
		return
	}
	matches, err := a.agentIdentity.CVEMatches(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read endpoint CVE matches")
		return
	}
	writeJSON(w, http.StatusOK, matches)
}

func (a *API) getEndpointPostureInventory(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdministrator(w, r); !ok || !a.requireAgentIdentity(w) {
		return
	}
	inventory, err := a.agentIdentity.PostureInventory(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "endpoint security-posture inventory not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read endpoint security-posture inventory")
		return
	}
	writeJSON(w, http.StatusOK, inventory)
}

func (a *API) getEndpointListeningInventory(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdministrator(w, r); !ok || !a.requireAgentIdentity(w) {
		return
	}
	inventory, err := a.agentIdentity.ListeningInventory(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "endpoint listening-service inventory not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read endpoint listening-service inventory")
		return
	}
	writeJSON(w, http.StatusOK, inventory)
}

func (a *API) getEndpointSoftwareInventory(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdministrator(w, r); !ok || !a.requireAgentIdentity(w) {
		return
	}
	inventory, err := a.agentIdentity.SoftwareInventory(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "endpoint software inventory not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read endpoint software inventory")
		return
	}
	writeJSON(w, http.StatusOK, inventory)
}

func (a *API) getEndpointOSInventory(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdministrator(w, r); !ok || !a.requireAgentIdentity(w) {
		return
	}
	inventory, err := a.agentIdentity.OSInventory(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "endpoint OS inventory not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read endpoint OS inventory")
		return
	}
	writeJSON(w, http.StatusOK, inventory)
}

func (a *API) updateEndpointCollectors(w http.ResponseWriter, r *http.Request) {
	actor, _, ok := a.requireAdministratorWithRecentMFA(w, r)
	if !ok || !a.requireAgentIdentity(w) {
		return
	}
	var request struct {
		Collectors []model.CollectorID `json:"collectors"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	err := a.agentIdentity.SetEndpointCollectors(r.PathValue("id"), request.Collectors, actor.ID, requestIP(r))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "active endpoint not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) scannerWorkerDispatchSettings(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdministrator(w, r); !ok || !a.requireAgentIdentity(w) {
		return
	}
	settings, err := a.agentIdentity.WorkerDispatchSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read scanner-worker dispatch settings")
		return
	}
	writeJSON(w, http.StatusOK, settings)
}

func (a *API) updateScannerWorkerDispatch(w http.ResponseWriter, r *http.Request) {
	actor, _, ok := a.requireAdministratorWithRecentMFA(w, r)
	if !ok || !a.requireAgentIdentity(w) {
		return
	}
	var request model.WorkerDispatchSettings
	if !decodeJSON(w, r, &request) {
		return
	}
	if err := a.agentIdentity.SetWorkerDispatch(request.Enabled, actor.ID, requestIP(r)); err != nil {
		writeError(w, http.StatusInternalServerError, "could not update scanner-worker dispatch")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) updateScannerWorkerDispatchForWorker(w http.ResponseWriter, r *http.Request) {
	actor, _, ok := a.requireAdministratorWithRecentMFA(w, r)
	if !ok || !a.requireAgentIdentity(w) {
		return
	}
	var request model.WorkerDispatchSettings
	if !decodeJSON(w, r, &request) {
		return
	}
	err := a.agentIdentity.SetWorkerDispatchForWorker(r.PathValue("id"), request.Enabled, actor.ID, requestIP(r))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "active scanner worker not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not update scanner-worker dispatch")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) listScannerWorkers(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdministrator(w, r); !ok {
		return
	}
	if !a.requireAgentIdentity(w) {
		return
	}
	workers, err := a.agentIdentity.ScannerWorkers()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list scanner workers")
		return
	}
	writeJSON(w, http.StatusOK, workers)
}

func (a *API) createScannerWorkerEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	actor, _, ok := a.requireAdministratorWithRecentMFA(w, r)
	if !ok {
		return
	}
	if !a.requireAgentIdentity(w) {
		return
	}
	var request model.WorkerEnrollmentToken
	if !decodeJSON(w, r, &request) {
		return
	}
	record, token, err := a.agentIdentity.CreateWorkerEnrollmentToken(request, actor.ID, requestIP(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"enrollment": record, "token": token})
}

func (a *API) enrollScannerWorker(w http.ResponseWriter, r *http.Request) {
	if !a.requireAgentIdentity(w) {
		return
	}
	var request struct {
		Token  string `json:"token"`
		CSRPEM string `json:"csr_pem"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	result, err := a.agentIdentity.EnrollWorker(request.Token, request.CSRPEM, requestIP(r))
	if errors.Is(err, store.ErrInvalidEnrollmentToken) {
		writeError(w, http.StatusUnauthorized, "enrollment token is invalid or expired")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, result)
}

func (a *API) revokeScannerWorker(w http.ResponseWriter, r *http.Request) {
	actor, _, ok := a.requireAdministratorWithRecentMFA(w, r)
	if !ok {
		return
	}
	if !a.requireAgentIdentity(w) {
		return
	}
	var request struct {
		Reason string `json:"reason"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	if err := a.agentIdentity.RevokeScannerWorker(r.PathValue("id"), request.Reason, actor.ID, requestIP(r)); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "active scanner worker not found")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) revokeEndpoint(w http.ResponseWriter, r *http.Request) {
	actor, _, ok := a.requireAdministratorWithRecentMFA(w, r)
	if !ok {
		return
	}
	if !a.requireAgentIdentity(w) {
		return
	}
	var request struct {
		Reason string `json:"reason"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	if err := a.agentIdentity.Revoke(r.PathValue("id"), request.Reason, actor.ID, requestIP(r)); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "active endpoint not found")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) listEndpoints(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdministrator(w, r); !ok {
		return
	}
	if !a.requireAgentIdentity(w) {
		return
	}
	items, err := a.agentIdentity.Endpoints()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list endpoints")
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (a *API) listAgentEnrollmentTokens(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdministrator(w, r); !ok {
		return
	}
	if !a.requireAgentIdentity(w) {
		return
	}
	items, err := a.agentIdentity.EnrollmentTokens()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list enrollment tokens")
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (a *API) createAgentEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	actor, _, ok := a.requireAdministratorWithRecentMFA(w, r)
	if !ok {
		return
	}
	if !a.requireAgentIdentity(w) {
		return
	}
	var request struct {
		Name string `json:"name"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	record, token, err := a.agentIdentity.CreateEnrollmentToken(request.Name, actor.ID, requestIP(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"enrollment": record, "token": token})
}

func (a *API) enrollAgent(w http.ResponseWriter, r *http.Request) {
	if !a.requireAgentIdentity(w) {
		return
	}
	var request struct {
		Token  string `json:"token"`
		CSRPEM string `json:"csr_pem"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	result, err := a.agentIdentity.Enroll(request.Token, request.CSRPEM, requestIP(r))
	if errors.Is(err, store.ErrInvalidEnrollmentToken) {
		writeError(w, http.StatusUnauthorized, "enrollment token is invalid or expired")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, result)
}

func (a *API) requireAgentIdentity(w http.ResponseWriter) bool {
	if a.agentIdentity != nil {
		return true
	}
	writeError(w, http.StatusServiceUnavailable, "endpoint identity is not enabled")
	return false
}
