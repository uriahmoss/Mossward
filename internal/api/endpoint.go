package api

import (
	"errors"
	"net/http"

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
	mux.HandleFunc("GET /api/admin/endpoints/{id}/os-inventory", a.getEndpointOSInventory)
	mux.HandleFunc("GET /api/admin/endpoints/{id}/software-inventory", a.getEndpointSoftwareInventory)
	mux.HandleFunc("GET /api/admin/endpoints/{id}/listening-inventory", a.getEndpointListeningInventory)
	mux.HandleFunc("GET /api/admin/endpoints/{id}/posture-inventory", a.getEndpointPostureInventory)
	mux.HandleFunc("GET /api/admin/endpoints/{id}/cves", a.getEndpointCVEMatches)
	mux.HandleFunc("GET /api/admin/scanner-workers", a.listScannerWorkers)
	mux.HandleFunc("GET /api/admin/scanner-worker-dispatch", a.scannerWorkerDispatchSettings)
	mux.HandleFunc("PUT /api/admin/scanner-worker-dispatch", a.updateScannerWorkerDispatch)
	mux.HandleFunc("PUT /api/admin/scanner-workers/{id}/dispatch", a.updateScannerWorkerDispatchForWorker)
	mux.HandleFunc("POST /api/admin/scanner-worker-enrollment-tokens", a.createScannerWorkerEnrollmentToken)
	mux.HandleFunc("POST /api/scanner-workers/enroll", a.enrollScannerWorker)
	mux.HandleFunc("POST /api/admin/scanner-workers/{id}/revoke", a.revokeScannerWorker)
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
