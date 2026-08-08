package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"mossward/internal/store"
)

func (a *API) registerAgentUpdateRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/admin/agent-updates", a.listAgentUpdates)
	mux.HandleFunc("POST /api/admin/agent-updates", a.importAgentUpdate)
	mux.HandleFunc("POST /api/admin/agent-updates/{id}/approve", a.approveAgentUpdate)
	mux.HandleFunc("POST /api/admin/agent-updates/{id}/revoke", a.revokeAgentUpdate)
	mux.HandleFunc("PUT /api/admin/endpoints/{id}/update", a.assignAgentUpdate)
}

func (a *API) assignAgentUpdate(w http.ResponseWriter, r *http.Request) {
	actor, _, ok := a.requireAdministratorWithRecentMFA(w, r)
	if !ok || !a.requireAgentUpdateCatalog(w) {
		return
	}
	var request struct {
		ReleaseID string `json:"release_id"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	if err := a.agentUpdates.Assign(r.PathValue("id"), request.ReleaseID, actor.ID, requestIP(r)); err != nil {
		writeAgentUpdateTransitionError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) listAgentUpdates(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdministrator(w, r); !ok || !a.requireAgentUpdateCatalog(w) {
		return
	}
	releases, err := a.agentUpdates.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list endpoint-agent updates")
		return
	}
	writeJSON(w, http.StatusOK, releases)
}

func (a *API) importAgentUpdate(w http.ResponseWriter, r *http.Request) {
	actor, _, ok := a.requireAdministratorWithRecentMFA(w, r)
	if !ok || !a.requireAgentUpdateCatalog(w) {
		return
	}
	var request struct {
		Envelope json.RawMessage `json:"envelope"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	if len(request.Envelope) == 0 {
		writeError(w, http.StatusBadRequest, "signed update envelope is required")
		return
	}
	release, err := a.agentUpdates.Import(request.Envelope, actor.ID, requestIP(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, release)
}

func (a *API) approveAgentUpdate(w http.ResponseWriter, r *http.Request) {
	actor, _, ok := a.requireAdministratorWithRecentMFA(w, r)
	if !ok || !a.requireAgentUpdateCatalog(w) {
		return
	}
	if err := a.agentUpdates.Approve(r.PathValue("id"), actor.ID, requestIP(r)); err != nil {
		writeAgentUpdateTransitionError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) revokeAgentUpdate(w http.ResponseWriter, r *http.Request) {
	actor, _, ok := a.requireAdministratorWithRecentMFA(w, r)
	if !ok || !a.requireAgentUpdateCatalog(w) {
		return
	}
	var request struct {
		Reason string `json:"reason"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	if err := a.agentUpdates.Revoke(r.PathValue("id"), request.Reason, actor.ID, requestIP(r)); err != nil {
		writeAgentUpdateTransitionError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) requireAgentUpdateCatalog(w http.ResponseWriter) bool {
	if a.agentUpdates == nil {
		writeError(w, http.StatusServiceUnavailable, "endpoint-agent release trust is not configured")
		return false
	}
	return true
}

func writeAgentUpdateTransitionError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "endpoint-agent update is not in the required state")
		return
	}
	writeError(w, http.StatusBadRequest, err.Error())
}
