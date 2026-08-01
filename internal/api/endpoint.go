package api

import (
	"errors"
	"net/http"

	"mossward/internal/store"
)

func (a *API) registerAgentIdentityRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/admin/endpoints", a.listEndpoints)
	mux.HandleFunc("GET /api/admin/agent-enrollment-tokens", a.listAgentEnrollmentTokens)
	mux.HandleFunc("POST /api/admin/agent-enrollment-tokens", a.createAgentEnrollmentToken)
	mux.HandleFunc("POST /api/agent/enroll", a.enrollAgent)
	mux.HandleFunc("POST /api/admin/endpoints/{id}/revoke", a.revokeEndpoint)
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
