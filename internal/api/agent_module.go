package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"mossward/internal/agentmodule"
	"mossward/internal/store"
)

func (a *API) registerAgentModuleRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/admin/agent-module-publishers", a.listAgentModulePublishers)
	mux.HandleFunc("PUT /api/admin/agent-module-publishers/{id}", a.saveAgentModulePublisher)
	mux.HandleFunc("GET /api/admin/agent-modules", a.listAgentModules)
	mux.HandleFunc("POST /api/admin/agent-modules", a.importAgentModule)
	mux.HandleFunc("POST /api/admin/agent-modules/{id}/approve", a.approveAgentModule)
	mux.HandleFunc("POST /api/admin/agent-modules/{id}/revoke", a.revokeAgentModule)
	mux.HandleFunc("GET /api/admin/agent-module-assignments", a.listAgentModuleAssignments)
	mux.HandleFunc("POST /api/admin/agent-module-assignments", a.assignAgentModule)
	mux.HandleFunc("PUT /api/admin/agent-modules/emergency-state", a.setAgentModuleEmergencyState)
	mux.HandleFunc("PUT /api/admin/endpoints/{id}/asset", a.linkEndpointAsset)
}

func (a *API) requireAgentModules(w http.ResponseWriter) bool {
	if a.agentModules == nil {
		writeError(w, http.StatusServiceUnavailable, "endpoint module service unavailable")
		return false
	}
	return true
}

func (a *API) listAgentModulePublishers(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdministrator(w, r); !ok || !a.requireAgentModules(w) {
		return
	}
	items, err := a.agentModules.Publishers()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list module publishers")
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (a *API) saveAgentModulePublisher(w http.ResponseWriter, r *http.Request) {
	actor, _, ok := a.requireAdministratorWithRecentMFA(w, r)
	if !ok || !a.requireAgentModules(w) {
		return
	}
	var request struct {
		Name      string `json:"name"`
		PublicKey string `json:"public_key"`
		Enabled   bool   `json:"enabled"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	key, err := base64.RawStdEncoding.DecodeString(request.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		writeError(w, http.StatusBadRequest, "publisher public key must be unpadded base64 Ed25519")
		return
	}
	if err := a.agentModules.SavePublisher(r.PathValue("id"), request.Name, key, request.Enabled, actor.ID, requestIP(r)); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) listAgentModules(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdministrator(w, r); !ok || !a.requireAgentModules(w) {
		return
	}
	items, err := a.agentModules.Releases()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list endpoint modules")
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (a *API) importAgentModule(w http.ResponseWriter, r *http.Request) {
	actor, _, ok := a.requireAdministratorWithRecentMFA(w, r)
	if !ok || !a.requireAgentModules(w) {
		return
	}
	var request struct {
		Envelope json.RawMessage `json:"envelope"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, agentmodule.MaximumPackageBytes*2))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		writeError(w, http.StatusBadRequest, "signed module envelope is invalid or too large")
		return
	}
	if len(request.Envelope) == 0 {
		writeError(w, http.StatusBadRequest, "signed module envelope is required")
		return
	}
	release, err := a.agentModules.Import(request.Envelope, actor.ID, requestIP(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, release)
}

func (a *API) approveAgentModule(w http.ResponseWriter, r *http.Request) {
	actor, _, ok := a.requireAdministratorWithRecentMFA(w, r)
	if !ok || !a.requireAgentModules(w) {
		return
	}
	if err := a.agentModules.Approve(r.PathValue("id"), actor.ID, requestIP(r)); err != nil {
		writeModuleError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) revokeAgentModule(w http.ResponseWriter, r *http.Request) {
	actor, _, ok := a.requireAdministratorWithRecentMFA(w, r)
	if !ok || !a.requireAgentModules(w) {
		return
	}
	var request struct {
		Reason string `json:"reason"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	if err := a.agentModules.Revoke(r.PathValue("id"), request.Reason, actor.ID, requestIP(r)); err != nil {
		writeModuleError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) listAgentModuleAssignments(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdministrator(w, r); !ok || !a.requireAgentModules(w) {
		return
	}
	items, err := a.agentModules.Assignments()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list module assignments")
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (a *API) assignAgentModule(w http.ResponseWriter, r *http.Request) {
	actor, _, ok := a.requireAdministratorWithRecentMFA(w, r)
	if !ok || !a.requireAgentModules(w) {
		return
	}
	var request struct {
		ReleaseID   string `json:"release_id"`
		TargetType  string `json:"target_type"`
		TargetID    string `json:"target_id"`
		RingPercent int    `json:"ring_percent"`
		Enabled     bool   `json:"enabled"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	if err := a.agentModules.Assign(request.ReleaseID, request.TargetType, request.TargetID, request.RingPercent, request.Enabled, actor.ID, requestIP(r)); err != nil {
		writeModuleError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "assigned"})
}

func (a *API) setAgentModuleEmergencyState(w http.ResponseWriter, r *http.Request) {
	actor, _, ok := a.requireAdministratorWithRecentMFA(w, r)
	if !ok || !a.requireAgentModules(w) {
		return
	}
	var request struct {
		Enabled bool `json:"enabled"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	if err := a.agentModules.SetEnabled(request.Enabled, actor.ID, requestIP(r)); err != nil {
		writeError(w, http.StatusInternalServerError, "could not update module emergency state")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) linkEndpointAsset(w http.ResponseWriter, r *http.Request) {
	actor, _, ok := a.requireAdministratorWithRecentMFA(w, r)
	if !ok || !a.requireAgentModules(w) {
		return
	}
	var request struct {
		AssetID string `json:"asset_id"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	if err := a.agentModules.LinkEndpointAsset(r.PathValue("id"), request.AssetID, actor.ID, requestIP(r)); err != nil {
		writeModuleError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeModuleError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "module, endpoint, group, or asset not found in the required state")
		return
	}
	writeError(w, http.StatusBadRequest, err.Error())
}
