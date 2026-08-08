package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"mossward/internal/model"
	"mossward/internal/store"
)

func (a *API) updateFindingWorkflow(w http.ResponseWriter, r *http.Request) {
	actor, ok := a.currentUser(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if actor.Role == model.RoleViewer {
		writeError(w, http.StatusForbidden, "analyst or administrator role required")
		return
	}
	var update model.FindingWorkflowUpdate
	if !decodeJSON(w, r, &update) {
		return
	}
	update.AssignedTo = strings.TrimSpace(update.AssignedTo)
	details, _ := json.Marshal(update)
	now := time.Now().UTC()
	event := model.AuditEvent{OccurredAt: now, ActorID: actor.ID, Action: "finding.workflow.updated", Severity: model.AuditInfo,
		TargetType: "finding", TargetID: r.PathValue("id"), SourceIP: requestIP(r), Details: string(details)}
	err := a.store.UpdateFindingWorkflow(r.PathValue("id"), update, now, event)
	if errors.Is(err, store.ErrFindingNotFound) {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	if errors.Is(err, store.ErrInvalidFindingWorkflow) {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not update finding workflow")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
