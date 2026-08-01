package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"mossward/internal/model"
	"mossward/internal/store"
)

func (a *API) listEnabledScopePolicies(w http.ResponseWriter, _ *http.Request) {
	policies, err := a.store.ListScopePolicies(true)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load scope policies")
		return
	}
	writeJSON(w, http.StatusOK, policies)
}

func (a *API) listAllScopePolicies(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdministrator(w, r); !ok {
		return
	}
	policies, err := a.store.ListScopePolicies(false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load scope policies")
		return
	}
	writeJSON(w, http.StatusOK, policies)
}

func (a *API) saveScopePolicy(w http.ResponseWriter, r *http.Request) {
	actor, _, ok := a.requireAdministratorWithRecentMFA(w, r)
	if !ok {
		return
	}
	var policy model.ScopePolicy
	if !decodeJSON(w, r, &policy) {
		return
	}
	if pathID := r.PathValue("id"); pathID != "" {
		policy.ID = pathID
	} else {
		policy.ID = ""
	}
	if err := a.prepareScopePolicy(&policy, actor); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	event := model.AuditEvent{OccurredAt: policy.UpdatedAt, ActorID: actor.ID, Action: "scanner.scope_policy.saved",
		Severity: model.AuditWarning, TargetType: "scope_policy", TargetID: policy.ID, SourceIP: requestIP(r), Details: "{}"}
	if err := a.store.UpsertScopePolicy(policy, event); err != nil {
		writeError(w, http.StatusBadRequest, "could not save scope policy")
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

func (a *API) prepareScopePolicy(policy *model.ScopePolicy, actor model.User) error {
	policy.Name = strings.TrimSpace(policy.Name)
	if policy.Name == "" {
		return errors.New("scope-policy name is required")
	}
	now := time.Now().UTC()
	if policy.ID == "" {
		id, err := randomID()
		if err != nil {
			return err
		}
		policy.ID = id
		policy.CreatedAt = now
		policy.CreatedBy = actor.ID
	} else if current, err := a.store.ScopePolicy(policy.ID); err == nil {
		policy.CreatedAt = current.CreatedAt
		policy.CreatedBy = current.CreatedBy
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	} else {
		policy.CreatedAt = now
		policy.CreatedBy = actor.ID
	}
	policy.UpdatedAt = now
	return a.scanner.ValidatePolicy(*policy)
}
