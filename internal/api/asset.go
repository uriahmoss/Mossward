package api

import (
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"mossward/internal/model"
	"mossward/internal/store"
)

const assetMetadataLimit = 200
const assetRetirementReasonLimit = 500

func (a *API) listAssets(w http.ResponseWriter, _ *http.Request) {
	assets, err := a.store.ListAssets()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list assets")
		return
	}
	writeJSON(w, http.StatusOK, assets)
}

func (a *API) getAsset(w http.ResponseWriter, r *http.Request) {
	detail, err := a.store.AssetDetail(r.PathValue("id"), time.Now().UTC())
	if errors.Is(err, store.ErrAssetNotFound) {
		writeError(w, http.StatusNotFound, "asset not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load asset")
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

func (a *API) updateAsset(w http.ResponseWriter, r *http.Request) {
	actor, ok := a.currentUser(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if actor.Role == model.RoleViewer {
		writeError(w, http.StatusForbidden, "analyst or administrator role required")
		return
	}
	var metadata model.AssetMetadata
	if !decodeJSON(w, r, &metadata) {
		return
	}
	metadata.Owner = strings.TrimSpace(metadata.Owner)
	metadata.Environment = strings.TrimSpace(metadata.Environment)
	metadata.Classification = strings.TrimSpace(metadata.Classification)
	if !validAssetMetadata(metadata) {
		writeError(w, http.StatusBadRequest, "asset metadata fields must not exceed 200 characters")
		return
	}
	event := model.AuditEvent{OccurredAt: time.Now().UTC(), ActorID: actor.ID, Action: "asset.metadata.updated",
		Severity: model.AuditInfo, TargetType: "asset", TargetID: r.PathValue("id"), SourceIP: requestIP(r), Details: "{}"}
	if err := a.store.UpdateAssetMetadata(r.PathValue("id"), metadata, event); err != nil {
		if errors.Is(err, store.ErrAssetNotFound) {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "could not update asset metadata")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func validAssetMetadata(metadata model.AssetMetadata) bool {
	return utf8.RuneCountInString(metadata.Owner) <= assetMetadataLimit &&
		utf8.RuneCountInString(metadata.Environment) <= assetMetadataLimit &&
		utf8.RuneCountInString(metadata.Classification) <= assetMetadataLimit
}

func (a *API) updateAssetLifecycle(w http.ResponseWriter, r *http.Request) {
	actor, ok := a.requireAdministrator(w, r)
	if !ok {
		return
	}
	var update model.AssetLifecycleUpdate
	if !decodeJSON(w, r, &update) {
		return
	}
	update.Reason = strings.TrimSpace(update.Reason)
	if update.Status == model.AssetRetired && update.Reason == "" {
		writeError(w, http.StatusBadRequest, "a retirement reason is required")
		return
	}
	if utf8.RuneCountInString(update.Reason) > assetRetirementReasonLimit {
		writeError(w, http.StatusBadRequest, "retirement reason must not exceed 500 characters")
		return
	}
	action := "asset.restored"
	if update.Status == model.AssetRetired {
		action = "asset.retired"
	}
	event := model.AuditEvent{OccurredAt: time.Now().UTC(), ActorID: actor.ID, Action: action,
		Severity: model.AuditInfo, TargetType: "asset", TargetID: r.PathValue("id"), SourceIP: requestIP(r), Details: "{}"}
	if err := a.store.UpdateAssetLifecycle(r.PathValue("id"), update, event); err != nil {
		if errors.Is(err, store.ErrAssetNotFound) {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		if errors.Is(err, store.ErrInvalidAssetLifecycle) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "could not update asset lifecycle")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) getAssetAgingSettings(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdministrator(w, r); !ok {
		return
	}
	settings, err := a.store.AssetAgingSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load asset aging settings")
		return
	}
	writeJSON(w, http.StatusOK, settings)
}

func (a *API) updateAssetAgingSettings(w http.ResponseWriter, r *http.Request) {
	actor, ok := a.requireAdministrator(w, r)
	if !ok {
		return
	}
	var settings model.AssetAgingSettings
	if !decodeJSON(w, r, &settings) {
		return
	}
	event := model.AuditEvent{OccurredAt: time.Now().UTC(), ActorID: actor.ID, Action: "asset.aging.updated",
		Severity: model.AuditInfo, TargetType: "asset_settings", TargetID: "global", SourceIP: requestIP(r), Details: "{}"}
	if err := a.store.UpdateAssetAgingSettings(settings, event); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) mergeAssets(w http.ResponseWriter, r *http.Request) {
	actor, ok := a.requireAdministrator(w, r)
	if !ok {
		return
	}
	var request model.AssetMergeRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	event := model.AuditEvent{OccurredAt: time.Now().UTC(), ActorID: actor.ID, Action: "asset.merged",
		Severity: model.AuditWarning, TargetType: "asset", TargetID: request.SurvivorID, SourceIP: requestIP(r), Details: "{}"}
	if err := a.store.MergeAssets(request, event); err != nil {
		if errors.Is(err, store.ErrAssetNotFound) {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
