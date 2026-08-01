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
