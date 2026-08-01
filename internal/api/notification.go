package api

import (
	"mossward/internal/model"
	"net/http"
)

func (a *API) registerNotificationRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/admin/smtp", a.getSMTP)
	mux.HandleFunc("PUT /api/admin/smtp", a.saveSMTP)
}
func (a *API) getSMTP(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdministrator(w, r); !ok {
		return
	}
	if a.notifications == nil {
		writeError(w, 503, "notification service unavailable")
		return
	}
	value, err := a.notifications.Settings()
	if err != nil {
		writeError(w, 500, "could not load SMTP settings")
		return
	}
	writeJSON(w, 200, value)
}
func (a *API) saveSMTP(w http.ResponseWriter, r *http.Request) {
	actor, _, ok := a.requireAdministratorWithRecentMFA(w, r)
	if !ok {
		return
	}
	if a.notifications == nil {
		writeError(w, 503, "notification service unavailable")
		return
	}
	var request model.SMTPConfiguration
	if !decodeJSON(w, r, &request) {
		return
	}
	value, err := a.notifications.Configure(request, actor.ID, requestIP(r))
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, value)
}
