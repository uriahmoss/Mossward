package api

import (
	"crypto/rand"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"mossward/internal/model"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (a *API) registerReportingRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/reporting/summary", a.reportingSummary)
	mux.HandleFunc("GET /api/reporting/export", a.reportingExport)
	mux.HandleFunc("GET /api/reporting/exceptions", a.listExceptions)
	mux.HandleFunc("POST /api/findings/{id}/exceptions", a.requestException)
	mux.HandleFunc("PATCH /api/reporting/exceptions/{id}", a.reviewException)
	mux.HandleFunc("GET /api/admin/evidence-retention", a.getRetention)
	mux.HandleFunc("PUT /api/admin/evidence-retention", a.saveRetention)
}
func (a *API) reportingSummary(w http.ResponseWriter, r *http.Request) {
	scans, err := a.store.List()
	if err != nil {
		writeError(w, 500, "could not build report")
		return
	}
	now := time.Now().UTC()
	summary := buildSummary(scans, now)
	exceptions, err := a.store.ListFindingExceptions()
	if err != nil {
		writeError(w, 500, "could not build report")
		return
	}
	for _, exception := range exceptions {
		if exception.Status == model.ExceptionApproved && (exception.ExpiresAt == nil || exception.ExpiresAt.After(now)) {
			summary.AcceptedRisk++
		}
	}
	writeJSON(w, 200, summary)
}
func buildSummary(scans []model.Scan, now time.Time) model.ReportingSummary {
	s := model.ReportingSummary{GeneratedAt: now, TotalScans: len(scans), Severity: map[string]int{}}
	byDate := map[string]*model.ReportingTrendPoint{}
	for _, scan := range scans {
		date := scan.CreatedAt.Format("2006-01-02")
		p := byDate[date]
		if p == nil {
			p = &model.ReportingTrendPoint{Date: date}
			byDate[date] = p
			s.Trend = append(s.Trend, *p)
		}
		for _, f := range scan.Findings {
			s.TotalFindings++
			s.Severity[f.Severity]++
			if f.Status == model.FindingResolved {
				s.ResolvedFindings++
			} else {
				s.OpenFindings++
			}
			for i := range s.Trend {
				if s.Trend[i].Date == date {
					s.Trend[i].Findings++
					if f.Status == model.FindingResolved {
						s.Trend[i].Resolved++
					}
				}
			}
		}
	}
	return s
}
func (a *API) reportingExport(w http.ResponseWriter, r *http.Request) {
	scans, err := a.store.List()
	if err != nil {
		writeError(w, 500, "could not export report")
		return
	}
	if r.URL.Query().Get("format") == "json" {
		w.Header().Set("Content-Disposition", `attachment; filename="mossward-report.json"`)
		writeJSON(w, 200, scans)
		return
	}
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", `attachment; filename="mossward-findings.csv"`)
	out := csv.NewWriter(w)
	_ = out.Write([]string{"scan_id", "scan_name", "finding_id", "status", "assigned_to", "severity", "check_id", "target", "address", "port", "title", "observed_at"})
	for _, scan := range scans {
		for _, f := range scan.Findings {
			_ = out.Write([]string{scan.ID, scan.Name, f.ID, string(f.Status), f.AssignedTo, f.Severity, f.CheckID, f.Target, f.Address, strconv.Itoa(f.Port), f.Title, f.ObservedAt.Format(time.RFC3339)})
		}
	}
	out.Flush()
}
func (a *API) listExceptions(w http.ResponseWriter, r *http.Request) {
	v, err := a.store.ListFindingExceptions()
	if err != nil {
		writeError(w, 500, "could not list exceptions")
		return
	}
	writeJSON(w, 200, v)
}
func (a *API) requestException(w http.ResponseWriter, r *http.Request) {
	actor, ok := a.currentUser(r)
	if !ok || actor.Role == model.RoleViewer {
		writeError(w, 403, "analyst or administrator role required")
		return
	}
	var v model.FindingException
	if !decodeJSON(w, r, &v) {
		return
	}
	v.ID = randomReportingID()
	v.FindingID = r.PathValue("id")
	v.Reason = strings.TrimSpace(v.Reason)
	v.Status = model.ExceptionPending
	v.RequestedBy = actor.ID
	v.CreatedAt = time.Now().UTC()
	if v.ReminderDays == 0 {
		v.ReminderDays = 30
	}
	event := model.AuditEvent{OccurredAt: v.CreatedAt, ActorID: actor.ID, Action: "finding.exception.requested", Severity: model.AuditWarning, TargetType: "finding", TargetID: v.FindingID, SourceIP: requestIP(r), Details: `{}`}
	if v.Reason == "" || a.store.SaveFindingException(v, event) != nil {
		writeError(w, 400, "invalid exception request")
		return
	}
	writeJSON(w, 201, v)
}
func (a *API) reviewException(w http.ResponseWriter, r *http.Request) {
	actor, ok := a.requireAdministrator(w, r)
	if !ok {
		return
	}
	var input struct {
		Status model.FindingExceptionStatus `json:"status"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	now := time.Now().UTC()
	event := model.AuditEvent{OccurredAt: now, ActorID: actor.ID, Action: "finding.exception.reviewed", Severity: model.AuditWarning, TargetType: "finding_exception", TargetID: r.PathValue("id"), SourceIP: requestIP(r), Details: `{}`}
	if a.store.ReviewFindingException(r.PathValue("id"), input.Status, actor.ID, now, event) != nil {
		writeError(w, 400, "could not review exception")
		return
	}
	w.WriteHeader(204)
}
func (a *API) getRetention(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdministrator(w, r); !ok {
		return
	}
	v, err := a.store.EvidenceRetentionSettings()
	if err != nil {
		writeError(w, 500, "could not load retention settings")
		return
	}
	writeJSON(w, 200, v)
}
func (a *API) saveRetention(w http.ResponseWriter, r *http.Request) {
	actor, ok := a.requireAdministrator(w, r)
	if !ok {
		return
	}
	var v model.EvidenceRetentionSettings
	if !decodeJSON(w, r, &v) {
		return
	}
	v.UpdatedAt = time.Now().UTC()
	details, _ := json.Marshal(v)
	event := model.AuditEvent{OccurredAt: v.UpdatedAt, ActorID: actor.ID, Action: "evidence.retention.updated", Severity: model.AuditWarning, TargetType: "evidence_retention", TargetID: "server", SourceIP: requestIP(r), Details: string(details)}
	if a.store.SaveEvidenceRetentionSettings(v, event) != nil {
		writeError(w, 400, "retention must be between 30 and 3650 days")
		return
	}
	writeJSON(w, 200, v)
}
func randomReportingID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
