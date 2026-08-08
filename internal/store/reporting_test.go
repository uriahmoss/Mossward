package store

import (
	"mossward/internal/model"
	"testing"
	"time"
)

func TestEvidenceRetentionDefaultsToYearAndPurgesExpiredScans(t *testing.T) {
	repository := openTestStore(t)
	settings, err := repository.EvidenceRetentionSettings()
	if err != nil || settings.RetentionDays != 365 {
		t.Fatalf("settings = %#v, %v", settings, err)
	}
	old := time.Now().UTC().AddDate(-2, 0, 0)
	completed := old
	scan := model.Scan{ID: "expired-evidence", Name: "Old", Status: model.StatusCompleted, CreatedAt: old, CompletedAt: &completed}
	if err := repository.Save(scan); err != nil {
		t.Fatal(err)
	}
	removed, err := repository.PurgeExpiredEvidence(time.Now().UTC())
	if err != nil || removed != 1 {
		t.Fatalf("removed = %d, %v", removed, err)
	}
	if _, err := repository.Get(scan.ID); err != ErrNotFound {
		t.Fatalf("expired scan still exists: %v", err)
	}
}

func TestApprovedOpenEndedExceptionIsRemindedAndPreservesEvidence(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, err := repository.db.Exec(`INSERT INTO users(id,email,display_name,role,status,created_at,updated_at) VALUES('admin','admin@example.test','Admin','administrator','active',?,?)`, formatTime(now), formatTime(now))
	if err != nil {
		t.Fatal(err)
	}
	old := now.AddDate(-2, 0, 0)
	scan := model.Scan{ID: "held-scan", Name: "Held", Status: model.StatusCompleted, CreatedAt: old, CompletedAt: &old,
		Findings: []model.Finding{{ID: "held-finding", CheckID: "test.check", Target: "host", Address: "192.0.2.1", Port: 443, Service: "https", Severity: "medium", Title: "Held", ObservedAt: old}}}
	if err := repository.Save(scan); err != nil {
		t.Fatal(err)
	}
	exception := model.FindingException{ID: "exception", FindingID: "held-finding", Reason: "Temporary dependency", Status: model.ExceptionPending, RequestedBy: "admin", CreatedAt: old, ReminderDays: 30}
	event := model.AuditEvent{OccurredAt: now, ActorID: "admin", Action: "test", Severity: model.AuditInfo}
	if err := repository.SaveFindingException(exception, event); err != nil {
		t.Fatal(err)
	}
	if err := repository.ReviewFindingException(exception.ID, model.ExceptionApproved, "admin", now, event); err != nil {
		t.Fatal(err)
	}
	due, err := repository.DueOpenEndedExceptions(now)
	if err != nil || len(due) != 1 {
		t.Fatalf("due reminders = %#v, %v", due, err)
	}
	removed, err := repository.PurgeExpiredEvidence(now)
	if err != nil || removed != 0 {
		t.Fatalf("held evidence removed = %d, %v", removed, err)
	}
}
