package store

import (
	"testing"
	"time"

	"mossward/internal/model"
)

func TestFindingWorkflowPersistsAcrossScanSave(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	scan := model.Scan{ID: "workflow-scan", Name: "Workflow", Status: model.StatusCompleted, CreatedAt: now,
		Findings: []model.Finding{{ID: "finding-1", CheckID: "http.test", Target: "host", Address: "192.0.2.1", Port: 80, Service: "http", Severity: "low", Title: "Test", ObservedAt: now}}}
	if err := repository.Save(scan); err != nil {
		t.Fatal(err)
	}
	event := model.AuditEvent{OccurredAt: now, Action: "finding.workflow.updated", Severity: model.AuditInfo, TargetType: "finding", TargetID: "finding-1", Details: `{}`}
	if err := repository.UpdateFindingWorkflow("finding-1", model.FindingWorkflowUpdate{Status: model.FindingResolved}, now, event); err != nil {
		t.Fatal(err)
	}
	loaded, err := repository.Get(scan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Findings[0].Status != model.FindingResolved || loaded.Findings[0].WorkflowUpdatedAt == nil {
		t.Fatalf("workflow was not loaded: %#v", loaded.Findings[0])
	}
	if err := repository.Save(loaded); err != nil {
		t.Fatal(err)
	}
	reloaded, err := repository.Get(scan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Findings[0].Status != model.FindingResolved {
		t.Fatalf("workflow was lost during scan save: %#v", reloaded.Findings[0])
	}
}

func TestFindingWorkflowRejectsInvalidStatus(t *testing.T) {
	repository := openTestStore(t)
	err := repository.UpdateFindingWorkflow("missing", model.FindingWorkflowUpdate{Status: "accepted_risk"}, time.Now(), model.AuditEvent{})
	if err != ErrInvalidFindingWorkflow {
		t.Fatalf("invalid status error = %v", err)
	}
}
