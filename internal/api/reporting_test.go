package api

import (
	"mossward/internal/model"
	"testing"
	"time"
)

func TestBuildSummaryCountsFindingWorkflow(t *testing.T) {
	now := time.Now().UTC()
	summary := buildSummary([]model.Scan{{ID: "scan", CreatedAt: now, Findings: []model.Finding{{Severity: "high", Status: model.FindingOpen}, {Severity: "low", Status: model.FindingResolved}}}}, now)
	if summary.TotalScans != 1 || summary.TotalFindings != 2 || summary.OpenFindings != 1 || summary.ResolvedFindings != 1 || summary.Severity["high"] != 1 {
		t.Fatalf("summary = %#v", summary)
	}
}
