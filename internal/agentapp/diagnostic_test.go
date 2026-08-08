package agentapp

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDiagnoseReportsMissingIdentityWithoutNetworkAccess(t *testing.T) {
	directory := t.TempDir()
	config := Config{ServerURL: "https://mossward.example.test", EndpointURL: "https://agents.example.test",
		StateDirectory: directory, CheckInIntervalSeconds: 60}
	report := Diagnose(context.Background(), config, true)
	if report.Healthy || len(report.Results) != 3 {
		t.Fatalf("unexpected report: %#v", report)
	}
	if report.Results[1].Name != "agent_identity" || report.Results[1].Status != DiagnosticError {
		t.Fatalf("identity result: %#v", report.Results[1])
	}
	if report.Results[2].Status != DiagnosticSkipped {
		t.Fatalf("connectivity result: %#v", report.Results[2])
	}
}

func TestCheckStateDirectoryRejectsBroadPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows permissions are enforced through ACLs")
	}
	directory := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	result := checkStateDirectory(directory)
	if result.Status != DiagnosticError {
		t.Fatalf("state result: %#v", result)
	}
}
