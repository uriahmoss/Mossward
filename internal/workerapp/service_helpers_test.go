package workerapp

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"mossward/internal/model"
)

const nativeServiceAcceptanceTimeout = 30 * time.Second

func nativeCommand(t *testing.T, directory, name string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, name, args...)
	command.Dir = directory
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("native service command %s failed: %v: %s", name, err, output)
	}
}

func waitNativeCompletion(t *testing.T, controller *deploymentController) {
	t.Helper()
	deadline := time.Now().Add(nativeServiceAcceptanceTimeout)
	for time.Now().Before(deadline) {
		controller.mu.Lock()
		complete := len(controller.evidence) == 1 && len(controller.results) == 1
		if complete && controller.results[0].Outcome != model.WorkerJobResultSucceeded {
			controller.mu.Unlock()
			t.Fatal("native service scan did not succeed")
		}
		controller.mu.Unlock()
		if complete {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("native worker did not deliver signed scan evidence and completion")
}

func assertNativeReplayRejected(t *testing.T, controller *deploymentController) {
	t.Helper()
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if len(controller.evidence) != 1 || len(controller.results) < 1 || len(controller.results) > 2 {
		t.Fatal("replayed lease repeated scan evidence or unexpected completion count")
	}
	// Runtime reports a rejected lease as failed; that is not a second scan.
	if len(controller.results) == 2 && controller.results[1].Outcome == model.WorkerJobResultSucceeded {
		t.Fatal("replayed lease reported a second successful scan")
	}
}
