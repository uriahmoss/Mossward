package workerapp

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"mossward/internal/model"
	"mossward/internal/workerclient"
)

func TestDeploymentMTLSScanRetainsAndDeliversEvidenceAfterRestart(t *testing.T) {
	config, controller, lease := deploymentFixture(t)
	controller.failDelivery = true
	app, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	cycleErr := app.runCycle(ctx)
	if cycleErr == nil {
		t.Fatal("failed upload unexpectedly acknowledged")
	}
	stats, err := app.outbox.Stats()
	if err != nil || stats.Items < 2 {
		t.Fatalf("failed delivery did not retain evidence and completion: cycle=%v stats=%+v err=%v", cycleErr, stats, err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	controller.mu.Lock()
	controller.failDelivery = false
	controller.mu.Unlock()
	restarted, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if err := restarted.runCycle(ctx); err != nil {
		t.Fatal(err)
	}
	stats, err = restarted.outbox.Stats()
	if err != nil || stats.Items != 0 {
		t.Fatal("acknowledged outbox did not drain")
	}
	controller.mu.Lock()
	if len(controller.evidence) != 1 || len(controller.results) != 1 || len(controller.order) != 2 || controller.order[0] != "evidence" || controller.order[1] != "result" {
		controller.mu.Unlock()
		t.Fatal("delivery order or count changed across restart")
	}
	batch := controller.evidence[0].Batch
	result := controller.results[0]
	controller.lease = lease
	controller.mu.Unlock()
	if !batch.Final || batch.JobID != lease.Envelope.Job.ID || len(batch.Observations) != 1 || result.Outcome != model.WorkerJobResultSucceeded {
		t.Fatal("real scan evidence or successful completion missing")
	}
	if err := restarted.runCycle(ctx); !errors.Is(err, workerclient.ErrJobReplay) {
		t.Fatalf("persistent replay guard failed: %v", err)
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if len(controller.evidence) != 1 {
		t.Fatal("replayed job repeated scan evidence")
	}
}

func TestDeploymentWorkerRunCancelsCleanly(t *testing.T) {
	config, controller, _ := deploymentFixture(t)
	controller.lease = model.WorkerJobLease{}
	app, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := app.Run(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestDeploymentRejectsWrongSiteBeforeEvidence(t *testing.T) {
	config, controller, _ := deploymentFixture(t)
	config.SiteID = "different-site"
	app, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	if err := app.runCycle(ctx); err == nil || !strings.Contains(err.Error(), "site affinity") {
		t.Fatalf("wrong-site job accepted: %v", err)
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if len(controller.evidence) != 0 {
		t.Fatal("wrong-site job emitted scan evidence")
	}
}
