package workerclient

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"mossward/internal/model"
	"mossward/internal/workerjob"
)

type recordingInspector struct {
	mu            sync.Mutex
	active        int
	maximumActive int
	checks        []string
	capabilities  [][]model.WorkerCapability
}

func (i *recordingInspector) InspectScoped(_ context.Context, target model.Target, port int, capabilities []model.WorkerCapability) (model.ServiceObservation, []model.Finding, bool) {
	i.mu.Lock()
	i.active++
	if i.active > i.maximumActive {
		i.maximumActive = i.active
	}
	i.checks = append(i.checks, executionCheckKey(target.Address, port))
	i.capabilities = append(i.capabilities, append([]model.WorkerCapability(nil), capabilities...))
	i.mu.Unlock()
	time.Sleep(10 * time.Millisecond)
	i.mu.Lock()
	i.active--
	i.mu.Unlock()
	return model.ServiceObservation{ID: "observation-" + target.Address, Target: target.Name, Address: target.Address,
		Port: port, Protocol: "tcp", Confidence: "low", Evidence: "reachable", ObservedAt: time.Now().UTC()}, nil, true
}

func TestExecutorHonorsResumeCapabilitiesAndConcurrency(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	worker := model.ScannerWorker{ID: "replacement", Status: model.EndpointActive, ExpiresAt: now.Add(time.Hour),
		AllowedCIDRs: []string{"192.0.2.0/24"}, AllowedPorts: []int{80, 443}, MaxConcurrent: 2,
		Capabilities: []model.WorkerCapability{model.WorkerCapabilityTCPConnect, model.WorkerCapabilityHTTP}}
	job := model.WorkerJob{SchemaVersion: 1, ID: "execute-job", WorkerID: worker.ID, ScanID: "scan", IssuedAt: now,
		ExpiresAt: now.Add(5 * time.Minute), Targets: []model.Target{{Name: "one", Address: "192.0.2.10"}, {Name: "two", Address: "192.0.2.11"}},
		Ports: []int{80, 443}, MaxConcurrent: 2, RateLimitPerSecond: 0,
		RequiredCapabilities: []model.WorkerCapability{model.WorkerCapabilityTCPConnect}, Status: model.WorkerJobPending,
		Resume: &model.WorkerJobResume{PreviousWorkerID: "previous", NextEvidenceSequence: 5,
			Completed: []model.WorkerCheckpoint{{Address: "192.0.2.10", Port: 80, CompletedAt: now.Add(-time.Minute)}}}}
	signer, err := workerjob.LoadOrCreateSigner(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := signer.Sign(job)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := OpenReplayLedger(filepath.Join(t.TempDir(), "state", "ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	inspector := &recordingInspector{}
	executor, err := NewExecutor(inspector, func(batch model.WorkerEvidenceBatch) (model.SignedWorkerEvidenceBatch, error) {
		return model.SignedWorkerEvidenceBatch{Batch: batch, Signature: "signed"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	executor.now = func() time.Time { return now }
	batches := []model.SignedWorkerEvidenceBatch{}
	summary, err := executor.Execute(context.Background(), envelope, signer.PublicKey(), worker, ledger,
		func(_ context.Context, batch model.SignedWorkerEvidenceBatch) error {
			batches = append(batches, batch)
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if summary.CompletedChecks != 3 || summary.SkippedChecks != 1 || summary.FinalSequence != 7 || len(batches) != 3 {
		t.Fatalf("unexpected execution summary or batches: %#v batches=%d", summary, len(batches))
	}
	if batches[0].Batch.Sequence != 5 || batches[2].Batch.Sequence != 7 || !batches[2].Batch.Final {
		t.Fatalf("resume evidence sequence was not preserved: %#v", batches)
	}
	if inspector.maximumActive > job.MaxConcurrent || len(inspector.checks) != 3 {
		t.Fatalf("executor exceeded concurrency or repeated checkpoints: max=%d checks=%v", inspector.maximumActive, inspector.checks)
	}
	for _, capabilities := range inspector.capabilities {
		if len(capabilities) != 1 || capabilities[0] != model.WorkerCapabilityTCPConnect {
			t.Fatalf("executor expanded signed capabilities: %v", capabilities)
		}
	}
}

func TestExecutorRejectsJobReplayBeforeInspection(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	worker := model.ScannerWorker{ID: "worker", Status: model.EndpointActive, ExpiresAt: now.Add(time.Hour),
		AllowedCIDRs: []string{"192.0.2.0/24"}, AllowedPorts: []int{443}, MaxConcurrent: 1,
		Capabilities: []model.WorkerCapability{model.WorkerCapabilityTCPConnect}}
	job := model.WorkerJob{SchemaVersion: 1, ID: "replay-job", WorkerID: worker.ID, ScanID: "scan", IssuedAt: now,
		ExpiresAt: now.Add(time.Minute), Targets: []model.Target{{Name: "one", Address: "192.0.2.10"}}, Ports: []int{443},
		MaxConcurrent: 1, RequiredCapabilities: []model.WorkerCapability{model.WorkerCapabilityTCPConnect}, Status: model.WorkerJobPending}
	signer, err := workerjob.LoadOrCreateSigner(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	envelope, _ := signer.Sign(job)
	ledger, err := OpenReplayLedger(filepath.Join(t.TempDir(), "state", "ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	inspector := &recordingInspector{}
	executor, _ := NewExecutor(inspector, func(batch model.WorkerEvidenceBatch) (model.SignedWorkerEvidenceBatch, error) {
		return model.SignedWorkerEvidenceBatch{Batch: batch}, nil
	})
	executor.now = func() time.Time { return now }
	emit := func(context.Context, model.SignedWorkerEvidenceBatch) error { return nil }
	if _, err := executor.Execute(context.Background(), envelope, signer.PublicKey(), worker, ledger, emit); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Execute(context.Background(), envelope, signer.PublicKey(), worker, ledger, emit); err != ErrJobReplay {
		t.Fatalf("replayed job reached executor: %v", err)
	}
}
