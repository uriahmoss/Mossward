package workerclient

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"mossward/internal/model"
	"mossward/internal/workerjob"
)

type runtimeTransport struct {
	lease      model.WorkerJobLease
	polls      int
	renewals   int
	delivered  []OutboxMessage
	forwardErr error
}

func (t *runtimeTransport) Poll(context.Context) (model.WorkerJobLease, error) {
	t.polls++
	if t.lease.Envelope.Job.ID == "" {
		return model.WorkerJobLease{}, ErrNoWorkerJob
	}
	lease := t.lease
	t.lease = model.WorkerJobLease{}
	return lease, nil
}

func (t *runtimeTransport) Renew(_ context.Context, renewal model.WorkerJobLeaseRenewal) (model.WorkerJobLeaseRenewal, error) {
	t.renewals++
	renewal.ExpiresAt = time.Now().UTC().Add(time.Minute)
	return renewal, nil
}

func (t *runtimeTransport) ForwardOutbox(ctx context.Context, outbox *Outbox, maximum int) (int, error) {
	if t.forwardErr != nil {
		return 0, t.forwardErr
	}
	return outbox.ForwardPending(ctx, maximum, func(_ context.Context, message OutboxMessage) error {
		t.delivered = append(t.delivered, message)
		return nil
	})
}

func TestRuntimePollsExecutesAndDeliversEvidenceBeforeCompletion(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	worker := model.ScannerWorker{ID: "worker", Status: model.EndpointActive, ExpiresAt: now.Add(time.Hour),
		AllowedCIDRs: []string{"192.0.2.0/24"}, AllowedPorts: []int{443}, MaxConcurrent: 1,
		Capabilities: []model.WorkerCapability{model.WorkerCapabilityTCPConnect}}
	job := model.WorkerJob{SchemaVersion: 1, ID: "job", WorkerID: worker.ID, ScanID: "scan", IssuedAt: now,
		ExpiresAt: now.Add(5 * time.Minute), Targets: []model.Target{{Name: "host", Address: "192.0.2.10"}}, Ports: []int{443},
		MaxConcurrent: 1, RequiredCapabilities: []model.WorkerCapability{model.WorkerCapabilityTCPConnect}, Status: model.WorkerJobPending}
	jobSigner, err := workerjob.LoadOrCreateSigner(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	envelope, _ := jobSigner.Sign(job)
	inspector := &recordingInspector{}
	executor, _ := NewExecutor(inspector, func(batch model.WorkerEvidenceBatch) (model.SignedWorkerEvidenceBatch, error) {
		return model.SignedWorkerEvidenceBatch{Batch: batch, Signature: "signed"}, nil
	})
	executor.now = func() time.Time { return now }
	state := filepath.Join(t.TempDir(), "state")
	outbox, ledger := runtimeState(t, state)
	transport := &runtimeTransport{lease: model.WorkerJobLease{Envelope: envelope, Token: "lease", ExpiresAt: now.Add(time.Minute)}}
	runtime, err := NewRuntime(transport, outbox, executor, worker, jobSigner.PublicKey(), ledger, DefaultBackpressurePolicy())
	if err != nil {
		t.Fatal(err)
	}
	runtime.now = func() time.Time { return now }
	if err := runtime.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if transport.polls != 1 || len(transport.delivered) != 2 || transport.delivered[0].Kind != OutboxEvidence || transport.delivered[1].Kind != OutboxCompletion {
		t.Fatalf("runtime delivery order is invalid: polls=%d delivered=%#v", transport.polls, transport.delivered)
	}
	var result model.WorkerJobResult
	if err := json.Unmarshal(transport.delivered[1].Payload, &result); err != nil || result.Outcome != model.WorkerJobResultSucceeded || result.JobID != job.ID {
		t.Fatalf("runtime completion is invalid: %#v %v", result, err)
	}
}

func TestRuntimeDoesNotPollWhenOutboxPressureCannotDrain(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	outbox, ledger := runtimeState(t, state)
	now := time.Now().UTC()
	for index := 0; index < 8; index++ {
		message := OutboxMessage{ID: string(rune('a' + index)), Kind: OutboxEvidence, Payload: []byte(`{}`), CreatedAt: now.Add(time.Duration(index))}
		if err := outbox.Enqueue(message); err != nil {
			t.Fatal(err)
		}
	}
	transport := &runtimeTransport{forwardErr: errors.New("offline")}
	executor, _ := NewExecutor(&recordingInspector{}, func(batch model.WorkerEvidenceBatch) (model.SignedWorkerEvidenceBatch, error) {
		return model.SignedWorkerEvidenceBatch{Batch: batch}, nil
	})
	publicKey, _, _ := ed25519.GenerateKey(nil)
	runtime, err := NewRuntime(transport, outbox, executor, model.ScannerWorker{ID: "worker"}, publicKey, ledger, DefaultBackpressurePolicy())
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if transport.polls != 0 {
		t.Fatalf("runtime polled while outbox was under pressure: %d", transport.polls)
	}
}

func runtimeState(t *testing.T, directory string) (*Outbox, *ReplayLedger) {
	t.Helper()
	outbox, err := OpenOutbox(filepath.Join(directory, "outbox.db"), filepath.Join(directory, "outbox.key"), OutboxLimits{MaxItems: 10, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := OpenReplayLedger(filepath.Join(directory, "ledger.db"))
	if err != nil {
		_ = outbox.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outbox.Close(); _ = ledger.Close() })
	return outbox, ledger
}
