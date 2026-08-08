package workerclient

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"mossward/internal/model"
)

const (
	defaultRuntimeForwardLimit = 100
	defaultLeaseRenewInterval  = 30 * time.Second
)

type RuntimeTransport interface {
	Poll(context.Context) (model.WorkerJobLease, error)
	Renew(context.Context, model.WorkerJobLeaseRenewal) (model.WorkerJobLeaseRenewal, error)
	ForwardOutbox(context.Context, *Outbox, int) (int, error)
}

type Runtime struct {
	transport     RuntimeTransport
	outbox        *Outbox
	executor      *Executor
	worker        model.ScannerWorker
	jobPublicKey  ed25519.PublicKey
	ledger        *ReplayLedger
	backpressure  BackpressurePolicy
	now           func() time.Time
	renewInterval time.Duration
}

func NewRuntime(transport RuntimeTransport, outbox *Outbox, executor *Executor, worker model.ScannerWorker,
	jobPublicKey ed25519.PublicKey, ledger *ReplayLedger, backpressure BackpressurePolicy) (*Runtime, error) {
	if transport == nil || outbox == nil || executor == nil || ledger == nil || len(jobPublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("scanner-worker runtime dependencies are unavailable")
	}
	if err := validateBackpressurePolicy(backpressure); err != nil {
		return nil, err
	}
	return &Runtime{transport: transport, outbox: outbox, executor: executor, worker: worker,
		jobPublicKey: append(ed25519.PublicKey(nil), jobPublicKey...), ledger: ledger, backpressure: backpressure,
		now: func() time.Time { return time.Now().UTC() }, renewInterval: defaultLeaseRenewInterval}, nil
}

func (r *Runtime) RunOnce(ctx context.Context) error {
	if _, err := r.transport.ForwardOutbox(ctx, r.outbox, defaultRuntimeForwardLimit); err != nil {
		slog.Warn("Scanner-worker pending delivery deferred", "error", err)
	}
	if paused, err := r.pollingPaused(); err != nil {
		return err
	} else if paused {
		slog.Warn("Scanner-worker polling paused by outbox pressure")
		return nil
	}
	lease, err := r.transport.Poll(ctx)
	if errors.Is(err, ErrNoWorkerJob) {
		return nil
	}
	if err != nil {
		return err
	}
	return r.executeLease(ctx, lease)
}

func (r *Runtime) pollingPaused() (bool, error) {
	state, err := r.outbox.Backpressure(r.backpressure)
	if err != nil {
		return false, err
	}
	return !state.AcceptNewJobs, nil
}

func (r *Runtime) executeLease(ctx context.Context, lease model.WorkerJobLease) error {
	executionCtx, cancel := context.WithCancel(ctx)
	renewed := make(chan error, 1)
	go func() {
		err := r.renewLease(executionCtx, lease)
		if err != nil {
			cancel()
		}
		renewed <- err
	}()
	emit := func(emitCtx context.Context, envelope model.SignedWorkerEvidenceBatch) error {
		return r.queueEvidence(emitCtx, envelope)
	}
	_, executionErr := r.executor.Execute(executionCtx, lease.Envelope, r.jobPublicKey, r.worker, r.ledger, emit)
	cancel()
	renewalErr := <-renewed
	if renewalErr != nil {
		executionErr = renewalErr
	}
	outcome := model.WorkerJobResultSucceeded
	if executionErr != nil {
		outcome = model.WorkerJobResultFailed
		if errors.Is(executionErr, context.Canceled) || errors.Is(executionErr, context.DeadlineExceeded) {
			outcome = model.WorkerJobResultCanceled
		}
	}
	if err := r.queueCompletion(ctx, lease, outcome); err != nil {
		return err
	}
	if _, err := r.transport.ForwardOutbox(ctx, r.outbox, defaultRuntimeForwardLimit); err != nil {
		return fmt.Errorf("forward scanner-worker completion: %w", err)
	}
	return executionErr
}

func (r *Runtime) queueEvidence(ctx context.Context, envelope model.SignedWorkerEvidenceBatch) error {
	payload, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	if err := r.outbox.Enqueue(OutboxMessage{ID: envelope.Batch.ID, Kind: OutboxEvidence, Payload: payload, CreatedAt: r.now()}); err != nil {
		return err
	}
	if _, err := r.transport.ForwardOutbox(ctx, r.outbox, 1); err != nil {
		slog.Warn("Scanner-worker evidence retained for retry", "job_id", envelope.Batch.JobID,
			"batch_id", envelope.Batch.ID, "error", err)
	}
	return nil
}

func (r *Runtime) queueCompletion(ctx context.Context, lease model.WorkerJobLease, outcome model.WorkerJobResultOutcome) error {
	resultID, err := randomExecutionID()
	if err != nil {
		return err
	}
	result := model.WorkerJobResult{SchemaVersion: 1, ID: resultID, JobID: lease.Envelope.Job.ID,
		LeaseToken: lease.Token, Outcome: outcome, CompletedAt: r.now()}
	payload, err := json.Marshal(result)
	if err != nil {
		return err
	}
	return r.outbox.Enqueue(OutboxMessage{ID: resultID, Kind: OutboxCompletion, Payload: payload, CreatedAt: r.now()})
}

func (r *Runtime) renewLease(ctx context.Context, lease model.WorkerJobLease) error {
	ticker := time.NewTicker(r.renewInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			renewal, err := r.transport.Renew(ctx, model.WorkerJobLeaseRenewal{JobID: lease.Envelope.Job.ID, LeaseToken: lease.Token})
			if err != nil {
				return fmt.Errorf("renew scanner-worker job lease: %w", err)
			}
			lease.ExpiresAt = renewal.ExpiresAt
			slog.Info("Scanner-worker job lease renewed", "job_id", lease.Envelope.Job.ID, "lease_expires_at", renewal.ExpiresAt)
		}
	}
}
