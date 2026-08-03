package workerclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"mossward/internal/model"
)

const maximumExecutionEvidenceItems = 250

type ScopedInspector interface {
	InspectScoped(context.Context, model.Target, int, []model.WorkerCapability) (model.ServiceObservation, []model.Finding, bool)
}

type EvidenceSigner func(model.WorkerEvidenceBatch) (model.SignedWorkerEvidenceBatch, error)
type EvidenceEmitter func(context.Context, model.SignedWorkerEvidenceBatch) error

type ExecutionSummary struct {
	CompletedChecks int
	SkippedChecks   int
	FinalSequence   uint64
}

type Executor struct {
	inspector ScopedInspector
	sign      EvidenceSigner
	now       func() time.Time
}

type executionCheck struct {
	target model.Target
	port   int
}

type executionResult struct {
	check       executionCheck
	observation *model.ServiceObservation
	findings    []model.Finding
	completedAt time.Time
}

func NewExecutor(inspector ScopedInspector, signer EvidenceSigner) (*Executor, error) {
	if inspector == nil || signer == nil {
		return nil, errors.New("scanner-worker executor dependencies are unavailable")
	}
	return &Executor{inspector: inspector, sign: signer, now: func() time.Time { return time.Now().UTC() }}, nil
}

func (e *Executor) Execute(ctx context.Context, envelope model.SignedWorkerJob, publicKey ed25519.PublicKey,
	worker model.ScannerWorker, ledger *ReplayLedger, emit EvidenceEmitter) (ExecutionSummary, error) {
	if emit == nil {
		return ExecutionSummary{}, errors.New("scanner-worker evidence emitter is unavailable")
	}
	now := e.now()
	if err := VerifyAndClaim(envelope, publicKey, worker, ledger, now); err != nil {
		return ExecutionSummary{}, err
	}
	return e.executeClaimed(ctx, envelope.Job, emit)
}

func (e *Executor) executeClaimed(ctx context.Context, job model.WorkerJob, emit EvidenceEmitter) (ExecutionSummary, error) {
	ctx, cancel := context.WithDeadline(ctx, job.ExpiresAt)
	defer cancel()
	checks, skipped := pendingExecutionChecks(job)
	sequence := uint64(1)
	if job.Resume != nil {
		sequence = job.Resume.NextEvidenceSequence
	}
	summary := ExecutionSummary{SkippedChecks: skipped, FinalSequence: sequence - 1}
	slog.Info("Scanner-worker execution started", "job_id", job.ID, "scan_id", job.ScanID,
		"pending_checks", len(checks), "skipped_checks", skipped, "max_concurrent", job.MaxConcurrent)
	if len(checks) == 0 {
		if err := e.emitResult(ctx, job, executionResult{}, sequence, true, emit); err != nil {
			slog.Error("Scanner-worker final evidence emission failed", "job_id", job.ID, "error", err)
			return summary, err
		}
		summary.FinalSequence = sequence
		slog.Info("Scanner-worker execution completed", "job_id", job.ID, "completed_checks", 0,
			"skipped_checks", summary.SkippedChecks, "final_sequence", summary.FinalSequence)
		return summary, nil
	}
	jobs := make(chan executionCheck)
	results := make(chan executionResult)
	e.startExecutionWorkers(ctx, job, jobs, results)
	go queueExecutionChecks(ctx, checks, job.RateLimitPerSecond, jobs)
	for result := range results {
		final := summary.CompletedChecks+1 == len(checks)
		if err := e.emitResult(ctx, job, result, sequence, final, emit); err != nil {
			cancel()
			slog.Error("Scanner-worker evidence emission failed", "job_id", job.ID, "sequence", sequence, "error", err)
			return summary, err
		}
		summary.CompletedChecks++
		summary.FinalSequence = sequence
		sequence++
	}
	if err := ctx.Err(); err != nil {
		slog.Warn("Scanner-worker execution interrupted", "job_id", job.ID, "completed_checks", summary.CompletedChecks, "error", err)
		return summary, fmt.Errorf("scanner-worker execution interrupted: %w", err)
	}
	slog.Info("Scanner-worker execution completed", "job_id", job.ID, "completed_checks", summary.CompletedChecks,
		"skipped_checks", summary.SkippedChecks, "final_sequence", summary.FinalSequence)
	return summary, nil
}

func pendingExecutionChecks(job model.WorkerJob) ([]executionCheck, int) {
	completed := map[string]bool{}
	if job.Resume != nil {
		for _, checkpoint := range job.Resume.Completed {
			completed[executionCheckKey(checkpoint.Address, checkpoint.Port)] = true
		}
	}
	checks := make([]executionCheck, 0, len(job.Targets)*len(job.Ports)-len(completed))
	for _, target := range job.Targets {
		for _, port := range job.Ports {
			if completed[executionCheckKey(target.Address, port)] {
				continue
			}
			checks = append(checks, executionCheck{target: target, port: port})
		}
	}
	return checks, len(completed)
}

func executionCheckKey(address string, port int) string { return fmt.Sprintf("%s:%d", address, port) }

func (e *Executor) startExecutionWorkers(ctx context.Context, job model.WorkerJob, jobs <-chan executionCheck, results chan<- executionResult) {
	var workers sync.WaitGroup
	for range job.MaxConcurrent {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for check := range jobs {
				observation, findings, reachable := e.inspector.InspectScoped(ctx, check.target, check.port, job.RequiredCapabilities)
				result := executionResult{check: check, findings: findings, completedAt: e.now()}
				if reachable {
					result.observation = &observation
				}
				select {
				case results <- result:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		workers.Wait()
		close(results)
	}()
}

func queueExecutionChecks(ctx context.Context, checks []executionCheck, rate int, jobs chan<- executionCheck) {
	defer close(jobs)
	var pace <-chan time.Time
	var ticker *time.Ticker
	if rate > 0 {
		ticker = time.NewTicker(time.Second / time.Duration(rate))
		defer ticker.Stop()
		pace = ticker.C
	}
	for _, check := range checks {
		if pace != nil {
			select {
			case <-pace:
			case <-ctx.Done():
				return
			}
		}
		select {
		case jobs <- check:
		case <-ctx.Done():
			return
		}
	}
}

func (e *Executor) emitResult(ctx context.Context, job model.WorkerJob, result executionResult, sequence uint64, final bool, emit EvidenceEmitter) error {
	itemCount := len(result.findings) + 1
	if result.observation != nil {
		itemCount++
	}
	if result.check.target.Address != "" && itemCount > maximumExecutionEvidenceItems {
		return errors.New("scanner-worker check produced an oversized evidence batch")
	}
	batchID, err := randomExecutionID()
	if err != nil {
		return err
	}
	batch := model.WorkerEvidenceBatch{SchemaVersion: 1, ID: batchID, WorkerID: job.WorkerID, JobID: job.ID,
		ScanID: job.ScanID, Sequence: sequence, Final: final, CollectedAt: e.now()}
	if result.check.target.Address != "" {
		batch.Checkpoints = []model.WorkerCheckpoint{{Address: result.check.target.Address, Port: result.check.port, CompletedAt: result.completedAt}}
		if result.observation != nil {
			batch.Observations = []model.ServiceObservation{*result.observation}
		}
		batch.Findings = result.findings
	}
	envelope, err := e.sign(batch)
	if err != nil {
		return err
	}
	return emit(ctx, envelope)
}

func randomExecutionID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("create scanner-worker evidence identifier: %w", err)
	}
	return hex.EncodeToString(value), nil
}
