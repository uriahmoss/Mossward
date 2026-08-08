package workerjob

import (
	"errors"
	"log/slog"
	"sort"
	"sync"
	"time"

	"mossward/internal/model"
)

const assignmentHeartbeatFreshness = 5 * time.Minute

var ErrNoEligibleWorker = errors.New("no eligible scanner worker has sufficient capacity")
var ErrDispatchDisabled = errors.New("scanner-worker job dispatch is disabled")

type DispatchStore interface {
	ListScannerWorkers() ([]model.ScannerWorker, error)
	ScannerWorkerJobLoads(time.Time) (map[string]model.WorkerJobLoad, error)
	ScannerWorkerDispatchSettings() (model.WorkerDispatchSettings, error)
	CreateScannerWorkerJob(model.SignedWorkerJob, time.Time) error
	ScannerWorkerJobResumeCandidate(string, time.Time) (model.WorkerJobResumeCandidate, error)
	ReassignScannerWorkerJob(string, model.SignedWorkerJob, time.Time) error
}

type Dispatcher struct {
	store  DispatchStore
	signer *Signer
	now    func() time.Time
	mu     sync.Mutex
}

func NewDispatcher(repository DispatchStore, signer *Signer) (*Dispatcher, error) {
	if repository == nil || signer == nil {
		return nil, errors.New("scanner-worker dispatcher dependencies are unavailable")
	}
	return &Dispatcher{store: repository, signer: signer, now: func() time.Time { return time.Now().UTC() }}, nil
}

func (d *Dispatcher) Dispatch(job model.WorkerJob) (model.SignedWorkerJob, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	if err := d.requireDispatchEnabled(); err != nil {
		return model.SignedWorkerJob{}, err
	}
	workers, err := d.store.ListScannerWorkers()
	if err != nil {
		return model.SignedWorkerJob{}, err
	}
	loads, err := d.store.ScannerWorkerJobLoads(now)
	if err != nil {
		return model.SignedWorkerJob{}, err
	}
	worker, err := selectWorker(job, workers, loads, now)
	if err != nil {
		return model.SignedWorkerJob{}, err
	}
	job = jobForWorker(job, worker)
	envelope, err := d.signer.Sign(job)
	if err != nil {
		return model.SignedWorkerJob{}, err
	}
	if err := d.store.CreateScannerWorkerJob(envelope, now); err != nil {
		return model.SignedWorkerJob{}, err
	}
	slog.Info("Scanner-worker job dispatched", "job_id", job.ID, "scan_id", job.ScanID, "worker_id", worker.ID,
		"max_concurrent", job.MaxConcurrent, "rate_limit_per_second", job.RateLimitPerSecond)
	return envelope, nil
}

func (d *Dispatcher) ReassignExpired(jobID string) (model.SignedWorkerJob, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	if err := d.requireDispatchEnabled(); err != nil {
		return model.SignedWorkerJob{}, err
	}
	candidate, err := d.store.ScannerWorkerJobResumeCandidate(jobID, now)
	if err != nil {
		return model.SignedWorkerJob{}, err
	}
	previousWorkerID := candidate.Envelope.Job.WorkerID
	workers, err := d.store.ListScannerWorkers()
	if err != nil {
		return model.SignedWorkerJob{}, err
	}
	loads, err := d.store.ScannerWorkerJobLoads(now)
	if err != nil {
		return model.SignedWorkerJob{}, err
	}
	job := candidate.Envelope.Job
	job.WorkerID = ""
	job.Status = model.WorkerJobPending
	job.Resume = &model.WorkerJobResume{PreviousWorkerID: previousWorkerID, Completed: candidate.Completed,
		NextEvidenceSequence: candidate.NextEvidenceSequence}
	worker, err := selectWorkerExcluding(job, workers, loads, now, previousWorkerID)
	if err != nil {
		return model.SignedWorkerJob{}, err
	}
	job = jobForWorker(job, worker)
	envelope, err := d.signer.Sign(job)
	if err != nil {
		return model.SignedWorkerJob{}, err
	}
	if err := d.store.ReassignScannerWorkerJob(previousWorkerID, envelope, now); err != nil {
		return model.SignedWorkerJob{}, err
	}
	slog.Info("Scanner-worker job safely reassigned", "job_id", job.ID, "scan_id", job.ScanID,
		"previous_worker_id", previousWorkerID, "worker_id", worker.ID, "completed_checkpoints", len(candidate.Completed))
	return envelope, nil
}

func (d *Dispatcher) requireDispatchEnabled() error {
	settings, err := d.store.ScannerWorkerDispatchSettings()
	if err != nil {
		return err
	}
	if !settings.Enabled {
		return ErrDispatchDisabled
	}
	return nil
}

type workerCandidate struct {
	worker         model.ScannerWorker
	remaining      int
	activeJobs     int
	lastSeenUnixNS int64
}

func selectWorker(job model.WorkerJob, workers []model.ScannerWorker, loads map[string]model.WorkerJobLoad, now time.Time) (model.ScannerWorker, error) {
	return selectWorkerExcluding(job, workers, loads, now, "")
}

func selectWorkerExcluding(job model.WorkerJob, workers []model.ScannerWorker, loads map[string]model.WorkerJobLoad, now time.Time, excludedWorkerID string) (model.ScannerWorker, error) {
	candidates := make([]workerCandidate, 0, len(workers))
	for _, worker := range workers {
		if worker.ID == excludedWorkerID {
			continue
		}
		load := loads[worker.ID]
		remaining := worker.AvailableConcurrency - load.ReservedConcurrency
		if !workerAvailableForAssignment(worker, job, remaining, now) {
			continue
		}
		candidateJob := jobForWorker(job, worker)
		if Validate(candidateJob, worker, now) != nil {
			continue
		}
		candidates = append(candidates, workerCandidate{worker: worker, remaining: remaining - job.MaxConcurrent,
			activeJobs: load.ActiveJobs, lastSeenUnixNS: worker.LastSeenAt.UnixNano()})
	}
	if len(candidates) == 0 {
		return model.ScannerWorker{}, ErrNoEligibleWorker
	}
	sort.Slice(candidates, func(left, right int) bool {
		if candidates[left].activeJobs != candidates[right].activeJobs {
			return candidates[left].activeJobs < candidates[right].activeJobs
		}
		if candidates[left].remaining != candidates[right].remaining {
			return candidates[left].remaining > candidates[right].remaining
		}
		if candidates[left].lastSeenUnixNS != candidates[right].lastSeenUnixNS {
			return candidates[left].lastSeenUnixNS > candidates[right].lastSeenUnixNS
		}
		return candidates[left].worker.ID < candidates[right].worker.ID
	})
	return candidates[0].worker, nil
}

func jobForWorker(job model.WorkerJob, worker model.ScannerWorker) model.WorkerJob {
	job.WorkerID = worker.ID
	if job.RateLimitPerSecond == 0 && worker.RateLimitPerSecond > 0 {
		job.RateLimitPerSecond = worker.RateLimitPerSecond
	}
	return job
}

func workerAvailableForAssignment(worker model.ScannerWorker, job model.WorkerJob, remaining int, now time.Time) bool {
	if worker.Status != model.EndpointActive || !worker.DispatchEnabled || worker.Health != model.WorkerHealthHealthy || worker.LastSeenAt == nil {
		return false
	}
	if now.Sub(*worker.LastSeenAt) > assignmentHeartbeatFreshness || !now.Before(worker.ExpiresAt) || job.ExpiresAt.After(worker.ExpiresAt) {
		return false
	}
	if job.SiteID != "" && worker.SiteID != job.SiteID {
		return false
	}
	return remaining >= job.MaxConcurrent
}
