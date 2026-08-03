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

type DispatchStore interface {
	ListScannerWorkers() ([]model.ScannerWorker, error)
	ScannerWorkerJobLoads(time.Time) (map[string]model.WorkerJobLoad, error)
	CreateScannerWorkerJob(model.SignedWorkerJob, time.Time) error
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
	job.WorkerID = worker.ID
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

type workerCandidate struct {
	worker         model.ScannerWorker
	remaining      int
	activeJobs     int
	lastSeenUnixNS int64
}

func selectWorker(job model.WorkerJob, workers []model.ScannerWorker, loads map[string]model.WorkerJobLoad, now time.Time) (model.ScannerWorker, error) {
	candidates := make([]workerCandidate, 0, len(workers))
	for _, worker := range workers {
		load := loads[worker.ID]
		remaining := worker.AvailableConcurrency - load.ReservedConcurrency
		if !workerAvailableForAssignment(worker, job, remaining, now) {
			continue
		}
		candidateJob := job
		candidateJob.WorkerID = worker.ID
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

func workerAvailableForAssignment(worker model.ScannerWorker, job model.WorkerJob, remaining int, now time.Time) bool {
	if worker.Status != model.EndpointActive || worker.Health != model.WorkerHealthHealthy || worker.LastSeenAt == nil {
		return false
	}
	if now.Sub(*worker.LastSeenAt) > assignmentHeartbeatFreshness || !now.Before(worker.ExpiresAt) {
		return false
	}
	return remaining >= job.MaxConcurrent
}
