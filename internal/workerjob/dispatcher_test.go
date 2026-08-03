package workerjob

import (
	"errors"
	"sync"
	"testing"
	"time"

	"mossward/internal/model"
)

type dispatchMemoryStore struct {
	mu      sync.Mutex
	workers []model.ScannerWorker
	jobs    []model.SignedWorkerJob
}

func (s *dispatchMemoryStore) ListScannerWorkers() ([]model.ScannerWorker, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]model.ScannerWorker(nil), s.workers...), nil
}

func (s *dispatchMemoryStore) ScannerWorkerJobLoads(now time.Time) (map[string]model.WorkerJobLoad, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	loads := map[string]model.WorkerJobLoad{}
	for _, envelope := range s.jobs {
		if !now.Before(envelope.Job.ExpiresAt) {
			continue
		}
		load := loads[envelope.Job.WorkerID]
		load.ActiveJobs++
		load.ReservedConcurrency += envelope.Job.MaxConcurrent
		loads[envelope.Job.WorkerID] = load
	}
	return loads, nil
}

func (s *dispatchMemoryStore) CreateScannerWorkerJob(envelope model.SignedWorkerJob, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jobs = append(s.jobs, envelope)
	return nil
}

func TestDispatcherSelectsFreshHealthyWorkerWithAvailableCapacity(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	workers := []model.ScannerWorker{
		workerSelectionFixture("busy", now),
		workerSelectionFixture("selected", now),
		workerSelectionFixture("stale", now.Add(-10*time.Minute)),
	}
	workers[2].LastSeenAt = timePointer(now.Add(-10 * time.Minute))
	repository := &dispatchMemoryStore{workers: workers, jobs: []model.SignedWorkerJob{{Job: model.WorkerJob{
		ID: "existing", WorkerID: "busy", MaxConcurrent: 3, ExpiresAt: now.Add(time.Minute)}}}}
	signer, err := LoadOrCreateSigner(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := NewDispatcher(repository, signer)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.now = func() time.Time { return now }
	job := dispatchJobFixture("new-job", now)
	envelope, err := dispatcher.Dispatch(job)
	if err != nil || envelope.Job.WorkerID != "selected" || len(repository.jobs) != 2 {
		t.Fatalf("unexpected worker assignment: %#v jobs=%d err=%v", envelope, len(repository.jobs), err)
	}
	if err := VerifyForWorker(envelope, signer.PublicKey(), workers[1], now); err != nil {
		t.Fatalf("dispatched job signature or scope is invalid: %v", err)
	}
}

func TestDispatcherRejectsWorkersWithoutCapacityOrScope(t *testing.T) {
	now := time.Now().UTC()
	worker := workerSelectionFixture("worker", now)
	worker.AvailableConcurrency = 1
	repository := &dispatchMemoryStore{workers: []model.ScannerWorker{worker}}
	signer, err := LoadOrCreateSigner(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := NewDispatcher(repository, signer)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.now = func() time.Time { return now }
	if _, err := dispatcher.Dispatch(dispatchJobFixture("job", now)); !errors.Is(err, ErrNoEligibleWorker) {
		t.Fatalf("job exceeded available worker capacity: %v", err)
	}
}

func workerSelectionFixture(id string, now time.Time) model.ScannerWorker {
	return model.ScannerWorker{ID: id, Status: model.EndpointActive, ExpiresAt: now.Add(time.Hour), LastSeenAt: timePointer(now),
		AllowedCIDRs: []string{"192.0.2.0/24"}, AllowedPorts: []int{443}, MaxConcurrent: 4, AvailableConcurrency: 4,
		RateLimitPerSecond: 10, Health: model.WorkerHealthHealthy,
		Capabilities: []model.WorkerCapability{model.WorkerCapabilityTCPConnect}}
}

func dispatchJobFixture(id string, now time.Time) model.WorkerJob {
	return model.WorkerJob{SchemaVersion: 1, ID: id, ScanID: "scan", IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute),
		Targets: []model.Target{{Name: "host", Address: "192.0.2.10"}}, Ports: []int{443}, MaxConcurrent: 2,
		RateLimitPerSecond: 5, RequiredCapabilities: []model.WorkerCapability{model.WorkerCapabilityTCPConnect}, Status: model.WorkerJobPending}
}

func timePointer(value time.Time) *time.Time { return &value }
