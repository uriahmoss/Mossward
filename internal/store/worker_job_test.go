package store

import (
	"errors"
	"testing"
	"time"

	"mossward/internal/model"
)

func TestScannerWorkerJobIdentityIsImmutableAndReplayProtected(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := repository.db.Exec(`INSERT INTO scanner_workers(id,name,status,certificate_serial,certificate_pem,allowed_cidrs,allowed_ports,max_concurrent,rate_limit_per_second,enrolled_at,expires_at) VALUES('worker','Worker','active','serial','certificate','["192.0.2.0/24"]','[443]',4,10,?,?)`, formatTime(now), formatTime(now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	job := model.WorkerJob{SchemaVersion: 1, ID: "job", WorkerID: "worker", ScanID: "scan", IssuedAt: now,
		ExpiresAt: now.Add(5 * time.Minute), Targets: []model.Target{{Name: "host", Address: "192.0.2.1"}},
		Ports: []int{443}, MaxConcurrent: 2, RateLimitPerSecond: 5,
		RequiredCapabilities: []model.WorkerCapability{model.WorkerCapabilityTCPConnect}, Status: model.WorkerJobPending}
	envelope := model.SignedWorkerJob{Algorithm: "Ed25519", KeyID: "key", Job: job, Signature: "signature"}
	if err := repository.CreateScannerWorkerJob(envelope, now); err != nil {
		t.Fatal(err)
	}
	if err := repository.CreateScannerWorkerJob(envelope, now); !errors.Is(err, ErrWorkerJobReplay) {
		t.Fatalf("worker-job replay was accepted: %v", err)
	}
	loaded, err := repository.ScannerWorkerJob(job.ID)
	if err != nil || loaded.Signature != envelope.Signature || loaded.Job.WorkerID != job.WorkerID {
		t.Fatalf("signed worker job did not round-trip: %#v %v", loaded, err)
	}
}
