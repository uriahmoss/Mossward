package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
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
	loads, err := repository.ScannerWorkerJobLoads(now)
	if err != nil || loads[job.WorkerID].ActiveJobs != 1 || loads[job.WorkerID].ReservedConcurrency != job.MaxConcurrent {
		t.Fatalf("unexpected scanner-worker job load: %#v %v", loads, err)
	}
}

func TestScannerWorkerResultRejectsReplayAndLeaseReuse(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := repository.db.Exec(`INSERT INTO scanner_workers(id,name,status,certificate_serial,certificate_pem,allowed_cidrs,allowed_ports,max_concurrent,rate_limit_per_second,enrolled_at,expires_at) VALUES('worker','Worker','active','serial','certificate','["192.0.2.0/24"]','[443]',4,10,?,?)`, formatTime(now), formatTime(now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	job := model.WorkerJob{SchemaVersion: 1, ID: "result-job", WorkerID: "worker", ScanID: "scan", IssuedAt: now,
		ExpiresAt: now.Add(5 * time.Minute), Targets: []model.Target{{Name: "host", Address: "192.0.2.10"}}, Ports: []int{443}, Status: model.WorkerJobPending}
	if err := repository.CreateScannerWorkerJob(model.SignedWorkerJob{Job: job}, now); err != nil {
		t.Fatal(err)
	}
	rawToken := bytes.Repeat([]byte{7}, 32)
	token := base64.RawURLEncoding.EncodeToString(rawToken)
	tokenHash := sha256.Sum256([]byte(token))
	if _, err := repository.LeaseScannerWorkerJob("worker", tokenHash[:], now, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	receipt := model.WorkerJobResultReceipt{ResultID: "result", JobID: job.ID, WorkerID: "worker",
		Outcome: model.WorkerJobResultSucceeded, CompletedAt: now.Add(time.Second), AcceptedAt: now.Add(2 * time.Second)}
	if err := repository.CompleteScannerWorkerJob(receipt, tokenHash[:], receipt.AcceptedAt); !errors.Is(err, ErrInvalidWorkerJobLease) {
		t.Fatalf("successful scanner-worker result without final evidence was accepted: %v", err)
	}
	finalBatch := model.SignedWorkerEvidenceBatch{CertificateSerial: "serial", Batch: model.WorkerEvidenceBatch{SchemaVersion: 1,
		ID: "result-final", WorkerID: "worker", JobID: job.ID, ScanID: job.ScanID, Sequence: 1, Final: true, CollectedAt: now,
		Checkpoints: []model.WorkerCheckpoint{{Address: "192.0.2.10", Port: 443, CompletedAt: now}}}}
	if err := repository.RecordScannerWorkerEvidenceBatch(finalBatch, now); err != nil {
		t.Fatal(err)
	}
	if err := repository.CompleteScannerWorkerJob(receipt, tokenHash[:], receipt.AcceptedAt); err != nil {
		t.Fatalf("valid scanner-worker result was rejected: %v", err)
	}
	if err := repository.CompleteScannerWorkerJob(receipt, tokenHash[:], receipt.AcceptedAt); !errors.Is(err, ErrWorkerResultReplay) {
		t.Fatalf("duplicate scanner-worker result was accepted: %v", err)
	}
	receipt.ResultID = "different-result"
	if err := repository.CompleteScannerWorkerJob(receipt, tokenHash[:], receipt.AcceptedAt); !errors.Is(err, ErrInvalidWorkerJobLease) {
		t.Fatalf("consumed scanner-worker lease was reused: %v", err)
	}
	var status model.WorkerJobStatus
	var resultID, outcome, completedAt string
	var storedHash []byte
	if err := repository.db.QueryRow(`SELECT status,result_id,result_outcome,completed_at,lease_token_hash FROM scanner_worker_jobs WHERE id=?`, job.ID).Scan(&status, &resultID, &outcome, &completedAt, &storedHash); err != nil {
		t.Fatal(err)
	}
	if status != model.WorkerJobCompleted || resultID != "result" || outcome != string(model.WorkerJobResultSucceeded) || completedAt != formatTime(receipt.CompletedAt) || storedHash != nil {
		t.Fatalf("unexpected completed worker-job state: status=%s result=%s outcome=%s completed=%s hash=%x", status, resultID, outcome, completedAt, storedHash)
	}
}

func TestScannerWorkerEvidenceRequiresContiguousSequence(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := repository.db.Exec(`INSERT INTO scanner_workers(id,name,status,certificate_serial,certificate_pem,allowed_cidrs,allowed_ports,max_concurrent,rate_limit_per_second,enrolled_at,expires_at) VALUES('worker','Worker','active','serial','certificate','["192.0.2.0/24"]','[443]',4,10,?,?)`, formatTime(now), formatTime(now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	job := model.WorkerJob{SchemaVersion: 1, ID: "evidence-job", WorkerID: "worker", ScanID: "scan", IssuedAt: now,
		ExpiresAt: now.Add(5 * time.Minute), Targets: []model.Target{{Name: "host", Address: "192.0.2.10"}}, Ports: []int{443}, Status: model.WorkerJobPending}
	if err := repository.CreateScannerWorkerJob(model.SignedWorkerJob{Job: job}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.LeaseScannerWorkerJob("worker", []byte("lease"), now, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	batch := model.WorkerEvidenceBatch{SchemaVersion: 1, ID: "batch-1", WorkerID: "worker", JobID: job.ID,
		ScanID: job.ScanID, Sequence: 1, CollectedAt: now,
		Checkpoints: []model.WorkerCheckpoint{{Address: "192.0.2.10", Port: 443, CompletedAt: now}}}
	envelope := model.SignedWorkerEvidenceBatch{CertificateSerial: "serial", Batch: batch, Signature: "signature"}
	if err := repository.RecordScannerWorkerEvidenceBatch(envelope, now); err != nil {
		t.Fatalf("first worker evidence batch was rejected: %v", err)
	}
	checkpoints, err := repository.ScannerWorkerJobCheckpoints(job.ID)
	if err != nil || len(checkpoints) != 1 || checkpoints[0].Address != "192.0.2.10" || checkpoints[0].Port != 443 {
		t.Fatalf("scanner-worker checkpoint did not persist: %#v %v", checkpoints, err)
	}
	if err := repository.RecordScannerWorkerEvidenceBatch(envelope, now); !errors.Is(err, ErrWorkerEvidenceReplay) {
		t.Fatalf("worker evidence replay was accepted: %v", err)
	}
	envelope.Batch.ID, envelope.Batch.Sequence = "batch-3", 3
	if err := repository.RecordScannerWorkerEvidenceBatch(envelope, now); !errors.Is(err, ErrWorkerEvidenceSequence) {
		t.Fatalf("worker evidence sequence gap was accepted: %v", err)
	}
	envelope.Batch.ID, envelope.Batch.Sequence, envelope.Batch.Final = "batch-2", 2, true
	if err := repository.RecordScannerWorkerEvidenceBatch(envelope, now); err != nil {
		t.Fatalf("final worker evidence batch was rejected: %v", err)
	}
	checkpoints, err = repository.ScannerWorkerJobCheckpoints(job.ID)
	if err != nil || len(checkpoints) != 1 {
		t.Fatalf("duplicate scanner-worker checkpoint was not idempotent: %#v %v", checkpoints, err)
	}
	envelope.Batch.ID, envelope.Batch.Sequence, envelope.Batch.Final = "batch-after-final", 3, false
	if err := repository.RecordScannerWorkerEvidenceBatch(envelope, now); !errors.Is(err, ErrWorkerEvidenceSequence) {
		t.Fatalf("worker evidence after final batch was accepted: %v", err)
	}
}

func TestScannerWorkerJobLeaseIsBoundAndReclaimedAfterExpiry(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := repository.db.Exec(`INSERT INTO scanner_workers(id,name,status,certificate_serial,certificate_pem,allowed_cidrs,allowed_ports,max_concurrent,rate_limit_per_second,enrolled_at,expires_at) VALUES('worker','Worker','active','serial','certificate','["192.0.2.0/24"]','[443]',4,10,?,?)`, formatTime(now), formatTime(now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	job := model.WorkerJob{SchemaVersion: 1, ID: "leased-job", WorkerID: "worker", ScanID: "scan", IssuedAt: now,
		ExpiresAt: now.Add(5 * time.Minute), Status: model.WorkerJobPending}
	envelope := model.SignedWorkerJob{Algorithm: "Ed25519", KeyID: "key", Job: job, Signature: "signature"}
	if err := repository.CreateScannerWorkerJob(envelope, now); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.LeaseScannerWorkerJob("different-worker", []byte("wrong"), now, now.Add(time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("job was leased to a different worker: %v", err)
	}
	firstHash := []byte("first-hash")
	leased, err := repository.LeaseScannerWorkerJob("worker", firstHash, now, now.Add(time.Minute))
	if err != nil || leased.Job.ID != job.ID {
		t.Fatalf("job was not leased: %#v %v", leased, err)
	}
	if _, err := repository.LeaseScannerWorkerJob("worker", []byte("early"), now.Add(30*time.Second), now.Add(90*time.Second)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("active lease was issued twice: %v", err)
	}
	secondHash := []byte("second-hash")
	if _, err := repository.LeaseScannerWorkerJob("worker", secondHash, now.Add(2*time.Minute), now.Add(3*time.Minute)); err != nil {
		t.Fatalf("expired lease was not reclaimed: %v", err)
	}
	var status model.WorkerJobStatus
	var storedHash []byte
	var attempts int
	if err := repository.db.QueryRow(`SELECT status,lease_token_hash,lease_attempt FROM scanner_worker_jobs WHERE id=?`, job.ID).Scan(&status, &storedHash, &attempts); err != nil {
		t.Fatal(err)
	}
	if status != model.WorkerJobLeased || !bytes.Equal(storedHash, secondHash) || attempts != 2 {
		t.Fatalf("unexpected reclaimed lease state: status=%s hash=%q attempts=%d", status, storedHash, attempts)
	}
}

func TestScannerWorkerJobLeaseHonorsDispatchKillSwitches(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := repository.db.Exec(`INSERT INTO scanner_workers(id,name,status,certificate_serial,certificate_pem,allowed_cidrs,allowed_ports,max_concurrent,rate_limit_per_second,enrolled_at,expires_at) VALUES('worker','Worker','active','serial','certificate','["192.0.2.0/24"]','[443]',4,10,?,?)`, formatTime(now), formatTime(now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	job := model.WorkerJob{SchemaVersion: 1, ID: "controlled-job", WorkerID: "worker", ScanID: "scan", IssuedAt: now,
		ExpiresAt: now.Add(5 * time.Minute), Targets: []model.Target{{Name: "host", Address: "192.0.2.10"}}, Ports: []int{443}, Status: model.WorkerJobPending}
	if err := repository.CreateScannerWorkerJob(model.SignedWorkerJob{Job: job}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.db.Exec(`UPDATE scanner_worker_dispatch_settings SET enabled=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.LeaseScannerWorkerJob("worker", []byte("lease"), now, now.Add(time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("global dispatch kill switch allowed a lease: %v", err)
	}
	if _, err := repository.db.Exec(`UPDATE scanner_worker_dispatch_settings SET enabled=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.db.Exec(`UPDATE scanner_workers SET dispatch_enabled=0 WHERE id='worker'`); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.LeaseScannerWorkerJob("worker", []byte("lease"), now, now.Add(time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("per-worker dispatch kill switch allowed a lease: %v", err)
	}
}

func TestScannerWorkerJobLeaseRenewalIsBoundAndCapped(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := repository.db.Exec(`INSERT INTO scanner_workers(id,name,status,certificate_serial,certificate_pem,allowed_cidrs,allowed_ports,max_concurrent,rate_limit_per_second,enrolled_at,expires_at) VALUES('worker','Worker','active','serial','certificate','["192.0.2.0/24"]','[443]',4,10,?,?)`, formatTime(now), formatTime(now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	job := model.WorkerJob{SchemaVersion: 1, ID: "renew-job", WorkerID: "worker", ScanID: "scan", IssuedAt: now,
		ExpiresAt: now.Add(3 * time.Minute), Targets: []model.Target{{Name: "host", Address: "192.0.2.10"}}, Ports: []int{443}, Status: model.WorkerJobPending}
	if err := repository.CreateScannerWorkerJob(model.SignedWorkerJob{Job: job}, now); err != nil {
		t.Fatal(err)
	}
	tokenHash := []byte("lease-hash")
	if _, err := repository.LeaseScannerWorkerJob("worker", tokenHash, now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	renewed, err := repository.RenewScannerWorkerJobLease("worker", job.ID, tokenHash, now.Add(30*time.Second), now.Add(5*time.Minute))
	if err != nil || !renewed.Equal(job.ExpiresAt) {
		t.Fatalf("lease renewal was not capped by signed job expiry: %v %v", renewed, err)
	}
	if _, err := repository.RenewScannerWorkerJobLease("different", job.ID, tokenHash, now.Add(time.Minute), now.Add(2*time.Minute)); !errors.Is(err, ErrInvalidWorkerJobLease) {
		t.Fatalf("different worker renewed the lease: %v", err)
	}
	if _, err := repository.RenewScannerWorkerJobLease("worker", job.ID, []byte("wrong"), now.Add(time.Minute), now.Add(2*time.Minute)); !errors.Is(err, ErrInvalidWorkerJobLease) {
		t.Fatalf("wrong lease token renewed the lease: %v", err)
	}
}

func TestScannerWorkerJobReassignmentPreservesCheckpointsAndRejectsOldWorker(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, workerID := range []string{"old-worker", "new-worker"} {
		if _, err := repository.db.Exec(`INSERT INTO scanner_workers(id,name,status,certificate_serial,certificate_pem,allowed_cidrs,allowed_ports,max_concurrent,rate_limit_per_second,enrolled_at,expires_at) VALUES(?,?, 'active',?,?, '["192.0.2.0/24"]','[443]',4,10,?,?)`, workerID, workerID, workerID+"-serial", "certificate", formatTime(now), formatTime(now.Add(time.Hour))); err != nil {
			t.Fatal(err)
		}
	}
	job := model.WorkerJob{SchemaVersion: 1, ID: "reassign-job", WorkerID: "old-worker", ScanID: "scan", IssuedAt: now,
		ExpiresAt: now.Add(10 * time.Minute), Targets: []model.Target{{Name: "first", Address: "192.0.2.10"}, {Name: "second", Address: "192.0.2.11"}},
		Ports: []int{443}, MaxConcurrent: 1, RequiredCapabilities: []model.WorkerCapability{model.WorkerCapabilityTCPConnect}, Status: model.WorkerJobPending}
	if err := repository.CreateScannerWorkerJob(model.SignedWorkerJob{Job: job}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.LeaseScannerWorkerJob("old-worker", []byte("old-lease"), now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	first := model.SignedWorkerEvidenceBatch{CertificateSerial: "old-worker-serial", Batch: model.WorkerEvidenceBatch{SchemaVersion: 1,
		ID: "old-batch", WorkerID: "old-worker", JobID: job.ID, ScanID: job.ScanID, Sequence: 1, Final: true, CollectedAt: now,
		Checkpoints: []model.WorkerCheckpoint{{Address: "192.0.2.10", Port: 443, CompletedAt: now}}}}
	if err := repository.RecordScannerWorkerEvidenceBatch(first, now); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.ScannerWorkerJobResumeCandidate(job.ID, now.Add(30*time.Second)); !errors.Is(err, ErrWorkerJobNotResumable) {
		t.Fatalf("active lease was exposed for reassignment: %v", err)
	}
	resumeAt := now.Add(2 * time.Minute)
	candidate, err := repository.ScannerWorkerJobResumeCandidate(job.ID, resumeAt)
	if err != nil || candidate.NextEvidenceSequence != 2 || len(candidate.Completed) != 1 {
		t.Fatalf("unexpected resume candidate: %#v %v", candidate, err)
	}
	job.WorkerID = "new-worker"
	job.Resume = &model.WorkerJobResume{PreviousWorkerID: "old-worker", Completed: candidate.Completed, NextEvidenceSequence: 2}
	if err := repository.ReassignScannerWorkerJob("old-worker", model.SignedWorkerJob{Job: job, Signature: "replacement"}, resumeAt); err != nil {
		t.Fatal(err)
	}
	late := first
	late.Batch.ID, late.Batch.Sequence = "late-old-batch", 2
	if err := repository.RecordScannerWorkerEvidenceBatch(late, resumeAt); !errors.Is(err, ErrInvalidWorkerJobLease) {
		t.Fatalf("late evidence from old worker was accepted: %v", err)
	}
	if _, err := repository.LeaseScannerWorkerJob("new-worker", []byte("new-lease"), resumeAt, resumeAt.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	second := model.SignedWorkerEvidenceBatch{CertificateSerial: "new-worker-serial", Batch: model.WorkerEvidenceBatch{SchemaVersion: 1,
		ID: "new-batch", WorkerID: "new-worker", JobID: job.ID, ScanID: job.ScanID, Sequence: 2, Final: true, CollectedAt: resumeAt,
		Checkpoints: []model.WorkerCheckpoint{{Address: "192.0.2.11", Port: 443, CompletedAt: resumeAt}}}}
	if err := repository.RecordScannerWorkerEvidenceBatch(second, resumeAt); err != nil {
		t.Fatalf("replacement worker could not continue evidence sequence: %v", err)
	}
	var assignments int
	if err := repository.db.QueryRow(`SELECT COUNT(*) FROM scanner_worker_job_assignments WHERE job_id=?`, job.ID).Scan(&assignments); err != nil || assignments != 2 {
		t.Fatalf("assignment history was not preserved: count=%d err=%v", assignments, err)
	}
}
