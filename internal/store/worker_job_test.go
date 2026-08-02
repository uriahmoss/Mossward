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
