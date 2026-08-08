package workerjob

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"mossward/internal/model"
)

func TestSignedWorkerJobVerificationRejectsTampering(t *testing.T) {
	signer, err := LoadOrCreateSigner(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	job, worker := validWorkerJobFixture(time.Now().UTC())
	if err := Validate(job, worker, job.IssuedAt); err != nil {
		t.Fatal(err)
	}
	envelope, err := signer.Sign(job)
	if err != nil || VerifyForWorker(envelope, signer.PublicKey(), worker, job.IssuedAt) != nil {
		t.Fatalf("signed worker job did not verify: %v", err)
	}
	envelope.Job.Ports[0] = 22
	if err := Verify(envelope, signer.PublicKey()); err == nil {
		t.Fatal("tampered worker job signature was accepted")
	}
	unrelatedPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(envelope, unrelatedPublic); err == nil {
		t.Fatal("worker job signed by an unrelated key was accepted")
	}
}

func TestWorkerJobValidationEnforcesAssignedScope(t *testing.T) {
	now := time.Now().UTC()
	job, worker := validWorkerJobFixture(now)
	job.Targets[0].Address = "198.51.100.10"
	if err := Validate(job, worker, now); err == nil {
		t.Fatal("out-of-scope worker target was accepted")
	}
	job, worker = validWorkerJobFixture(now)
	job.RateLimitPerSecond = worker.RateLimitPerSecond + 1
	if err := Validate(job, worker, now); err == nil {
		t.Fatal("worker job exceeded its assigned rate")
	}
	job, worker = validWorkerJobFixture(now)
	job.RequiredCapabilities = []model.WorkerCapability{model.WorkerCapabilitySSH}
	if err := Validate(job, worker, now); err == nil {
		t.Fatal("unavailable worker capability was accepted")
	}
}

func TestWorkerJobValidationSupportsBoundedOvernightExecution(t *testing.T) {
	now := time.Now().UTC()
	job, worker := validWorkerJobFixture(now)
	worker.ExpiresAt = now.Add(25 * time.Hour)
	job.ExpiresAt = now.Add(12 * time.Hour)
	if err := Validate(job, worker, now); err != nil {
		t.Fatalf("bounded overnight worker job was rejected: %v", err)
	}
	job.ExpiresAt = now.Add(maximumJobLifetime + time.Second)
	if err := Validate(job, worker, now); err == nil {
		t.Fatal("worker job exceeded the maximum signed lifetime")
	}
}

func validWorkerJobFixture(now time.Time) (model.WorkerJob, model.ScannerWorker) {
	worker := model.ScannerWorker{ID: "worker-one", Status: model.EndpointActive, ExpiresAt: now.Add(time.Hour),
		AllowedCIDRs: []string{"192.0.2.0/24"}, AllowedPorts: []int{443}, MaxConcurrent: 4,
		RateLimitPerSecond: 10, Capabilities: []model.WorkerCapability{model.WorkerCapabilityTCPConnect}}
	job := model.WorkerJob{SchemaVersion: 1, ID: "job-one", WorkerID: worker.ID, ScanID: "scan-one",
		IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute), Targets: []model.Target{{Name: "host", Address: "192.0.2.10"}},
		Ports: []int{443}, MaxConcurrent: 2, RateLimitPerSecond: 5,
		RequiredCapabilities: []model.WorkerCapability{model.WorkerCapabilityTCPConnect}, Status: model.WorkerJobPending}
	return job, worker
}

func TestWorkerJobSigningKeyPersists(t *testing.T) {
	directory := t.TempDir()
	first, err := LoadOrCreateSigner(directory)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateSigner(directory)
	if err != nil || first.KeyID() != second.KeyID() {
		t.Fatalf("worker-job signing identity changed: %q %q %v", first.KeyID(), second.KeyID(), err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(directory, signingKeyFile))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != signingKeyMode {
			t.Fatalf("worker-job signing key permissions = %v", info.Mode().Perm())
		}
	}
}
