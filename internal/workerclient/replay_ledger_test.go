package workerclient

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"mossward/internal/model"
	"mossward/internal/workerjob"
)

func TestReplayLedgerPersistsClaimsAcrossRestart(t *testing.T) {
	now := time.Now().UTC()
	envelope, worker, publicKey := signedJobFixture(t, now)
	path := filepath.Join(t.TempDir(), "state", "replay.db")
	ledger, err := OpenReplayLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAndClaim(envelope, publicKey, worker, ledger, now); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	ledger, err = OpenReplayLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	if err := VerifyAndClaim(envelope, publicKey, worker, ledger, now); !errors.Is(err, ErrJobReplay) {
		t.Fatalf("persisted scanner-worker job replay was accepted: %v", err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != replayLedgerFileMode {
			t.Fatalf("replay ledger permissions = %v", info.Mode().Perm())
		}
	}
}

func TestReplayLedgerAllowsOnlyOneConcurrentClaim(t *testing.T) {
	now := time.Now().UTC()
	envelope, worker, publicKey := signedJobFixture(t, now)
	ledger, err := OpenReplayLedger(filepath.Join(t.TempDir(), "state", "replay.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	var accepted atomic.Int32
	var unexpected atomic.Int32
	var group sync.WaitGroup
	for range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			err := VerifyAndClaim(envelope, publicKey, worker, ledger, now)
			if err == nil {
				accepted.Add(1)
				return
			}
			if !errors.Is(err, ErrJobReplay) {
				unexpected.Add(1)
			}
		}()
	}
	group.Wait()
	if accepted.Load() != 1 || unexpected.Load() != 0 {
		t.Fatalf("concurrent claims accepted=%d unexpected=%d", accepted.Load(), unexpected.Load())
	}
}

func TestReplayLedgerRecordsOnlyVerifiedJobs(t *testing.T) {
	now := time.Now().UTC()
	envelope, worker, publicKey := signedJobFixture(t, now)
	ledger, err := OpenReplayLedger(filepath.Join(t.TempDir(), "state", "replay.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	tampered := envelope
	tampered.Job.Ports = []int{22}
	if err := VerifyAndClaim(tampered, publicKey, worker, ledger, now); err == nil {
		t.Fatal("tampered scanner-worker job was accepted")
	}
	if err := VerifyAndClaim(envelope, publicKey, worker, ledger, now); err != nil {
		t.Fatalf("valid job was blocked after rejected tampering: %v", err)
	}
}

func TestReplayLedgerRejectsBroadStateDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission test")
	}
	directory := filepath.Join(t.TempDir(), "broad-state")
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenReplayLedger(filepath.Join(directory, "replay.db")); err == nil {
		t.Fatal("broad scanner-worker state directory was accepted")
	}
}

func signedJobFixture(t *testing.T, now time.Time) (model.SignedWorkerJob, model.ScannerWorker, ed25519.PublicKey) {
	t.Helper()
	signer, err := workerjob.LoadOrCreateSigner(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	worker := model.ScannerWorker{ID: "worker", Status: model.EndpointActive, ExpiresAt: now.Add(time.Hour),
		AllowedCIDRs: []string{"192.0.2.0/24"}, AllowedPorts: []int{443}, MaxConcurrent: 4,
		RateLimitPerSecond: 10, Capabilities: []model.WorkerCapability{model.WorkerCapabilityTCPConnect}}
	job := model.WorkerJob{SchemaVersion: 1, ID: "job", WorkerID: worker.ID, ScanID: "scan", IssuedAt: now,
		ExpiresAt: now.Add(5 * time.Minute), Targets: []model.Target{{Name: "host", Address: "192.0.2.10"}},
		Ports: []int{443}, MaxConcurrent: 2, RateLimitPerSecond: 5,
		RequiredCapabilities: []model.WorkerCapability{model.WorkerCapabilityTCPConnect}, Status: model.WorkerJobPending}
	envelope, err := signer.Sign(job)
	if err != nil {
		t.Fatal(err)
	}
	return envelope, worker, signer.PublicKey()
}
