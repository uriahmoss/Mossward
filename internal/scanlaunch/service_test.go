package scanlaunch

import (
	"errors"
	"testing"
	"time"

	"mossward/internal/model"
)

type launchStore struct{ scans []model.Scan }

func (s *launchStore) Save(scan model.Scan) error {
	s.scans = append(s.scans, scan)
	return nil
}

type localScheduler struct{ scans []model.Scan }

func (s *localScheduler) Schedule(scan model.Scan) error {
	s.scans = append(s.scans, scan)
	return nil
}

type remoteDispatcher struct {
	jobs []model.WorkerJob
	err  error
}

func (d *remoteDispatcher) Dispatch(job model.WorkerJob) (model.SignedWorkerJob, error) {
	if d.err != nil {
		return model.SignedWorkerJob{}, d.err
	}
	job.WorkerID = "worker"
	d.jobs = append(d.jobs, job)
	return model.SignedWorkerJob{Job: job}, nil
}

func TestLauncherRoutesLocalPolicyOnlyToLocalEngine(t *testing.T) {
	store := &launchStore{}
	local := &localScheduler{}
	remote := &remoteDispatcher{}
	launcher, err := New(store, local, remote)
	if err != nil {
		t.Fatal(err)
	}
	scan := launchScanFixture(time.Now().UTC())
	if err := launcher.Launch(scan, model.ReusableScanPolicy{ExecutionMode: model.ScanExecutionLocal}); err != nil {
		t.Fatal(err)
	}
	if len(local.scans) != 1 || len(remote.jobs) != 0 || len(store.scans) != 0 {
		t.Fatalf("local policy crossed execution boundaries: local=%d remote=%d stored=%d", len(local.scans), len(remote.jobs), len(store.scans))
	}
}

func TestLauncherCreatesScopedRemoteJobWithoutLocalFallback(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	store := &launchStore{}
	local := &localScheduler{}
	remote := &remoteDispatcher{}
	launcher, err := New(store, local, remote)
	if err != nil {
		t.Fatal(err)
	}
	launcher.now = func() time.Time { return now }
	scan := launchScanFixture(now)
	policy := model.ReusableScanPolicy{ExecutionMode: model.ScanExecutionRemote, WorkerSiteID: "chicago-hq"}
	if err := launcher.Launch(scan, policy); err != nil {
		t.Fatal(err)
	}
	if len(local.scans) != 0 || len(remote.jobs) != 1 || len(store.scans) != 1 {
		t.Fatalf("remote policy crossed execution boundaries: local=%d remote=%d stored=%d", len(local.scans), len(remote.jobs), len(store.scans))
	}
	job := remote.jobs[0]
	if job.ScanID != scan.ID || job.SiteID != policy.WorkerSiteID || job.MaxConcurrent != scan.MaxConcurrent ||
		job.RateLimitPerSecond != scan.RateLimitPerSecond || job.ExpiresAt.Sub(now) != defaultRemoteJobLifetime {
		t.Fatalf("remote job did not preserve policy scope: %#v", job)
	}
	wanted := []model.WorkerCapability{model.WorkerCapabilityTCPConnect, model.WorkerCapabilityServiceIdentification,
		model.WorkerCapabilityHTTP, model.WorkerCapabilityTLS, model.WorkerCapabilitySSH}
	if len(job.RequiredCapabilities) != len(wanted) {
		t.Fatalf("remote job capabilities are incomplete: %v", job.RequiredCapabilities)
	}
	for index := range wanted {
		if job.RequiredCapabilities[index] != wanted[index] {
			t.Fatalf("remote job capabilities are not deterministic: %v", job.RequiredCapabilities)
		}
	}
}

func TestLauncherFailsRemotePolicyWithoutLocalFallback(t *testing.T) {
	store := &launchStore{}
	local := &localScheduler{}
	launcher, err := New(store, local, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = launcher.Launch(launchScanFixture(time.Now().UTC()), model.ReusableScanPolicy{ExecutionMode: model.ScanExecutionRemote})
	if err == nil || len(local.scans) != 0 {
		t.Fatalf("unavailable remote dispatch fell back to local execution: local=%d err=%v", len(local.scans), err)
	}
	remote := &remoteDispatcher{err: errors.New("no eligible worker")}
	launcher, _ = New(store, local, remote)
	if err := launcher.Launch(launchScanFixture(time.Now().UTC()), model.ReusableScanPolicy{ExecutionMode: model.ScanExecutionRemote}); err == nil {
		t.Fatal("remote dispatcher failure was hidden")
	}
	if len(local.scans) != 0 || store.scans[len(store.scans)-1].Status != model.StatusFailed {
		t.Fatalf("failed remote launch fell back or was not recorded: local=%d scans=%#v", len(local.scans), store.scans)
	}
}

func launchScanFixture(now time.Time) model.Scan {
	return model.Scan{ID: "scan", Name: "Remote", Status: model.StatusQueued, CreatedAt: now,
		Targets: []model.Target{{Name: "host", Address: "192.0.2.10"}}, Ports: []int{22, 443},
		MaxConcurrent: 2, RateLimitPerSecond: 5, TotalChecks: 2}
}
