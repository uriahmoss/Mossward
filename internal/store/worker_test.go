package store

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"mossward/internal/model"
)

func TestScannerWorkerEnrollmentTokenIsScopedAndSingleUse(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := repository.db.Exec(`INSERT INTO users(id,email,display_name,role,status,created_at,updated_at) VALUES('admin','admin@example.test','Admin','administrator','active',?,?)`, formatTime(now), formatTime(now)); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte("worker-token"))
	token := model.WorkerEnrollmentToken{ID: "token", Name: "Branch", SiteID: "chicago-hq", TokenHash: hash[:], AllowedCIDRs: []string{"192.0.2.0/24"},
		AllowedPorts: []int{22, 443}, MaxConcurrent: 4, RateLimitPerSecond: 10, CreatedBy: "admin", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	event := model.AuditEvent{OccurredAt: now, ActorID: "admin", Action: "test", Severity: model.AuditInfo, Details: "{}"}
	if err := repository.CreateWorkerEnrollmentToken(token, event); err != nil {
		t.Fatal(err)
	}
	loaded, err := repository.WorkerEnrollmentToken(hash[:], now)
	if err != nil || loaded.SiteID != token.SiteID || len(loaded.AllowedCIDRs) != 1 || loaded.MaxConcurrent != token.MaxConcurrent {
		t.Fatalf("worker enrollment scope missing: %#v %v", loaded, err)
	}
	worker := model.ScannerWorker{ID: "worker", Name: loaded.Name, SiteID: loaded.SiteID, Status: model.EndpointActive, CertificateSerial: "123",
		CertificatePEM: "certificate", AllowedCIDRs: loaded.AllowedCIDRs, AllowedPorts: loaded.AllowedPorts,
		MaxConcurrent: loaded.MaxConcurrent, RateLimitPerSecond: loaded.RateLimitPerSecond, EnrolledAt: now, ExpiresAt: now.Add(24 * time.Hour)}
	if err := repository.ConsumeWorkerEnrollmentToken(hash[:], worker, now, event); err != nil {
		t.Fatal(err)
	}
	if err := repository.ConsumeWorkerEnrollmentToken(hash[:], worker, now, event); !errors.Is(err, ErrInvalidEnrollmentToken) {
		t.Fatalf("worker enrollment token replay accepted: %v", err)
	}
	workers, err := repository.ListScannerWorkers()
	if err != nil || len(workers) != 1 || workers[0].SiteID != token.SiteID || workers[0].AllowedPorts[1] != 443 || !workers[0].DispatchEnabled {
		t.Fatalf("scanner-worker inventory missing: %#v %v", workers, err)
	}
	settings, err := repository.ScannerWorkerDispatchSettings()
	if err != nil || !settings.Enabled {
		t.Fatalf("scanner-worker dispatch did not default enabled: %#v %v", settings, err)
	}
	if err := repository.SetScannerWorkerDispatch(false, event); err != nil {
		t.Fatal(err)
	}
	if err := repository.SetScannerWorkerDispatchForWorker(worker.ID, false, event); err != nil {
		t.Fatal(err)
	}
	settings, err = repository.ScannerWorkerDispatchSettings()
	workers, workersErr := repository.ListScannerWorkers()
	if err != nil || workersErr != nil || settings.Enabled || workers[0].DispatchEnabled {
		t.Fatalf("scanner-worker dispatch controls were not persisted: settings=%#v workers=%#v errors=%v %v", settings, workers, err, workersErr)
	}
	heartbeat := model.WorkerHeartbeat{SchemaVersion: 1, SoftwareVersion: "1.0.0", OperatingSystem: "linux",
		Architecture: "amd64", Capabilities: []model.WorkerCapability{model.WorkerCapabilityTCPConnect},
		AvailableConcurrency: 3, Health: model.WorkerHealthHealthy}
	if err := repository.RecordScannerWorkerHeartbeat(worker.ID, heartbeat, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	workers, err = repository.ListScannerWorkers()
	if err != nil || workers[0].SoftwareVersion != heartbeat.SoftwareVersion || workers[0].AvailableConcurrency != 3 || workers[0].LastSeenAt == nil {
		t.Fatalf("scanner-worker heartbeat missing: %#v %v", workers, err)
	}
}
