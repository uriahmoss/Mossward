package scanlaunch

import (
	"errors"
	"fmt"
	"log/slog"
	"time"

	"mossward/internal/model"
)

const defaultRemoteJobLifetime = 12 * time.Hour

type LocalScheduler interface {
	Schedule(model.Scan) error
}

type RemoteDispatcher interface {
	Dispatch(model.WorkerJob) (model.SignedWorkerJob, error)
}

type ScanStore interface {
	Save(model.Scan) error
}

type Service struct {
	store       ScanStore
	local       LocalScheduler
	remote      RemoteDispatcher
	now         func() time.Time
	jobLifetime time.Duration
}

func New(repository ScanStore, local LocalScheduler, remote RemoteDispatcher) (*Service, error) {
	if repository == nil || local == nil {
		return nil, errors.New("scan-policy launcher dependencies are unavailable")
	}
	return &Service{store: repository, local: local, remote: remote, now: func() time.Time { return time.Now().UTC() },
		jobLifetime: defaultRemoteJobLifetime}, nil
}

func (s *Service) Launch(scan model.Scan, policy model.ReusableScanPolicy) error {
	if policy.ExecutionMode == "" || policy.ExecutionMode == model.ScanExecutionLocal {
		return s.local.Schedule(scan)
	}
	if policy.ExecutionMode != model.ScanExecutionRemote {
		return errors.New("scan policy execution mode is invalid")
	}
	if s.remote == nil {
		return errors.New("remote scanner-worker dispatch is unavailable")
	}
	return s.launchRemote(scan, policy)
}

func (s *Service) launchRemote(scan model.Scan, policy model.ReusableScanPolicy) error {
	now := s.now()
	expiresAt := now.Add(s.jobLifetime)
	if scan.WindowEnd != nil && scan.WindowEnd.Before(expiresAt) {
		expiresAt = *scan.WindowEnd
	}
	if !expiresAt.After(now) {
		return errors.New("remote scan execution window has ended")
	}
	scan.Status = model.StatusQueued
	if err := s.store.Save(scan); err != nil {
		return fmt.Errorf("persist remote scan before dispatch: %w", err)
	}
	job := model.WorkerJob{SchemaVersion: 1, ID: "scan-" + scan.ID, ScanID: scan.ID, SiteID: policy.WorkerSiteID,
		IssuedAt: now, ExpiresAt: expiresAt, Targets: scan.Targets, Ports: scan.Ports, MaxConcurrent: scan.MaxConcurrent,
		RateLimitPerSecond: scan.RateLimitPerSecond, RequiredCapabilities: requiredCapabilities(scan.Ports), Status: model.WorkerJobPending}
	envelope, err := s.remote.Dispatch(job)
	if err != nil {
		scan.Status = model.StatusFailed
		scan.Error = "remote scanner-worker dispatch failed"
		completedAt := s.now()
		scan.CompletedAt = &completedAt
		if saveErr := s.store.Save(scan); saveErr != nil {
			slog.Error("Could not persist failed remote scan", "scan_id", scan.ID, "error", saveErr)
		}
		return err
	}
	slog.Info("Remote scan policy dispatched", "scan_id", scan.ID, "job_id", envelope.Job.ID,
		"worker_id", envelope.Job.WorkerID, "site_id", policy.WorkerSiteID)
	return nil
}

func requiredCapabilities(ports []int) []model.WorkerCapability {
	required := map[model.WorkerCapability]bool{
		model.WorkerCapabilityTCPConnect:            true,
		model.WorkerCapabilityServiceIdentification: true,
	}
	for _, port := range ports {
		switch port {
		case 22:
			required[model.WorkerCapabilitySSH] = true
		case 80, 8080:
			required[model.WorkerCapabilityHTTP] = true
		case 443, 8443:
			required[model.WorkerCapabilityHTTP] = true
			required[model.WorkerCapabilityTLS] = true
		}
	}
	order := []model.WorkerCapability{model.WorkerCapabilityTCPConnect, model.WorkerCapabilityServiceIdentification,
		model.WorkerCapabilityHTTP, model.WorkerCapabilityTLS, model.WorkerCapabilitySSH}
	capabilities := make([]model.WorkerCapability, 0, len(required))
	for _, capability := range order {
		if required[capability] {
			capabilities = append(capabilities, capability)
		}
	}
	return capabilities
}
