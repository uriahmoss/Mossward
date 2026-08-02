package workerjob

import (
	"crypto/ed25519"
	"errors"
	"net/netip"
	"time"

	"mossward/internal/model"
)

func VerifyForWorker(envelope model.SignedWorkerJob, publicKey ed25519.PublicKey, worker model.ScannerWorker, now time.Time) error {
	if err := Verify(envelope, publicKey); err != nil {
		return err
	}
	return Validate(envelope.Job, worker, now)
}

const (
	jobSchemaVersion   = 1
	maximumJobLifetime = 15 * time.Minute
	jobClockSkew       = time.Minute
	jobIdentityLimit   = 200
	maximumJobRate     = 1000
)

func Validate(job model.WorkerJob, worker model.ScannerWorker, now time.Time) error {
	if job.SchemaVersion != jobSchemaVersion || job.Status != model.WorkerJobPending {
		return errors.New("worker job schema or initial status is invalid")
	}
	if !validJobIdentities(job) || job.WorkerID != worker.ID {
		return errors.New("worker job identity is invalid")
	}
	if job.IssuedAt.After(now.Add(jobClockSkew)) || !job.ExpiresAt.After(now) ||
		!job.ExpiresAt.After(job.IssuedAt) || job.ExpiresAt.Sub(job.IssuedAt) > maximumJobLifetime {
		return errors.New("worker job validity period is invalid")
	}
	if worker.Status != model.EndpointActive || !now.Before(worker.ExpiresAt) {
		return errors.New("scanner worker is not active")
	}
	if err := validateJobResources(job, worker); err != nil {
		return err
	}
	if err := validateJobTargets(job.Targets, worker.AllowedCIDRs); err != nil {
		return err
	}
	if err := validateJobPorts(job.Ports, worker.AllowedPorts); err != nil {
		return err
	}
	return validateJobCapabilities(job.RequiredCapabilities, worker.Capabilities)
}

func validJobIdentities(job model.WorkerJob) bool {
	return job.ID != "" && len(job.ID) <= jobIdentityLimit && job.WorkerID != "" &&
		len(job.WorkerID) <= jobIdentityLimit && job.ScanID != "" && len(job.ScanID) <= jobIdentityLimit
}

func validateJobResources(job model.WorkerJob, worker model.ScannerWorker) error {
	if job.MaxConcurrent < 1 || job.MaxConcurrent > worker.MaxConcurrent {
		return errors.New("worker job concurrency exceeds the assigned worker scope")
	}
	if job.RateLimitPerSecond < 0 || job.RateLimitPerSecond > maximumJobRate {
		return errors.New("worker job rate limit is invalid")
	}
	if worker.RateLimitPerSecond > 0 && (job.RateLimitPerSecond == 0 || job.RateLimitPerSecond > worker.RateLimitPerSecond) {
		return errors.New("worker job rate exceeds the assigned worker scope")
	}
	return nil
}

func validateJobTargets(targets []model.Target, allowedCIDRs []string) error {
	if len(targets) == 0 {
		return errors.New("worker job requires at least one target")
	}
	prefixes := make([]netip.Prefix, 0, len(allowedCIDRs))
	for _, raw := range allowedCIDRs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return errors.New("scanner worker has an invalid assigned network")
		}
		prefixes = append(prefixes, prefix)
	}
	seen := map[netip.Addr]bool{}
	for _, target := range targets {
		address, err := netip.ParseAddr(target.Address)
		if err != nil || seen[address] || !addressAllowed(address, prefixes) {
			return errors.New("worker job contains a duplicate, invalid, or out-of-scope target")
		}
		seen[address] = true
	}
	return nil
}

func addressAllowed(address netip.Addr, prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func validateJobPorts(ports, allowedPorts []int) error {
	if len(ports) == 0 {
		return errors.New("worker job requires at least one port")
	}
	allowed := map[int]bool{}
	for _, port := range allowedPorts {
		allowed[port] = true
	}
	seen := map[int]bool{}
	for _, port := range ports {
		if !allowed[port] || seen[port] {
			return errors.New("worker job contains a duplicate or out-of-scope port")
		}
		seen[port] = true
	}
	return nil
}

func validateJobCapabilities(required, reported []model.WorkerCapability) error {
	if len(required) == 0 {
		return errors.New("worker job requires at least one capability")
	}
	available := map[model.WorkerCapability]bool{}
	for _, capability := range reported {
		available[capability] = true
	}
	seen := map[model.WorkerCapability]bool{}
	for _, capability := range required {
		if !available[capability] || seen[capability] {
			return errors.New("worker job contains a duplicate or unavailable capability")
		}
		seen[capability] = true
	}
	return nil
}
