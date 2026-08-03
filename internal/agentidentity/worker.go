package agentidentity

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"mossward/internal/model"
	"mossward/internal/store"
)

const (
	maximumWorkerConcurrency = 256
	maximumWorkerRate        = 1000
	workerHeartbeatSchema    = 1
	workerHeartbeatTextLimit = 200
	workerHealthMessageLimit = 500
	workerOfflineAfter       = 5 * time.Minute
	workerSiteIDLimit        = 64
)

var workerSiteIDPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

type WorkerStore interface {
	CreateWorkerEnrollmentToken(model.WorkerEnrollmentToken, model.AuditEvent) error
	WorkerEnrollmentToken([]byte, time.Time) (model.WorkerEnrollmentToken, error)
	ConsumeWorkerEnrollmentToken([]byte, model.ScannerWorker, time.Time, model.AuditEvent) error
	ListScannerWorkers() ([]model.ScannerWorker, error)
	ScannerWorkerBySerial(string) (model.ScannerWorker, error)
	RecordScannerWorkerHeartbeat(string, model.WorkerHeartbeat, time.Time) error
	RevokeScannerWorker(string, string, time.Time, model.AuditEvent) error
	ScannerWorkerDispatchSettings() (model.WorkerDispatchSettings, error)
	SetScannerWorkerDispatch(bool, model.AuditEvent) error
	SetScannerWorkerDispatchForWorker(string, bool, model.AuditEvent) error
	LeaseScannerWorkerJob(string, []byte, time.Time, time.Time) (model.SignedWorkerJob, error)
	CompleteScannerWorkerJob(model.WorkerJobResultReceipt, []byte, time.Time) error
	ScannerWorkerJob(string) (model.SignedWorkerJob, error)
	RecordScannerWorkerEvidenceBatch(model.SignedWorkerEvidenceBatch, time.Time) error
}

type WorkerEnrollmentResult struct {
	Worker              model.ScannerWorker `json:"worker"`
	CertificatePEM      string              `json:"certificate_pem"`
	CAChainPEM          string              `json:"ca_chain_pem"`
	JobSigningKeyID     string              `json:"job_signing_key_id"`
	JobSigningPublicKey string              `json:"job_signing_public_key"`
}

func (s *Service) CreateWorkerEnrollmentToken(request model.WorkerEnrollmentToken, actorID, sourceIP string) (model.WorkerEnrollmentToken, string, error) {
	if s.workerStore == nil {
		return request, "", errors.New("scanner-worker identity storage is unavailable")
	}
	request.Name = strings.TrimSpace(request.Name)
	if err := validateWorkerEnrollment(&request); err != nil {
		return request, "", err
	}
	id, token, hash, err := newEnrollmentToken()
	if err != nil {
		return request, "", err
	}
	now := s.now()
	request.ID, request.TokenHash, request.CreatedBy = id, hash, actorID
	request.CreatedAt, request.ExpiresAt = now, now.Add(enrollmentTokenLifetime)
	event := model.AuditEvent{OccurredAt: now, ActorID: actorID, Action: "scanner_worker.enrollment_token.created",
		Severity: model.AuditWarning, TargetType: "scanner_worker_enrollment", TargetID: id, SourceIP: sourceIP, Details: "{}"}
	if err := s.workerStore.CreateWorkerEnrollmentToken(request, event); err != nil {
		return request, "", err
	}
	return request, token, nil
}

func validateWorkerEnrollment(request *model.WorkerEnrollmentToken) error {
	if request.Name == "" || len(request.Name) > endpointNameLimit {
		return errors.New("worker name must be between 1 and 200 characters")
	}
	request.SiteID = strings.ToLower(strings.TrimSpace(request.SiteID))
	if len(request.SiteID) > workerSiteIDLimit || (request.SiteID != "" && !workerSiteIDPattern.MatchString(request.SiteID)) {
		return errors.New("worker site ID must contain lowercase letters, numbers, and single hyphens")
	}
	if len(request.AllowedCIDRs) == 0 || len(request.AllowedPorts) == 0 {
		return errors.New("worker requires at least one allowed network and port")
	}
	cidrs := make([]string, 0, len(request.AllowedCIDRs))
	seenCIDRs := map[string]bool{}
	for _, raw := range request.AllowedCIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return errors.New("worker contains an invalid allowed network")
		}
		normalized := prefix.Masked().String()
		if !seenCIDRs[normalized] {
			cidrs = append(cidrs, normalized)
			seenCIDRs[normalized] = true
		}
	}
	request.AllowedCIDRs = cidrs
	ports := append([]int(nil), request.AllowedPorts...)
	sort.Ints(ports)
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return errors.New("worker contains an invalid allowed port")
		}
	}
	request.AllowedPorts = deduplicateWorkerPorts(ports)
	if request.MaxConcurrent < 1 || request.MaxConcurrent > maximumWorkerConcurrency {
		return errors.New("worker concurrency must be between 1 and 256")
	}
	if request.RateLimitPerSecond < 0 || request.RateLimitPerSecond > maximumWorkerRate {
		return errors.New("worker rate limit must be between 0 and 1000 checks per second")
	}
	return nil
}

func deduplicateWorkerPorts(ports []int) []int {
	result := ports[:0]
	for _, port := range ports {
		if len(result) == 0 || result[len(result)-1] != port {
			result = append(result, port)
		}
	}
	return result
}

func (s *Service) EnrollWorker(token, csrPEM, sourceIP string) (WorkerEnrollmentResult, error) {
	if s.jobSigner == nil {
		return WorkerEnrollmentResult{}, errors.New("scanner-worker job signing is unavailable")
	}
	hash, err := enrollmentTokenHash(token)
	if err != nil || s.workerStore == nil {
		return WorkerEnrollmentResult{}, store.ErrInvalidEnrollmentToken
	}
	now := s.now()
	enrollment, err := s.workerStore.WorkerEnrollmentToken(hash, now)
	if err != nil {
		return WorkerEnrollmentResult{}, store.ErrInvalidEnrollmentToken
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return WorkerEnrollmentResult{}, err
	}
	id := hex.EncodeToString(idBytes)
	serial, certificatePEM, expiresAt, err := s.pki.IssueScannerWorker(id, enrollment.Name, []byte(csrPEM), now)
	if err != nil {
		return WorkerEnrollmentResult{}, err
	}
	worker := model.ScannerWorker{ID: id, Name: enrollment.Name, Status: model.EndpointActive,
		SiteID: enrollment.SiteID, DispatchEnabled: true,
		CertificateSerial: serial, CertificatePEM: certificatePEM, AllowedCIDRs: enrollment.AllowedCIDRs,
		AllowedPorts: enrollment.AllowedPorts, MaxConcurrent: enrollment.MaxConcurrent,
		RateLimitPerSecond: enrollment.RateLimitPerSecond, EnrolledAt: now, ExpiresAt: expiresAt}
	event := model.AuditEvent{OccurredAt: now, Action: "scanner_worker.enrolled", Severity: model.AuditInfo,
		TargetType: "scanner_worker", TargetID: id, SourceIP: sourceIP, Details: "{}"}
	if err := s.workerStore.ConsumeWorkerEnrollmentToken(hash, worker, now, event); err != nil {
		return WorkerEnrollmentResult{}, err
	}
	return WorkerEnrollmentResult{Worker: worker, CertificatePEM: certificatePEM, CAChainPEM: s.pki.CAChainPEM(),
		JobSigningKeyID: s.jobSigner.KeyID(), JobSigningPublicKey: base64.RawStdEncoding.EncodeToString(s.jobSigner.PublicKey())}, nil
}

func (s *Service) ScannerWorkers() ([]model.ScannerWorker, error) {
	if s.workerStore == nil {
		return nil, errors.New("scanner-worker identity storage is unavailable")
	}
	workers, err := s.workerStore.ListScannerWorkers()
	if err != nil {
		return nil, err
	}
	for index := range workers {
		workers[index].Alerts = scannerWorkerAlerts(workers[index], s.now())
	}
	return workers, nil
}

func scannerWorkerAlerts(worker model.ScannerWorker, now time.Time) []model.EndpointAlert {
	if worker.Status == model.EndpointRevoked {
		return []model.EndpointAlert{{Code: "certificate_revoked", Severity: "error", Message: "Scanner-worker certificate is revoked"}}
	}
	if !now.Before(worker.ExpiresAt) {
		return []model.EndpointAlert{{Code: "certificate_expired", Severity: "error", Message: "Scanner-worker certificate has expired"}}
	}
	alerts := []model.EndpointAlert{}
	if !now.Before(worker.ExpiresAt.Add(-certificateRenewBefore)) {
		alerts = append(alerts, model.EndpointAlert{Code: "certificate_expiring", Severity: "warning", Message: "Scanner-worker certificate expires within 30 days"})
	}
	if worker.LastSeenAt == nil || now.Sub(*worker.LastSeenAt) >= workerOfflineAfter {
		alerts = append(alerts, model.EndpointAlert{Code: "worker_offline", Severity: "warning", Message: "Scanner worker has not checked in within 5 minutes"})
	}
	if worker.Health == model.WorkerHealthDegraded {
		alerts = append(alerts, model.EndpointAlert{Code: "worker_degraded", Severity: "warning", Message: worker.HealthMessage})
	}
	return alerts
}

func validateWorkerHeartbeat(heartbeat *model.WorkerHeartbeat, maximumConcurrency int) error {
	heartbeat.SoftwareVersion = strings.TrimSpace(heartbeat.SoftwareVersion)
	heartbeat.OperatingSystem = strings.ToLower(strings.TrimSpace(heartbeat.OperatingSystem))
	heartbeat.Architecture = strings.ToLower(strings.TrimSpace(heartbeat.Architecture))
	heartbeat.HealthMessage = strings.TrimSpace(heartbeat.HealthMessage)
	if heartbeat.SchemaVersion != workerHeartbeatSchema {
		return errors.New("unsupported scanner-worker heartbeat schema")
	}
	if heartbeat.SoftwareVersion == "" || len(heartbeat.SoftwareVersion) > workerHeartbeatTextLimit {
		return errors.New("scanner-worker software version is invalid")
	}
	if heartbeat.OperatingSystem != "linux" && heartbeat.OperatingSystem != "windows" {
		return errors.New("scanner-worker operating system is unsupported")
	}
	if heartbeat.Architecture != "amd64" && heartbeat.Architecture != "arm64" {
		return errors.New("scanner-worker architecture is unsupported")
	}
	if heartbeat.AvailableConcurrency < 0 || heartbeat.AvailableConcurrency > maximumConcurrency {
		return errors.New("scanner-worker available concurrency exceeds its assigned limit")
	}
	if heartbeat.Health != model.WorkerHealthHealthy && heartbeat.Health != model.WorkerHealthDegraded {
		return errors.New("scanner-worker health state is invalid")
	}
	if len(heartbeat.HealthMessage) > workerHealthMessageLimit || (heartbeat.Health == model.WorkerHealthDegraded && heartbeat.HealthMessage == "") {
		return errors.New("degraded scanner-worker health requires a bounded message")
	}
	capabilities, err := normalizedWorkerCapabilities(heartbeat.Capabilities)
	if err != nil {
		return err
	}
	heartbeat.Capabilities = capabilities
	return nil
}

func normalizedWorkerCapabilities(values []model.WorkerCapability) ([]model.WorkerCapability, error) {
	allowed := map[model.WorkerCapability]bool{
		model.WorkerCapabilityTCPConnect: true, model.WorkerCapabilityServiceIdentification: true,
		model.WorkerCapabilityHTTP: true, model.WorkerCapabilityTLS: true, model.WorkerCapabilitySSH: true,
	}
	seen := map[model.WorkerCapability]bool{}
	result := []model.WorkerCapability{}
	for _, capability := range values {
		if !allowed[capability] {
			return nil, errors.New("scanner worker reported an unsupported capability")
		}
		if !seen[capability] {
			result = append(result, capability)
			seen[capability] = true
		}
	}
	if len(result) == 0 {
		return nil, errors.New("scanner worker must report at least one capability")
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result, nil
}

func (s *Service) RevokeScannerWorker(id, reason, actorID, sourceIP string) error {
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > revocationReasonLimit {
		return errors.New("revocation reason must be between 1 and 500 characters")
	}
	now := s.now()
	event := model.AuditEvent{OccurredAt: now, ActorID: actorID, Action: "scanner_worker.revoked",
		Severity: model.AuditWarning, TargetType: "scanner_worker", TargetID: id, SourceIP: sourceIP, Details: "{}"}
	return s.workerStore.RevokeScannerWorker(id, reason, now, event)
}

func (s *Service) WorkerDispatchSettings() (model.WorkerDispatchSettings, error) {
	if s.workerStore == nil {
		return model.WorkerDispatchSettings{}, errors.New("scanner-worker identity storage is unavailable")
	}
	return s.workerStore.ScannerWorkerDispatchSettings()
}

func (s *Service) SetWorkerDispatch(enabled bool, actorID, sourceIP string) error {
	now := s.now()
	event := model.AuditEvent{OccurredAt: now, ActorID: actorID, Action: "scanner_worker.dispatch.updated",
		Severity: model.AuditWarning, TargetType: "scanner_worker_fleet", TargetID: "global", SourceIP: sourceIP,
		Details: `{"enabled":` + strconv.FormatBool(enabled) + `}`}
	return s.workerStore.SetScannerWorkerDispatch(enabled, event)
}

func (s *Service) SetWorkerDispatchForWorker(id string, enabled bool, actorID, sourceIP string) error {
	now := s.now()
	event := model.AuditEvent{OccurredAt: now, ActorID: actorID, Action: "scanner_worker.dispatch.updated",
		Severity: model.AuditWarning, TargetType: "scanner_worker", TargetID: id, SourceIP: sourceIP,
		Details: `{"enabled":` + strconv.FormatBool(enabled) + `}`}
	return s.workerStore.SetScannerWorkerDispatchForWorker(id, enabled, event)
}
