package agentidentity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"mossward/internal/agentmodule"
	"mossward/internal/model"
	"mossward/internal/store"
	"mossward/internal/workerevidence"
	"mossward/internal/workerjob"
)

type memoryEndpointStore struct {
	token                model.AgentEnrollmentToken
	endpoint             model.Endpoint
	consumed             bool
	lastSeen             *time.Time
	heartbeatGeneratedAt *time.Time
	heartbeatReceivedAt  *time.Time
	workerToken          model.WorkerEnrollmentToken
	worker               model.ScannerWorker
	workerConsumed       bool
	workerLastSeen       *time.Time
	workerJob            model.SignedWorkerJob
	workerLeaseHash      []byte
	workerResult         model.WorkerJobResultReceipt
	leasedWorkerJob      model.SignedWorkerJob
	workerEvidence       []model.SignedWorkerEvidenceBatch
	dispatchEnabled      bool
}

func (s *memoryEndpointStore) CreateWorkerEnrollmentToken(token model.WorkerEnrollmentToken, _ model.AuditEvent) error {
	s.workerToken = token
	return nil
}
func (s *memoryEndpointStore) WorkerEnrollmentToken(hash []byte, now time.Time) (model.WorkerEnrollmentToken, error) {
	if s.workerConsumed || !bytes.Equal(hash, s.workerToken.TokenHash) || !now.Before(s.workerToken.ExpiresAt) {
		return model.WorkerEnrollmentToken{}, store.ErrInvalidEnrollmentToken
	}
	return s.workerToken, nil
}
func (s *memoryEndpointStore) ConsumeWorkerEnrollmentToken(hash []byte, worker model.ScannerWorker, _ time.Time, _ model.AuditEvent) error {
	if s.workerConsumed || !bytes.Equal(hash, s.workerToken.TokenHash) {
		return store.ErrInvalidEnrollmentToken
	}
	s.workerConsumed, s.worker = true, worker
	return nil
}
func (s *memoryEndpointStore) ListScannerWorkers() ([]model.ScannerWorker, error) {
	return []model.ScannerWorker{s.worker}, nil
}
func (s *memoryEndpointStore) ScannerWorkerJobLoads(time.Time) (map[string]model.WorkerJobLoad, error) {
	return map[string]model.WorkerJobLoad{}, nil
}
func (s *memoryEndpointStore) ScannerWorkerBySerial(serial string) (model.ScannerWorker, error) {
	if serial != s.worker.CertificateSerial {
		return model.ScannerWorker{}, store.ErrNotFound
	}
	return s.worker, nil
}
func (s *memoryEndpointStore) RecordScannerWorkerHeartbeat(id string, heartbeat model.WorkerHeartbeat, seenAt time.Time) error {
	if id != s.worker.ID {
		return store.ErrNotFound
	}
	s.worker.SoftwareVersion, s.worker.OperatingSystem, s.worker.Architecture = heartbeat.SoftwareVersion, heartbeat.OperatingSystem, heartbeat.Architecture
	s.worker.Capabilities, s.worker.AvailableConcurrency = heartbeat.Capabilities, heartbeat.AvailableConcurrency
	s.worker.Health, s.worker.HealthMessage, s.workerLastSeen = heartbeat.Health, heartbeat.HealthMessage, &seenAt
	return nil
}
func (s *memoryEndpointStore) RevokeScannerWorker(id, reason string, revokedAt time.Time, _ model.AuditEvent) error {
	if id != s.worker.ID || s.worker.Status != model.EndpointActive {
		return store.ErrNotFound
	}
	s.worker.Status, s.worker.RevocationReason, s.worker.RevokedAt = model.EndpointRevoked, reason, &revokedAt
	return nil
}
func (s *memoryEndpointStore) ScannerWorkerDispatchSettings() (model.WorkerDispatchSettings, error) {
	return model.WorkerDispatchSettings{Enabled: s.dispatchEnabled}, nil
}
func (s *memoryEndpointStore) SetScannerWorkerDispatch(enabled bool, _ model.AuditEvent) error {
	s.dispatchEnabled = enabled
	return nil
}
func (s *memoryEndpointStore) SetScannerWorkerDispatchForWorker(id string, enabled bool, _ model.AuditEvent) error {
	if id != s.worker.ID {
		return store.ErrNotFound
	}
	s.worker.DispatchEnabled = enabled
	return nil
}
func (s *memoryEndpointStore) LeaseScannerWorkerJob(id string, hash []byte, _, _ time.Time) (model.SignedWorkerJob, error) {
	if id != s.worker.ID || s.workerJob.Job.ID == "" {
		return model.SignedWorkerJob{}, store.ErrNotFound
	}
	s.workerLeaseHash = append([]byte(nil), hash...)
	job := s.workerJob
	s.workerJob = model.SignedWorkerJob{}
	s.leasedWorkerJob = job
	return job, nil
}
func (s *memoryEndpointStore) RenewScannerWorkerJobLease(id, jobID string, hash []byte, _, expiresAt time.Time) (time.Time, error) {
	if id != s.worker.ID || jobID != s.leasedWorkerJob.Job.ID || !bytes.Equal(hash, s.workerLeaseHash) {
		return time.Time{}, store.ErrInvalidWorkerJobLease
	}
	return expiresAt, nil
}
func (s *memoryEndpointStore) CompleteScannerWorkerJob(receipt model.WorkerJobResultReceipt, hash []byte, _ time.Time) error {
	if receipt.WorkerID != s.worker.ID || len(hash) != sha256.Size {
		return store.ErrInvalidWorkerJobLease
	}
	if s.workerResult.ResultID == receipt.ResultID {
		if s.workerResult.JobID == receipt.JobID && s.workerResult.WorkerID == receipt.WorkerID && s.workerResult.Outcome == receipt.Outcome && s.workerResult.CompletedAt.Equal(receipt.CompletedAt) {
			return store.ErrWorkerResultAlreadyAccepted
		}
		return store.ErrWorkerResultReplay
	}
	s.workerResult = receipt
	return nil
}
func (s *memoryEndpointStore) ScannerWorkerJob(id string) (model.SignedWorkerJob, error) {
	if s.leasedWorkerJob.Job.ID != id {
		return model.SignedWorkerJob{}, store.ErrNotFound
	}
	return s.leasedWorkerJob, nil
}
func (s *memoryEndpointStore) RecordScannerWorkerEvidenceBatch(envelope model.SignedWorkerEvidenceBatch, _ time.Time) error {
	for _, existing := range s.workerEvidence {
		if existing.Batch.ID == envelope.Batch.ID {
			if reflect.DeepEqual(existing, envelope) {
				return store.ErrWorkerEvidenceAlreadyAccepted
			}
			return store.ErrWorkerEvidenceReplay
		}
	}
	s.workerEvidence = append(s.workerEvidence, envelope)
	return nil
}
func (s *memoryEndpointStore) ScannerWorkerJobCheckpoints(string) ([]model.WorkerCheckpoint, error) {
	checkpoints := []model.WorkerCheckpoint{}
	for _, envelope := range s.workerEvidence {
		checkpoints = append(checkpoints, envelope.Batch.Checkpoints...)
	}
	return checkpoints, nil
}

func (s *memoryEndpointStore) CreateAgentEnrollmentToken(token model.AgentEnrollmentToken, _ model.AuditEvent) error {
	s.token = token
	return nil
}
func (s *memoryEndpointStore) ListAgentEnrollmentTokens(time.Time) ([]model.AgentEnrollmentToken, error) {
	return []model.AgentEnrollmentToken{s.token}, nil
}
func (s *memoryEndpointStore) AgentEnrollmentTokenName(hash []byte, now time.Time) (string, error) {
	if s.consumed || !bytes.Equal(hash, s.token.TokenHash) || !now.Before(s.token.ExpiresAt) {
		return "", store.ErrInvalidEnrollmentToken
	}
	return s.token.Name, nil
}
func (s *memoryEndpointStore) ConsumeAgentEnrollmentToken(hash []byte, endpoint model.Endpoint, _ time.Time, _ model.AuditEvent) error {
	if s.consumed || !bytes.Equal(hash, s.token.TokenHash) {
		return store.ErrInvalidEnrollmentToken
	}
	s.consumed = true
	s.endpoint = endpoint
	return nil
}
func (s *memoryEndpointStore) ListEndpoints() ([]model.Endpoint, error) {
	return []model.Endpoint{s.endpoint}, nil
}
func (s *memoryEndpointStore) EndpointBySerial(serial string) (model.Endpoint, error) {
	if serial != s.endpoint.CertificateSerial {
		return model.Endpoint{}, store.ErrNotFound
	}
	return s.endpoint, nil
}
func (s *memoryEndpointStore) MarkEndpointSeen(id string, seenAt time.Time) error {
	if id != s.endpoint.ID {
		return errors.New("unknown endpoint")
	}
	s.lastSeen = &seenAt
	return nil
}
func (s *memoryEndpointStore) RecordEndpointCheckIn(id string, checkIn model.AgentCheckIn, seenAt time.Time) error {
	if id != s.endpoint.ID {
		return errors.New("unknown endpoint")
	}
	s.lastSeen = &seenAt
	if !checkIn.GeneratedAt.IsZero() {
		generatedAt := checkIn.GeneratedAt
		s.heartbeatGeneratedAt = &generatedAt
	}
	s.heartbeatReceivedAt = &seenAt
	s.endpoint.SoftwareVersion = checkIn.SoftwareVersion
	s.endpoint.OperatingSystem = checkIn.OperatingSystem
	s.endpoint.Architecture = checkIn.Architecture
	return nil
}
func (s *memoryEndpointStore) AgentUpdateOffer(string, time.Time) ([]byte, error) { return nil, nil }
func (s *memoryEndpointStore) AgentModuleOffers(string, string, string, string) ([]agentmodule.Offer, error) {
	return nil, nil
}
func (s *memoryEndpointStore) RecordAgentModuleHealth(string, []agentmodule.Health) error { return nil }
func (s *memoryEndpointStore) RecordEndpointOSInventory(string, model.EndpointOSInventory, time.Time) error {
	return nil
}
func (s *memoryEndpointStore) EndpointOSInventory(string) (model.EndpointOSInventory, error) {
	return model.EndpointOSInventory{}, store.ErrNotFound
}
func (s *memoryEndpointStore) RecordEndpointSoftwareInventory(string, model.EndpointSoftwareInventory, time.Time) error {
	return nil
}
func (s *memoryEndpointStore) EndpointSoftwareInventory(string) (model.EndpointSoftwareInventory, error) {
	return model.EndpointSoftwareInventory{}, store.ErrNotFound
}
func (s *memoryEndpointStore) RecordEndpointListeningInventory(string, model.EndpointListeningInventory, time.Time) error {
	return nil
}
func (s *memoryEndpointStore) EndpointListeningInventory(string) (model.EndpointListeningInventory, error) {
	return model.EndpointListeningInventory{}, store.ErrNotFound
}
func (s *memoryEndpointStore) RecordEndpointPostureInventory(string, model.EndpointPostureInventory, time.Time) error {
	return nil
}
func (s *memoryEndpointStore) EndpointPostureInventory(string) (model.EndpointPostureInventory, error) {
	return model.EndpointPostureInventory{}, store.ErrNotFound
}
func (s *memoryEndpointStore) EndpointCVEMatches(string) ([]model.EndpointCVEMatch, error) {
	return nil, nil
}
func (s *memoryEndpointStore) RecordEndpointNetworkInventory(string, model.EndpointNetworkInventory, time.Time) error {
	return nil
}
func (s *memoryEndpointStore) EndpointNetworkInventory(string) (model.EndpointNetworkInventory, error) {
	return model.EndpointNetworkInventory{}, store.ErrNotFound
}
func (s *memoryEndpointStore) SetEndpointCollectors(id string, collectors []model.CollectorID, _ model.AuditEvent) error {
	if id != s.endpoint.ID || s.endpoint.Status != model.EndpointActive {
		return store.ErrNotFound
	}
	s.endpoint.AllowedCollectors = append([]model.CollectorID(nil), collectors...)
	return nil
}

func (s *memoryEndpointStore) SetEndpointNetworkExclusions(id string, exclusions model.NetworkTelemetryExclusions, _ model.AuditEvent) error {
	if s.endpoint.ID != id || s.endpoint.Status != model.EndpointActive {
		return store.ErrNotFound
	}
	s.endpoint.NetworkExclusions = exclusions
	return nil
}
func (s *memoryEndpointStore) RenewEndpointCertificate(oldSerial string, endpoint model.Endpoint, _ model.AuditEvent) error {
	if oldSerial != s.endpoint.CertificateSerial {
		return store.ErrEndpointCertificateChanged
	}
	s.endpoint = endpoint
	return nil
}
func (s *memoryEndpointStore) RevokeEndpoint(id, reason string, revokedAt time.Time, _ model.AuditEvent) error {
	if id != s.endpoint.ID || s.endpoint.Status != model.EndpointActive {
		return store.ErrNotFound
	}
	s.endpoint.Status, s.endpoint.RevocationReason, s.endpoint.RevokedAt = model.EndpointRevoked, reason, &revokedAt
	return nil
}

func TestEnrollmentAndMTLSIdentity(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pki, err := LoadOrCreatePKI(t.TempDir(), []string{"agent.mossward.test"}, now)
	if err != nil {
		t.Fatal(err)
	}
	repository := &memoryEndpointStore{}
	service := NewService(repository, pki)
	service.now = func() time.Time { return now }
	_, token, err := service.CreateEnrollmentToken("Workstation 1", "admin", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Enroll(token, string(endpointCSR(t)), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if result.Endpoint.Name != "Workstation 1" || result.CertificatePEM == "" || result.CAChainPEM == "" {
		t.Fatalf("unexpected enrollment result: %#v", result)
	}
	if _, err := service.Enroll(token, string(endpointCSR(t)), "127.0.0.1"); !errors.Is(err, store.ErrInvalidEnrollmentToken) {
		t.Fatalf("expected token replay rejection, got %v", err)
	}
	leaf := decodeCertificate(t, []byte(result.CertificatePEM))
	connection := tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	if err := service.verifyConnection(connection); err != nil {
		t.Fatalf("verify enrolled endpoint: %v", err)
	}
	generatedAt := now.Add(-time.Hour)
	payload, _ := json.Marshal(model.AgentCheckIn{SchemaVersion: 2, GeneratedAt: generatedAt, SoftwareVersion: "development",
		OperatingSystem: "linux", Architecture: "amd64", SupportedCollectors: []model.CollectorID{}})
	request := httptest.NewRequest(http.MethodPost, "https://agent.mossward.test/api/agent/v1/check-in", bytes.NewReader(payload))
	request.TLS = &connection
	response := httptest.NewRecorder()
	service.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || repository.lastSeen == nil || repository.heartbeatGeneratedAt == nil || !repository.heartbeatGeneratedAt.Equal(generatedAt) || repository.heartbeatReceivedAt == nil || !repository.heartbeatReceivedAt.Equal(now) {
		t.Fatalf("check-in failed: %d %s", response.Code, response.Body.String())
	}
	hash := sha256.Sum256([]byte(token))
	if !bytes.Equal(hash[:], repository.token.TokenHash) {
		t.Fatal("raw enrollment token was not stored as a hash")
	}
}

func TestVersionTwoCheckInRequiresGeneratedAt(t *testing.T) {
	checkIn := model.AgentCheckIn{SchemaVersion: 2, SoftwareVersion: "development", OperatingSystem: "linux", Architecture: "amd64"}
	if err := validateEndpointCheckIn(checkIn); err == nil {
		t.Fatal("version 2 check-in without generation time was accepted")
	}
	checkIn.GeneratedAt = time.Now().UTC()
	if err := validateEndpointCheckIn(checkIn); err != nil {
		t.Fatalf("valid version 2 check-in rejected: %v", err)
	}
}

func TestEndpointCertificateRenewalAndRevocation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pki, err := LoadOrCreatePKI(t.TempDir(), []string{"agent.mossward.test"}, now)
	if err != nil {
		t.Fatal(err)
	}
	repository := &memoryEndpointStore{endpoint: model.Endpoint{ID: "endpoint-1", Name: "Workstation", Status: model.EndpointActive,
		CertificateSerial: "old", ExpiresAt: now.Add(29 * 24 * time.Hour)}}
	service := NewService(repository, pki)
	service.now = func() time.Time { return now }
	result, err := service.Renew(repository.endpoint, string(endpointCSR(t)), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if result.Endpoint.CertificateSerial == "old" || result.Endpoint.RenewedAt == nil {
		t.Fatalf("certificate was not renewed: %#v", result.Endpoint)
	}
	if err := service.Revoke("endpoint-1", "device retired", "admin", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	items, err := service.Endpoints()
	if err != nil || len(items) != 1 || items[0].Status != model.EndpointRevoked || len(items[0].Alerts) != 1 {
		t.Fatalf("unexpected revoked inventory: %#v %v", items, err)
	}
}

func TestScannerWorkerEnrollmentAndMTLSCheckIn(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pki, err := LoadOrCreatePKI(t.TempDir(), []string{"agent.mossward.test"}, now)
	if err != nil {
		t.Fatal(err)
	}
	repository := &memoryEndpointStore{}
	jobSigner, err := workerjob.LoadOrCreateSigner(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(repository, pki, jobSigner)
	service.now = func() time.Time { return now }
	request := model.WorkerEnrollmentToken{Name: "Branch scanner", SiteID: "Chicago-HQ", AllowedCIDRs: []string{"192.0.2.0/24"},
		AllowedPorts: []int{443}, MaxConcurrent: 4, RateLimitPerSecond: 10}
	_, token, err := service.CreateWorkerEnrollmentToken(request, "admin", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.EnrollWorker(token, string(endpointCSR(t)), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if result.Worker.Name != request.Name || result.Worker.SiteID != "chicago-hq" || result.Worker.MaxConcurrent != request.MaxConcurrent || result.CertificatePEM == "" || result.JobSigningPublicKey == "" {
		t.Fatalf("unexpected scanner-worker enrollment: %#v", result)
	}
	leaf := decodeCertificate(t, []byte(result.CertificatePEM))
	connection := tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	if err := service.verifyConnection(connection); err != nil {
		t.Fatalf("verify enrolled scanner worker: %v", err)
	}
	heartbeat := `{"schema_version":1,"software_version":"1.0.0","operating_system":"linux","architecture":"amd64","capabilities":["tcp_connect","tls_configuration"],"available_concurrency":3,"health":"healthy"}`
	httpRequest := httptest.NewRequest(http.MethodPost, "https://agent.mossward.test/api/scanner-worker/v1/check-in", strings.NewReader(heartbeat))
	httpRequest.TLS = &connection
	response := httptest.NewRecorder()
	service.Handler().ServeHTTP(response, httpRequest)
	if response.Code != http.StatusOK || repository.workerLastSeen == nil || repository.worker.SoftwareVersion != "1.0.0" || len(repository.worker.Capabilities) != 2 {
		t.Fatalf("scanner-worker check-in failed: %d %s", response.Code, response.Body.String())
	}
	if _, err := service.EnrollWorker(token, string(endpointCSR(t)), "127.0.0.1"); !errors.Is(err, store.ErrInvalidEnrollmentToken) {
		t.Fatalf("worker token replay was accepted: %v", err)
	}
}

func TestScannerWorkerHeartbeatValidationAndOfflineAlert(t *testing.T) {
	heartbeat := model.WorkerHeartbeat{SchemaVersion: 1, SoftwareVersion: "1.0.0", OperatingSystem: "linux",
		Architecture: "amd64", Capabilities: []model.WorkerCapability{"arbitrary_execution"},
		AvailableConcurrency: 1, Health: model.WorkerHealthHealthy}
	if err := validateWorkerHeartbeat(&heartbeat, 4); err == nil {
		t.Fatal("unsupported scanner-worker capability was accepted")
	}
	heartbeat.Capabilities = []model.WorkerCapability{model.WorkerCapabilityTCPConnect}
	heartbeat.AvailableConcurrency = 5
	if err := validateWorkerHeartbeat(&heartbeat, 4); err == nil {
		t.Fatal("scanner worker exceeded its assigned concurrency")
	}
	now := time.Now().UTC()
	worker := model.ScannerWorker{Status: model.EndpointActive, ExpiresAt: now.Add(60 * 24 * time.Hour),
		SoftwareVersion: minimumSupportedWorkerVersion, Health: model.WorkerHealthHealthy}
	alerts := scannerWorkerAlerts(worker, now)
	if len(alerts) != 1 || alerts[0].Code != "worker_offline" {
		t.Fatalf("missing offline scanner-worker alert: %#v", alerts)
	}
}

func TestScannerWorkerFleetStatePrecedenceAndVersions(t *testing.T) {
	now := time.Now().UTC()
	lastSeen := now.Add(-time.Minute)
	worker := model.ScannerWorker{Status: model.EndpointActive, ExpiresAt: now.Add(time.Hour), LastSeenAt: &lastSeen,
		SoftwareVersion: minimumSupportedWorkerVersion, Health: model.WorkerHealthHealthy, AvailableConcurrency: 1}
	if state := scannerWorkerFleetState(worker, now); state != model.WorkerFleetHealthy {
		t.Fatalf("healthy worker classified as %s", state)
	}
	worker.SoftwareVersion = "0.9.9"
	if state := scannerWorkerFleetState(worker, now); state != model.WorkerFleetOutdated {
		t.Fatalf("outdated worker classified as %s", state)
	}
	worker.SoftwareVersion, worker.ActiveJobs, worker.AvailableConcurrency = "1.1.0", 1, 0
	if state := scannerWorkerFleetState(worker, now); state != model.WorkerFleetOverloaded {
		t.Fatalf("overloaded worker classified as %s", state)
	}
	worker.LastSeenAt = nil
	if state := scannerWorkerFleetState(worker, now); state != model.WorkerFleetOffline {
		t.Fatalf("offline worker classified as %s", state)
	}
	worker.Status = model.EndpointRevoked
	if state := scannerWorkerFleetState(worker, now); state != model.WorkerFleetRevoked {
		t.Fatalf("revoked worker classified as %s", state)
	}
	if !workerVersionBefore("invalid", minimumSupportedWorkerVersion) || workerVersionBefore("1.2.0", minimumSupportedWorkerVersion) {
		t.Fatal("worker semantic version comparison is unsafe")
	}
}

func TestScannerWorkerPollLeasesBoundJob(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pki, err := LoadOrCreatePKI(t.TempDir(), []string{"agent.mossward.test"}, now)
	if err != nil {
		t.Fatal(err)
	}
	repository := &memoryEndpointStore{worker: model.ScannerWorker{ID: "worker", Status: model.EndpointActive, ExpiresAt: now.Add(time.Hour)},
		workerJob: model.SignedWorkerJob{Job: model.WorkerJob{ID: "job", WorkerID: "worker", ScanID: "scan", IssuedAt: now.Add(-time.Minute),
			ExpiresAt: now.Add(5 * time.Minute), Targets: []model.Target{{Name: "host", Address: "192.0.2.10"}}, Ports: []int{443}}}}
	service := NewService(repository, pki)
	service.now = func() time.Time { return now }
	request := httptest.NewRequest(http.MethodPost, "https://agent.mossward.test/api/scanner-worker/v1/jobs/poll", nil)
	identity, err := url.Parse("spiffe://mossward/scanner-worker/worker")
	if err != nil {
		t.Fatal(err)
	}
	workerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		URIs: []*url.URL{identity}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &workerKey.PublicKey, workerKey)
	if err != nil {
		t.Fatal(err)
	}
	workerCertificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{workerCertificate}}
	repository.worker.CertificateSerial = "1"
	response := httptest.NewRecorder()
	service.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || len(repository.workerLeaseHash) != sha256.Size {
		t.Fatalf("scanner-worker job was not leased: %d %s", response.Code, response.Body.String())
	}
	var lease model.WorkerJobLease
	if err := json.NewDecoder(response.Body).Decode(&lease); err != nil || lease.Envelope.Job.ID != "job" || lease.Token == "" || !lease.ExpiresAt.Equal(now.Add(workerJobLeaseLifetime)) {
		t.Fatalf("unexpected scanner-worker lease: %#v %v", lease, err)
	}
	renewalBody, _ := json.Marshal(model.WorkerJobLeaseRenewal{JobID: "job", LeaseToken: lease.Token})
	renewalRequest := httptest.NewRequest(http.MethodPost, "https://agent.mossward.test/api/scanner-worker/v1/jobs/lease/renew", bytes.NewReader(renewalBody))
	renewalRequest.TLS = request.TLS
	renewalResponse := httptest.NewRecorder()
	service.Handler().ServeHTTP(renewalResponse, renewalRequest)
	if renewalResponse.Code != http.StatusOK {
		t.Fatalf("scanner-worker lease was not renewed: %d %s", renewalResponse.Code, renewalResponse.Body.String())
	}
	evidenceBatch := model.WorkerEvidenceBatch{SchemaVersion: 1, ID: "batch", WorkerID: "worker", JobID: "job", ScanID: "scan",
		Sequence: 1, Final: true, CollectedAt: now, Observations: []model.ServiceObservation{{ID: "observation", Address: "192.0.2.10", Port: 443, ObservedAt: now}},
		Checkpoints: []model.WorkerCheckpoint{{Address: "192.0.2.10", Port: 443, CompletedAt: now}}}
	evidenceEnvelope, err := workerevidence.Sign(evidenceBatch, workerCertificate, workerKey)
	if err != nil {
		t.Fatal(err)
	}
	evidenceBody, err := json.Marshal(evidenceEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	evidenceRequest := httptest.NewRequest(http.MethodPost, "https://agent.mossward.test/api/scanner-worker/v1/jobs/evidence", bytes.NewReader(evidenceBody))
	evidenceRequest.TLS = request.TLS
	evidenceResponse := httptest.NewRecorder()
	service.Handler().ServeHTTP(evidenceResponse, evidenceRequest)
	if evidenceResponse.Code != http.StatusAccepted || len(repository.workerEvidence) != 1 {
		t.Fatalf("scanner-worker evidence was not accepted: %d %s", evidenceResponse.Code, evidenceResponse.Body.String())
	}
	evidenceRetry := httptest.NewRequest(http.MethodPost, "https://agent.mossward.test/api/scanner-worker/v1/jobs/evidence", bytes.NewReader(evidenceBody))
	evidenceRetry.TLS = request.TLS
	evidenceRetryResponse := httptest.NewRecorder()
	service.Handler().ServeHTTP(evidenceRetryResponse, evidenceRetry)
	if evidenceRetryResponse.Code != http.StatusOK || len(repository.workerEvidence) != 1 {
		t.Fatalf("exact scanner-worker evidence retry was not acknowledged: %d %s", evidenceRetryResponse.Code, evidenceRetryResponse.Body.String())
	}
	resultBody, err := json.Marshal(model.WorkerJobResult{SchemaVersion: 1, ID: "result", JobID: "job", LeaseToken: lease.Token,
		Outcome: model.WorkerJobResultSucceeded, CompletedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	resultRequest := httptest.NewRequest(http.MethodPost, "https://agent.mossward.test/api/scanner-worker/v1/jobs/result", bytes.NewReader(resultBody))
	resultRequest.TLS = request.TLS
	resultResponse := httptest.NewRecorder()
	service.Handler().ServeHTTP(resultResponse, resultRequest)
	if resultResponse.Code != http.StatusAccepted || repository.workerResult.ResultID != "result" {
		t.Fatalf("scanner-worker result was not accepted: %d %s", resultResponse.Code, resultResponse.Body.String())
	}
	replayRequest := httptest.NewRequest(http.MethodPost, "https://agent.mossward.test/api/scanner-worker/v1/jobs/result", bytes.NewReader(resultBody))
	replayRequest.TLS = request.TLS
	replayResponse := httptest.NewRecorder()
	service.Handler().ServeHTTP(replayResponse, replayRequest)
	if replayResponse.Code != http.StatusOK {
		t.Fatalf("exact scanner-worker result retry returned %d", replayResponse.Code)
	}
	second := httptest.NewRecorder()
	service.Handler().ServeHTTP(second, request)
	if second.Code != http.StatusNoContent {
		t.Fatalf("empty worker queue returned %d", second.Code)
	}
}
