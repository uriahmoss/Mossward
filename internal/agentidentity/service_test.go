package agentidentity

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"mossward/internal/model"
	"mossward/internal/store"
	"mossward/internal/workerjob"
)

type memoryEndpointStore struct {
	token           model.AgentEnrollmentToken
	endpoint        model.Endpoint
	consumed        bool
	lastSeen        *time.Time
	workerToken     model.WorkerEnrollmentToken
	worker          model.ScannerWorker
	workerConsumed  bool
	workerLastSeen  *time.Time
	workerJob       model.SignedWorkerJob
	workerLeaseHash []byte
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
func (s *memoryEndpointStore) LeaseScannerWorkerJob(id string, hash []byte, _, _ time.Time) (model.SignedWorkerJob, error) {
	if id != s.worker.ID || s.workerJob.Job.ID == "" {
		return model.SignedWorkerJob{}, store.ErrNotFound
	}
	s.workerLeaseHash = append([]byte(nil), hash...)
	job := s.workerJob
	s.workerJob = model.SignedWorkerJob{}
	return job, nil
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
	request := httptest.NewRequest(http.MethodPost, "https://agent.mossward.test/api/agent/v1/check-in", nil)
	request.TLS = &connection
	response := httptest.NewRecorder()
	service.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || repository.lastSeen == nil {
		t.Fatalf("check-in failed: %d %s", response.Code, response.Body.String())
	}
	hash := sha256.Sum256([]byte(token))
	if !bytes.Equal(hash[:], repository.token.TokenHash) {
		t.Fatal("raw enrollment token was not stored as a hash")
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
	request := model.WorkerEnrollmentToken{Name: "Branch scanner", AllowedCIDRs: []string{"192.0.2.0/24"},
		AllowedPorts: []int{443}, MaxConcurrent: 4, RateLimitPerSecond: 10}
	_, token, err := service.CreateWorkerEnrollmentToken(request, "admin", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.EnrollWorker(token, string(endpointCSR(t)), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if result.Worker.Name != request.Name || result.Worker.MaxConcurrent != request.MaxConcurrent || result.CertificatePEM == "" || result.JobSigningPublicKey == "" {
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
	worker := model.ScannerWorker{Status: model.EndpointActive, ExpiresAt: now.Add(60 * 24 * time.Hour), Health: model.WorkerHealthHealthy}
	alerts := scannerWorkerAlerts(worker, now)
	if len(alerts) != 1 || alerts[0].Code != "worker_offline" {
		t.Fatalf("missing offline scanner-worker alert: %#v", alerts)
	}
}

func TestScannerWorkerPollLeasesBoundJob(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pki, err := LoadOrCreatePKI(t.TempDir(), []string{"agent.mossward.test"}, now)
	if err != nil {
		t.Fatal(err)
	}
	repository := &memoryEndpointStore{worker: model.ScannerWorker{ID: "worker", Status: model.EndpointActive, ExpiresAt: now.Add(time.Hour)},
		workerJob: model.SignedWorkerJob{Job: model.WorkerJob{ID: "job", WorkerID: "worker", ExpiresAt: now.Add(5 * time.Minute)}}}
	service := NewService(repository, pki)
	service.now = func() time.Time { return now }
	request := httptest.NewRequest(http.MethodPost, "https://agent.mossward.test/api/scanner-worker/v1/jobs/poll", nil)
	identity, err := url.Parse("spiffe://mossward/scanner-worker/worker")
	if err != nil {
		t.Fatal(err)
	}
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{SerialNumber: big.NewInt(1), URIs: []*url.URL{identity}}}}
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
	second := httptest.NewRecorder()
	service.Handler().ServeHTTP(second, request)
	if second.Code != http.StatusNoContent {
		t.Fatalf("empty worker queue returned %d", second.Code)
	}
}
