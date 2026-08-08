package agentidentity

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mossward/internal/model"
	"mossward/internal/scanlaunch"
	"mossward/internal/store"
	"mossward/internal/workerclient"
	"mossward/internal/workerevidence"
	"mossward/internal/workerjob"
)

type integrationRoundTripper struct {
	handler     http.Handler
	certificate *x509.Certificate
}

func (r integrationRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{r.certificate}}
	recorder := httptest.NewRecorder()
	r.handler.ServeHTTP(recorder, request)
	return recorder.Result(), nil
}

type integrationInspector struct{}

type integrationLocalScheduler struct{}

func (integrationLocalScheduler) Schedule(model.Scan) error {
	return fmt.Errorf("integration test unexpectedly selected local execution")
}

func (integrationInspector) InspectScoped(_ context.Context, target model.Target, port int, _ []model.WorkerCapability) (model.ServiceObservation, []model.Finding, bool) {
	observedAt := time.Now().UTC()
	id := strings.NewReplacer(".", "-", ":", "-").Replace(target.Address)
	observation := model.ServiceObservation{ID: fmt.Sprintf("observation-%s-%d", id, port), Target: target.Name,
		Address: target.Address, Port: port, Protocol: "https", Product: "nginx", Version: "1.0.0",
		Confidence: "high", Evidence: "integration test service", ObservedAt: observedAt}
	finding := model.Finding{ID: fmt.Sprintf("finding-%s-%d", id, port), CheckID: "integration.remote",
		Target: target.Name, Address: target.Address, Port: port, Service: "https", Severity: "info",
		Title: "Remote worker integration finding", Evidence: "integration test", ObservedAt: observedAt}
	return observation, []model.Finding{finding}, true
}

type enrolledIntegrationWorker struct {
	worker      model.ScannerWorker
	certificate *x509.Certificate
	signer      crypto.Signer
	transport   *workerclient.Transport
}

func TestRemoteWorkerPolicyExecutionProjectsEvidenceEndToEnd(t *testing.T) {
	repository, service, jobSigner := integrationControlPlane(t)
	worker := enrollIntegrationWorker(t, service, "worker-one")
	checkInIntegrationWorker(t, worker)
	dispatcher, err := workerjob.NewDispatcher(repository, jobSigner)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	scan := model.Scan{ID: "integration-scan", Name: "Integration scan", Targets: []model.Target{{Name: "host", Address: "192.0.2.10"}},
		Ports: []int{443}, Status: model.StatusQueued, TotalChecks: 1, MaxConcurrent: 1, RateLimitPerSecond: 10, CreatedAt: now}
	launcher, err := scanlaunch.New(repository, integrationLocalScheduler{}, dispatcher)
	if err != nil {
		t.Fatal(err)
	}
	policy := model.ReusableScanPolicy{ExecutionMode: model.ScanExecutionRemote}
	if err := launcher.Launch(scan, policy); err != nil {
		t.Fatal(err)
	}
	runtime := integrationRuntime(t, worker, jobSigner.PublicKey())
	if err := runtime.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	completed, err := repository.Get(scan.ID)
	if err != nil || completed.Status != model.StatusCompleted || completed.DoneChecks != 1 ||
		len(completed.Observations) != 1 || len(completed.Findings) != 1 {
		t.Fatalf("remote worker flow did not complete the scan: %#v %v", completed, err)
	}
}

func TestRemoteWorkerResumeSkipsAcceptedCheckpoint(t *testing.T) {
	repository, service, jobSigner := integrationControlPlane(t)
	first := enrollIntegrationWorker(t, service, "worker-first")
	second := enrollIntegrationWorker(t, service, "worker-second")
	checkInIntegrationWorker(t, first)
	checkInIntegrationWorker(t, second)
	now := time.Now().UTC().Truncate(time.Millisecond)
	targets := []model.Target{{Name: "first", Address: "192.0.2.20"}, {Name: "second", Address: "192.0.2.21"}}
	scan := model.Scan{ID: "resume-scan", Name: "Resume scan", Targets: targets, Ports: []int{443}, Status: model.StatusQueued,
		TotalChecks: 2, CreatedAt: now}
	if err := repository.Save(scan); err != nil {
		t.Fatal(err)
	}
	job := model.WorkerJob{SchemaVersion: 1, ID: "scan-" + scan.ID, WorkerID: first.worker.ID, ScanID: scan.ID,
		IssuedAt: now, ExpiresAt: now.Add(time.Hour), Targets: targets, Ports: scan.Ports, MaxConcurrent: 1,
		RateLimitPerSecond:   10,
		RequiredCapabilities: []model.WorkerCapability{model.WorkerCapabilityTCPConnect}, Status: model.WorkerJobPending}
	envelope, err := jobSigner.Sign(job)
	if err != nil {
		t.Fatalf("create initial resumable job: %v", err)
	}
	if err := repository.CreateScannerWorkerJob(envelope, now); err != nil {
		t.Fatalf("create initial resumable job: %v", err)
	}
	lease, err := first.transport.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	partial := model.WorkerEvidenceBatch{SchemaVersion: 1, ID: "partial-batch", WorkerID: first.worker.ID, JobID: job.ID,
		ScanID: scan.ID, Sequence: 1, CollectedAt: now,
		Checkpoints: []model.WorkerCheckpoint{{Address: targets[0].Address, Port: 443, CompletedAt: now}}}
	signedPartial, err := workerevidence.Sign(partial, first.certificate, first.signer)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(signedPartial)
	if err := first.transport.Deliver(context.Background(), workerclient.OutboxMessage{Kind: workerclient.OutboxEvidence, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	resumeAt := lease.ExpiresAt.Add(time.Second)
	service.now = func() time.Time { return resumeAt }
	candidate, err := repository.ScannerWorkerJobResumeCandidate(job.ID, resumeAt)
	if err != nil {
		t.Fatal(err)
	}
	job.WorkerID = second.worker.ID
	job.Resume = &model.WorkerJobResume{PreviousWorkerID: first.worker.ID, Completed: candidate.Completed,
		NextEvidenceSequence: candidate.NextEvidenceSequence}
	resumedEnvelope, err := jobSigner.Sign(job)
	if err != nil {
		t.Fatalf("reassign interrupted worker job: %v", err)
	}
	if err := repository.ReassignScannerWorkerJob(first.worker.ID, resumedEnvelope, resumeAt); err != nil {
		t.Fatalf("reassign interrupted worker job: %v", err)
	}
	runtime := integrationRuntime(t, second, jobSigner.PublicKey())
	if err := runtime.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	completed, err := repository.Get(scan.ID)
	if err != nil || completed.Status != model.StatusCompleted || completed.DoneChecks != 2 || len(completed.Observations) != 1 {
		t.Fatalf("resumed worker did not finish only pending work: %#v %v", completed, err)
	}
}

func integrationControlPlane(t *testing.T) (*store.SQLiteStore, *Service, *workerjob.Signer) {
	t.Helper()
	directory := t.TempDir()
	repository, err := store.NewSQLiteStore(filepath.Join(directory, "mossward.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repository.Close() })
	now := time.Now().UTC()
	administrator := model.User{ID: "integration-admin", Email: "admin@example.test", DisplayName: "Integration Admin",
		Role: model.RoleAdministrator, Status: model.UserActive, MFARequired: true, CreatedAt: now, UpdatedAt: now}
	event := model.AuditEvent{OccurredAt: now, ActorID: administrator.ID, Action: "identity.bootstrap.completed",
		Severity: model.AuditInfo, TargetType: "user", TargetID: administrator.ID, Details: "{}"}
	if err := repository.BootstrapAdministrator(administrator, "integration-password-hash",
		model.BootstrapMFA{TOTPSecretCiphertext: []byte("integration-secret"), RecoveryCodeHashes: [][]byte{[]byte("integration-code")}}, event); err != nil {
		t.Fatal(err)
	}
	pki, err := LoadOrCreatePKI(filepath.Join(directory, "pki"), []string{"mossward.test"}, now)
	if err != nil {
		t.Fatal(err)
	}
	jobSigner, err := workerjob.LoadOrCreateSigner(filepath.Join(directory, "signing"))
	if err != nil {
		t.Fatal(err)
	}
	return repository, NewService(repository, pki, jobSigner), jobSigner
}

func enrollIntegrationWorker(t *testing.T, service *Service, name string) enrolledIntegrationWorker {
	t.Helper()
	request := model.WorkerEnrollmentToken{Name: name, AllowedCIDRs: []string{"192.0.2.0/24"}, AllowedPorts: []int{443},
		MaxConcurrent: 1, RateLimitPerSecond: 10}
	_, token, err := service.CreateWorkerEnrollmentToken(request, "integration-admin", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	csr, signer := integrationCSR(t, name)
	result, err := service.EnrollWorker(token, string(csr), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	certificate := integrationCertificate(t, result.CertificatePEM)
	client := &http.Client{Transport: integrationRoundTripper{handler: service.Handler(), certificate: certificate}}
	transport, err := workerclient.NewTransport("https://mossward.test", client)
	if err != nil {
		t.Fatal(err)
	}
	result.Worker.Capabilities = []model.WorkerCapability{model.WorkerCapabilityTCPConnect,
		model.WorkerCapabilityServiceIdentification, model.WorkerCapabilityHTTP, model.WorkerCapabilityTLS,
		model.WorkerCapabilitySSH}
	result.Worker.AvailableConcurrency = 1
	return enrolledIntegrationWorker{worker: result.Worker, certificate: certificate, signer: signer, transport: transport}
}

func checkInIntegrationWorker(t *testing.T, worker enrolledIntegrationWorker) {
	t.Helper()
	heartbeat := model.WorkerHeartbeat{SchemaVersion: 1, SoftwareVersion: "1.0.0", OperatingSystem: "linux", Architecture: "amd64",
		Capabilities: worker.worker.Capabilities, AvailableConcurrency: 1, Health: model.WorkerHealthHealthy}
	if err := worker.transport.CheckIn(context.Background(), heartbeat); err != nil {
		t.Fatal(err)
	}
}

func integrationRuntime(t *testing.T, worker enrolledIntegrationWorker, publicKey ed25519.PublicKey) *workerclient.Runtime {
	t.Helper()
	state := filepath.Join(t.TempDir(), "state")
	outbox, err := workerclient.OpenOutbox(filepath.Join(state, "outbox.db"), filepath.Join(state, "outbox.key"),
		workerclient.OutboxLimits{MaxItems: 100, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outbox.Close() })
	ledger, err := workerclient.OpenReplayLedger(filepath.Join(state, "replay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	executor, err := workerclient.NewExecutor(integrationInspector{}, func(batch model.WorkerEvidenceBatch) (model.SignedWorkerEvidenceBatch, error) {
		return workerevidence.Sign(batch, worker.certificate, worker.signer)
	})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := workerclient.NewRuntime(worker.transport, outbox, executor, worker.worker, publicKey, ledger,
		workerclient.DefaultBackpressurePolicy())
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

func integrationCSR(t *testing.T, name string) ([]byte, crypto.Signer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: name}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), key
}

func integrationCertificate(t *testing.T, encoded string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(encoded))
	if block == nil {
		t.Fatal("worker certificate was not PEM encoded")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}
