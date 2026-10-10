package workerapp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"mossward/internal/agentidentity"
	"mossward/internal/model"
	"mossward/internal/privatefs"
	"mossward/internal/workerevidence"
	"mossward/internal/workerjob"
)

type deploymentController struct {
	mu           sync.Mutex
	lease        model.WorkerJobLease
	failDelivery bool
	evidence     []model.SignedWorkerEvidenceBatch
	results      []model.WorkerJobResult
	order        []string
}

func (controller *deploymentController) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if request.Method != http.MethodPost || request.TLS == nil || len(request.TLS.VerifiedChains) == 0 {
		http.Error(response, "authentication required", http.StatusUnauthorized)
		return
	}
	leaf := request.TLS.PeerCertificates[0]
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != "spiffe://mossward/scanner-worker/deployment-worker" {
		http.Error(response, "wrong worker", http.StatusForbidden)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	switch request.URL.Path {
	case "/api/scanner-worker/v1/check-in":
		response.WriteHeader(http.StatusNoContent)
	case "/api/scanner-worker/v1/jobs/poll":
		if controller.lease.Envelope.Job.ID == "" {
			response.WriteHeader(http.StatusNoContent)
			return
		}
		lease := controller.lease
		controller.lease = model.WorkerJobLease{}
		_ = json.NewEncoder(response).Encode(lease)
	case "/api/scanner-worker/v1/jobs/evidence":
		if controller.failDelivery {
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var batch model.SignedWorkerEvidenceBatch
		if err := json.NewDecoder(request.Body).Decode(&batch); err != nil {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := workerevidence.Verify(batch, leaf); err != nil {
			response.WriteHeader(http.StatusForbidden)
			return
		}
		controller.evidence = append(controller.evidence, batch)
		controller.order = append(controller.order, "evidence")
		response.WriteHeader(http.StatusNoContent)
	case "/api/scanner-worker/v1/jobs/result":
		if controller.failDelivery {
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var result model.WorkerJobResult
		if err := json.NewDecoder(request.Body).Decode(&result); err != nil {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		controller.results = append(controller.results, result)
		controller.order = append(controller.order, "result")
		response.WriteHeader(http.StatusNoContent)
	default:
		response.WriteHeader(http.StatusNotFound)
	}
}

func deploymentFixture(t *testing.T) (Config, *deploymentController, model.WorkerJobLease) {
	t.Helper()
	directory := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	pki, err := agentidentity.LoadOrCreatePKI(filepath.Join(directory, "pki"), []string{"127.0.0.1"}, now)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	_, certificate, _, err := pki.IssueScannerWorker("deployment-worker", "Deployment fixture", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), now)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := workerjob.LoadOrCreateSigner(filepath.Join(directory, "signer"))
	if err != nil {
		t.Fatal(err)
	}
	// The only scan destination is an owned loopback TCP listener.
	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = target.Close() })
	go func() {
		for {
			connection, err := target.Accept()
			if err != nil {
				return
			}
			_ = connection.Close()
		}
	}()
	port := target.Addr().(*net.TCPAddr).Port
	job := model.WorkerJob{SchemaVersion: 1, ID: "deployment-job", WorkerID: "deployment-worker", SiteID: "deployment-site", ScanID: "deployment-scan",
		IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute), Targets: []model.Target{{Name: "loopback", Address: "127.0.0.1"}}, Ports: []int{port},
		MaxConcurrent: 1, RequiredCapabilities: []model.WorkerCapability{model.WorkerCapabilityTCPConnect}, Status: model.WorkerJobPending}
	envelope, err := signer.Sign(job)
	if err != nil {
		t.Fatal(err)
	}
	lease := model.WorkerJobLease{Envelope: envelope, Token: "synthetic-lease", ExpiresAt: now.Add(time.Minute)}
	controller := &deploymentController{lease: lease}
	server := httptest.NewUnstartedServer(controller)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pki.ServerCertificate()}, ClientCAs: pki.RootPool(), ClientAuth: tls.RequireAndVerifyClientCert}
	server.StartTLS()
	t.Cleanup(server.Close)
	config := Config{ServerURL: server.URL, WorkerID: job.WorkerID, SiteID: job.SiteID, CertificateFile: filepath.Join(directory, "worker.crt"), PrivateKeyFile: filepath.Join(directory, "worker.key"),
		CAFile: filepath.Join(directory, "ca.crt"), StateDirectory: filepath.Join(directory, "state"), JobSigningPublicKey: base64.RawStdEncoding.EncodeToString(signer.PublicKey()),
		AllowedCIDRs: []string{"127.0.0.1/32"}, AllowedPorts: []int{port}, MaxConcurrent: 1, Capabilities: job.RequiredCapabilities, PollIntervalSeconds: 1}
	config.applyDefaults()
	for path, data := range map[string][]byte{config.CertificateFile: []byte(certificate), config.PrivateKeyFile: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), config.CAFile: []byte(pki.CAChainPEM())} {
		if err := privatefs.WriteFile(path, data); err != nil {
			t.Fatal(err)
		}
	}
	return config, controller, lease
}
