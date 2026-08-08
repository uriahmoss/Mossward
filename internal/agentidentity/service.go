package agentidentity

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"mossward/internal/model"
	"mossward/internal/store"
	"mossward/internal/workerjob"
)

const (
	enrollmentTokenBytes    = 32
	enrollmentTokenLifetime = 15 * time.Minute
	endpointNameLimit       = 200
	certificateRenewBefore  = 30 * 24 * time.Hour
	revocationReasonLimit   = 500
)

type EndpointStore interface {
	CreateAgentEnrollmentToken(model.AgentEnrollmentToken, model.AuditEvent) error
	ListAgentEnrollmentTokens(time.Time) ([]model.AgentEnrollmentToken, error)
	AgentEnrollmentTokenName([]byte, time.Time) (string, error)
	ConsumeAgentEnrollmentToken([]byte, model.Endpoint, time.Time, model.AuditEvent) error
	ListEndpoints() ([]model.Endpoint, error)
	EndpointBySerial(string) (model.Endpoint, error)
	MarkEndpointSeen(string, time.Time) error
	SetEndpointCollectors(string, []model.CollectorID, model.AuditEvent) error
	RenewEndpointCertificate(string, model.Endpoint, model.AuditEvent) error
	RevokeEndpoint(string, string, time.Time, model.AuditEvent) error
}

type Service struct {
	store       EndpointStore
	workerStore WorkerStore
	pki         *PKI
	jobSigner   *workerjob.Signer
	now         func() time.Time
}

type EnrollmentResult struct {
	Endpoint       model.Endpoint `json:"endpoint"`
	CertificatePEM string         `json:"certificate_pem"`
	CAChainPEM     string         `json:"ca_chain_pem"`
}

func NewService(repository EndpointStore, pki *PKI, signers ...*workerjob.Signer) *Service {
	service := &Service{store: repository, pki: pki, now: func() time.Time { return time.Now().UTC() }}
	if len(signers) > 0 {
		service.jobSigner = signers[0]
	}
	service.workerStore, _ = repository.(WorkerStore)
	return service
}

func (s *Service) CreateEnrollmentToken(name, actorID, sourceIP string) (model.AgentEnrollmentToken, string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > endpointNameLimit {
		return model.AgentEnrollmentToken{}, "", errors.New("endpoint name must be between 1 and 200 characters")
	}
	id, token, hash, err := newEnrollmentToken()
	if err != nil {
		return model.AgentEnrollmentToken{}, "", err
	}
	now := s.now()
	record := model.AgentEnrollmentToken{ID: id, Name: name, TokenHash: hash, CreatedBy: actorID,
		CreatedAt: now, ExpiresAt: now.Add(enrollmentTokenLifetime)}
	event := model.AuditEvent{OccurredAt: now, ActorID: actorID, Action: "endpoint.enrollment_token.created",
		Severity: model.AuditWarning, TargetType: "endpoint_enrollment", TargetID: id, SourceIP: sourceIP, Details: "{}"}
	if err := s.store.CreateAgentEnrollmentToken(record, event); err != nil {
		return model.AgentEnrollmentToken{}, "", err
	}
	return record, token, nil
}

func (s *Service) EnrollmentTokens() ([]model.AgentEnrollmentToken, error) {
	return s.store.ListAgentEnrollmentTokens(s.now())
}

func (s *Service) Endpoints() ([]model.Endpoint, error) {
	items, err := s.store.ListEndpoints()
	if err != nil {
		return nil, err
	}
	for index := range items {
		items[index].Alerts = endpointAlerts(items[index], s.now())
	}
	return items, nil
}

func endpointAlerts(endpoint model.Endpoint, now time.Time) []model.EndpointAlert {
	alerts := []model.EndpointAlert{}
	if endpoint.Status == model.EndpointRevoked {
		return append(alerts, model.EndpointAlert{Code: "certificate_revoked", Severity: "error", Message: "Endpoint certificate is revoked"})
	}
	if !now.Before(endpoint.ExpiresAt) {
		return append(alerts, model.EndpointAlert{Code: "certificate_expired", Severity: "error", Message: "Endpoint certificate has expired"})
	}
	if !now.Before(endpoint.ExpiresAt.Add(-certificateRenewBefore)) {
		alerts = append(alerts, model.EndpointAlert{Code: "certificate_expiring", Severity: "warning", Message: "Endpoint certificate expires within 30 days"})
	}
	return alerts
}

func (s *Service) Renew(endpoint model.Endpoint, csrPEM, sourceIP string) (EnrollmentResult, error) {
	now := s.now()
	if now.Before(endpoint.ExpiresAt.Add(-certificateRenewBefore)) {
		return EnrollmentResult{}, errors.New("endpoint certificate is not within its renewal window")
	}
	serial, certificatePEM, expiresAt, err := s.pki.IssueEndpoint(endpoint.ID, endpoint.Name, []byte(csrPEM), now)
	if err != nil {
		return EnrollmentResult{}, err
	}
	oldSerial := endpoint.CertificateSerial
	endpoint.CertificateSerial, endpoint.CertificatePEM, endpoint.ExpiresAt, endpoint.RenewedAt = serial, certificatePEM, expiresAt, &now
	event := model.AuditEvent{OccurredAt: now, Action: "endpoint.certificate.renewed", Severity: model.AuditInfo,
		TargetType: "endpoint", TargetID: endpoint.ID, SourceIP: sourceIP, Details: "{}"}
	if err := s.store.RenewEndpointCertificate(oldSerial, endpoint, event); err != nil {
		return EnrollmentResult{}, err
	}
	return EnrollmentResult{Endpoint: endpoint, CertificatePEM: certificatePEM, CAChainPEM: s.pki.CAChainPEM()}, nil
}

func (s *Service) Revoke(id, reason, actorID, sourceIP string) error {
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > revocationReasonLimit {
		return errors.New("revocation reason must be between 1 and 500 characters")
	}
	now := s.now()
	event := model.AuditEvent{OccurredAt: now, ActorID: actorID, Action: "endpoint.revoked", Severity: model.AuditWarning,
		TargetType: "endpoint", TargetID: id, SourceIP: sourceIP, Details: "{}"}
	return s.store.RevokeEndpoint(id, reason, now, event)
}

func (s *Service) Enroll(token, csrPEM, sourceIP string) (EnrollmentResult, error) {
	hash, err := enrollmentTokenHash(token)
	if err != nil {
		return EnrollmentResult{}, store.ErrInvalidEnrollmentToken
	}
	now := s.now()
	name, err := s.store.AgentEnrollmentTokenName(hash, now)
	if err != nil {
		return EnrollmentResult{}, store.ErrInvalidEnrollmentToken
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return EnrollmentResult{}, err
	}
	id := hex.EncodeToString(idBytes)
	serial, certificatePEM, expiresAt, err := s.pki.IssueEndpoint(id, name, []byte(csrPEM), now)
	if err != nil {
		return EnrollmentResult{}, err
	}
	endpoint := model.Endpoint{ID: id, Name: name, Status: model.EndpointActive, CertificateSerial: serial,
		CertificatePEM: certificatePEM, EnrolledAt: now, ExpiresAt: expiresAt}
	event := model.AuditEvent{OccurredAt: now, Action: "endpoint.enrolled", Severity: model.AuditInfo,
		TargetType: "endpoint", TargetID: id, SourceIP: sourceIP, Details: "{}"}
	if err := s.store.ConsumeAgentEnrollmentToken(hash, endpoint, now, event); err != nil {
		return EnrollmentResult{}, err
	}
	return EnrollmentResult{Endpoint: endpoint, CertificatePEM: certificatePEM, CAChainPEM: s.pki.CAChainPEM()}, nil
}

func (s *Service) TLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{s.pki.ServerCertificate()},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: s.pki.RootPool(), VerifyConnection: s.verifyConnection}
}

func (s *Service) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if r.URL.Path == "/api/scanner-worker/v1/check-in" {
			s.workerCheckIn(w, r)
			return
		}
		if r.URL.Path == "/api/scanner-worker/v1/jobs/poll" {
			s.workerPollJob(w, r)
			return
		}
		if r.URL.Path == "/api/scanner-worker/v1/jobs/result" {
			s.workerSubmitResult(w, r)
			return
		}
		if r.URL.Path == "/api/scanner-worker/v1/jobs/lease/renew" {
			s.workerRenewJobLease(w, r)
			return
		}
		if r.URL.Path == "/api/scanner-worker/v1/jobs/evidence" {
			s.workerSubmitEvidence(w, r)
			return
		}
		if r.URL.Path != "/api/agent/v1/check-in" && r.URL.Path != "/api/agent/v1/certificate/renew" {
			http.NotFound(w, r)
			return
		}
		endpoint, err := s.endpointFromConnection(r.TLS)
		if err != nil {
			http.Error(w, "authenticated endpoint required", http.StatusUnauthorized)
			return
		}
		now := s.now()
		if r.URL.Path == "/api/agent/v1/certificate/renew" {
			var request struct {
				CSRPEM string `json:"csr_pem"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&request); err != nil {
				http.Error(w, "invalid renewal request", http.StatusBadRequest)
				return
			}
			result, err := s.Renew(endpoint, request.CSRPEM, r.RemoteAddr)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(result)
			return
		}
		var heartbeat model.AgentCheckIn
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&heartbeat); err != nil || heartbeat.SchemaVersion != 1 || decoder.Decode(&struct{}{}) != io.EOF {
			http.Error(w, "invalid endpoint-agent check-in", http.StatusBadRequest)
			return
		}
		if err := validateEndpointCollectors(heartbeat.SupportedCollectors); err != nil {
			http.Error(w, "invalid endpoint-agent capabilities", http.StatusBadRequest)
			return
		}
		if err := s.store.MarkEndpointSeen(endpoint.ID, now); err != nil {
			http.Error(w, "endpoint state unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(model.AgentCheckInResponse{Status: "accepted", EndpointID: endpoint.ID,
			ServerTime: now, AllowedCollectors: endpoint.AllowedCollectors})
	})
}

func (s *Service) SetEndpointCollectors(id string, collectors []model.CollectorID, actorID, sourceIP string) error {
	if err := validateEndpointCollectors(collectors); err != nil {
		return err
	}
	event := model.AuditEvent{OccurredAt: s.now(), ActorID: actorID, Action: "endpoint.collectors.updated",
		Severity: model.AuditWarning, TargetType: "endpoint", TargetID: id, SourceIP: sourceIP, Details: "{}"}
	return s.store.SetEndpointCollectors(id, collectors, event)
}

func validateEndpointCollectors(collectors []model.CollectorID) error {
	allowed := map[model.CollectorID]bool{
		model.CollectorOperatingSystem: true, model.CollectorInstalledSoftware: true,
		model.CollectorListeningServices: true, model.CollectorSecurityPosture: true,
	}
	seen := map[model.CollectorID]bool{}
	for _, collector := range collectors {
		if !allowed[collector] || seen[collector] {
			return errors.New("endpoint collector policy contains an unsupported or duplicate collector")
		}
		seen[collector] = true
	}
	return nil
}

func (s *Service) verifyConnection(connection tls.ConnectionState) error {
	if _, err := s.endpointFromConnection(&connection); err == nil {
		return nil
	}
	_, err := s.workerFromConnection(&connection)
	return err
}

func (s *Service) workerCheckIn(w http.ResponseWriter, r *http.Request) {
	worker, err := s.workerFromConnection(r.TLS)
	if err != nil {
		http.Error(w, "authenticated scanner worker required", http.StatusUnauthorized)
		return
	}
	now := s.now()
	var heartbeat model.WorkerHeartbeat
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&heartbeat); err != nil {
		http.Error(w, "invalid scanner-worker heartbeat", http.StatusBadRequest)
		return
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		http.Error(w, "scanner-worker heartbeat must contain exactly one object", http.StatusBadRequest)
		return
	}
	if err := validateWorkerHeartbeat(&heartbeat, worker.MaxConcurrent); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.workerStore.RecordScannerWorkerHeartbeat(worker.ID, heartbeat, now); err != nil {
		http.Error(w, "scanner-worker state unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "accepted", "worker_id": worker.ID, "server_time": now})
}

func (s *Service) workerFromConnection(connection *tls.ConnectionState) (model.ScannerWorker, error) {
	if connection == nil || len(connection.PeerCertificates) == 0 || s.workerStore == nil {
		return model.ScannerWorker{}, errors.New("scanner-worker certificate missing")
	}
	certificate := connection.PeerCertificates[0]
	worker, err := s.workerStore.ScannerWorkerBySerial(certificate.SerialNumber.String())
	if err != nil || worker.Status != model.EndpointActive || !s.now().Before(worker.ExpiresAt) {
		return model.ScannerWorker{}, errors.New("scanner-worker certificate is not active")
	}
	wanted := "spiffe://mossward/scanner-worker/" + worker.ID
	for _, identity := range certificate.URIs {
		if identity.String() == wanted {
			return worker, nil
		}
	}
	return model.ScannerWorker{}, errors.New("scanner-worker certificate identity mismatch")
}

func (s *Service) endpointFromConnection(connection *tls.ConnectionState) (model.Endpoint, error) {
	if connection == nil || len(connection.PeerCertificates) == 0 {
		return model.Endpoint{}, errors.New("client certificate missing")
	}
	certificate := connection.PeerCertificates[0]
	endpoint, err := s.store.EndpointBySerial(certificate.SerialNumber.String())
	if err != nil || endpoint.Status != model.EndpointActive || !s.now().Before(endpoint.ExpiresAt) {
		return model.Endpoint{}, errors.New("endpoint certificate is not active")
	}
	wanted := "spiffe://mossward/endpoint/" + endpoint.ID
	for _, identity := range certificate.URIs {
		if identity.String() == wanted {
			return endpoint, nil
		}
	}
	return model.Endpoint{}, errors.New("endpoint certificate identity mismatch")
}

func newEnrollmentToken() (string, string, []byte, error) {
	idBytes := make([]byte, 16)
	tokenBytes := make([]byte, enrollmentTokenBytes)
	if _, err := rand.Read(idBytes); err != nil {
		return "", "", nil, fmt.Errorf("generate enrollment identifier: %w", err)
	}
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", "", nil, fmt.Errorf("generate enrollment token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(idBytes), token, hash[:], nil
}

func enrollmentTokenHash(token string) ([]byte, error) {
	if len(token) != enrollmentTokenBytes*2 {
		return nil, errors.New("invalid enrollment token")
	}
	if _, err := hex.DecodeString(token); err != nil {
		return nil, errors.New("invalid enrollment token")
	}
	hash := sha256.Sum256([]byte(token))
	return hash[:], nil
}
