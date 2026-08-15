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
	"net/netip"
	"slices"
	"strings"
	"time"

	"mossward/internal/agentmodule"
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
	maximumAgentCheckInSize = 4 << 20
)

type EndpointStore interface {
	CreateAgentEnrollmentToken(model.AgentEnrollmentToken, model.AuditEvent) error
	ListAgentEnrollmentTokens(time.Time) ([]model.AgentEnrollmentToken, error)
	AgentEnrollmentTokenName([]byte, time.Time) (string, error)
	ConsumeAgentEnrollmentToken([]byte, model.Endpoint, time.Time, model.AuditEvent) error
	ListEndpoints() ([]model.Endpoint, error)
	EndpointBySerial(string) (model.Endpoint, error)
	RecordEndpointCheckIn(string, model.AgentCheckIn, time.Time) error
	AgentUpdateOffer(string, time.Time) ([]byte, error)
	AgentModuleOffers(string, string, string, string) ([]agentmodule.Offer, error)
	RecordAgentModuleHealth(string, []agentmodule.Health) error
	RecordEndpointOSInventory(string, model.EndpointOSInventory, time.Time) error
	EndpointOSInventory(string) (model.EndpointOSInventory, error)
	RecordEndpointSoftwareInventory(string, model.EndpointSoftwareInventory, time.Time) error
	EndpointSoftwareInventory(string) (model.EndpointSoftwareInventory, error)
	RecordEndpointListeningInventory(string, model.EndpointListeningInventory, time.Time) error
	EndpointListeningInventory(string) (model.EndpointListeningInventory, error)
	RecordEndpointPostureInventory(string, model.EndpointPostureInventory, time.Time) error
	EndpointPostureInventory(string) (model.EndpointPostureInventory, error)
	EndpointCVEMatches(string) ([]model.EndpointCVEMatch, error)
	RecordEndpointNetworkInventory(string, model.EndpointNetworkInventory, time.Time) error
	EndpointNetworkInventory(string) (model.EndpointNetworkInventory, error)
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
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maximumAgentCheckInSize))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&heartbeat); err != nil || heartbeat.SchemaVersion != 1 || decoder.Decode(&struct{}{}) != io.EOF {
			http.Error(w, "invalid endpoint-agent check-in", http.StatusBadRequest)
			return
		}
		if err := validateEndpointCheckIn(heartbeat); err != nil {
			http.Error(w, "invalid endpoint-agent capabilities", http.StatusBadRequest)
			return
		}
		if err := s.store.RecordEndpointCheckIn(endpoint.ID, heartbeat, now); err != nil {
			http.Error(w, "endpoint state unavailable", http.StatusServiceUnavailable)
			return
		}
		updateEnvelope, err := s.store.AgentUpdateOffer(endpoint.ID, now)
		if err != nil {
			http.Error(w, "endpoint update state unavailable", http.StatusServiceUnavailable)
			return
		}
		if err := s.store.RecordAgentModuleHealth(endpoint.ID, heartbeat.ModuleHealth); err != nil {
			http.Error(w, "endpoint module health unavailable", http.StatusServiceUnavailable)
			return
		}
		if heartbeat.OSInventory != nil && slices.Contains(endpoint.AllowedCollectors, model.CollectorOperatingSystem) {
			if err := s.store.RecordEndpointOSInventory(endpoint.ID, *heartbeat.OSInventory, now); err != nil {
				http.Error(w, "endpoint OS inventory unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		if heartbeat.SoftwareInventory != nil && slices.Contains(endpoint.AllowedCollectors, model.CollectorInstalledSoftware) {
			if err := s.store.RecordEndpointSoftwareInventory(endpoint.ID, *heartbeat.SoftwareInventory, now); err != nil {
				http.Error(w, "endpoint software inventory unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		if heartbeat.ListeningInventory != nil && slices.Contains(endpoint.AllowedCollectors, model.CollectorListeningServices) {
			if err := s.store.RecordEndpointListeningInventory(endpoint.ID, *heartbeat.ListeningInventory, now); err != nil {
				http.Error(w, "endpoint listening-service inventory unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		if heartbeat.PostureInventory != nil && slices.Contains(endpoint.AllowedCollectors, model.CollectorSecurityPosture) {
			if err := s.store.RecordEndpointPostureInventory(endpoint.ID, *heartbeat.PostureInventory, now); err != nil {
				http.Error(w, "endpoint security-posture inventory unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		if heartbeat.NetworkInventory != nil && slices.Contains(endpoint.AllowedCollectors, model.CollectorNetworkTelemetry) {
			if err := s.store.RecordEndpointNetworkInventory(endpoint.ID, *heartbeat.NetworkInventory, now); err != nil {
				http.Error(w, "endpoint network metadata unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		moduleOffers, err := s.store.AgentModuleOffers(endpoint.ID, heartbeat.SoftwareVersion, heartbeat.OperatingSystem, heartbeat.Architecture)
		if err != nil {
			http.Error(w, "endpoint module state unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(model.AgentCheckInResponse{Status: "accepted", EndpointID: endpoint.ID,
			ServerTime: now, AllowedCollectors: endpoint.AllowedCollectors, UpdateEnvelope: updateEnvelope, ModuleOffers: moduleOffers})
	})
}

func validateEndpointCheckIn(checkIn model.AgentCheckIn) error {
	if strings.TrimSpace(checkIn.SoftwareVersion) == "" {
		return errors.New("endpoint software version is required")
	}
	if checkIn.OperatingSystem != "linux" && checkIn.OperatingSystem != "windows" {
		return errors.New("endpoint operating system is unsupported")
	}
	if checkIn.Architecture != "amd64" && checkIn.Architecture != "arm64" {
		return errors.New("endpoint architecture is unsupported")
	}
	if len(checkIn.ModuleHealth) > 256 {
		return errors.New("endpoint module health report is too large")
	}
	seenModules := map[string]bool{}
	for _, report := range checkIn.ModuleHealth {
		if strings.TrimSpace(report.ModuleID) == "" || strings.TrimSpace(report.Version) == "" || report.CrashCount < 0 || len(report.Error) > 500 || seenModules[report.ModuleID] {
			return errors.New("endpoint module health report is invalid")
		}
		seenModules[report.ModuleID] = true
	}
	if err := validateOSInventory(checkIn.OSInventory); err != nil {
		return err
	}
	if err := validateSoftwareInventory(checkIn.SoftwareInventory); err != nil {
		return err
	}
	if err := validateListeningInventory(checkIn.ListeningInventory); err != nil {
		return err
	}
	if err := validatePostureInventory(checkIn.PostureInventory); err != nil {
		return err
	}
	if err := validateNetworkInventory(checkIn.NetworkInventory); err != nil {
		return err
	}
	return validateEndpointCollectors(checkIn.SupportedCollectors)
}

func validateNetworkInventory(inventory *model.EndpointNetworkInventory) error {
	if inventory == nil {
		return nil
	}
	if inventory.CollectedAt.IsZero() || len(inventory.Connections) > 10000 {
		return errors.New("endpoint network metadata is invalid")
	}
	seen := map[string]bool{}
	for _, connection := range inventory.Connections {
		local, localErr := netip.ParseAddr(connection.LocalAddress)
		remote, remoteErr := netip.ParseAddr(connection.RemoteAddress)
		identity := fmt.Sprintf("%s\x00%s\x00%d\x00%s\x00%d\x00%d", connection.Protocol, local, connection.LocalPort, remote, connection.RemotePort, connection.ProcessID)
		if (connection.Protocol != "tcp" && connection.Protocol != "udp") || localErr != nil || remoteErr != nil || remote.IsUnspecified() ||
			connection.LocalPort < 1 || connection.LocalPort > 65535 || connection.RemotePort < 1 || connection.RemotePort > 65535 || connection.ProcessID < 0 ||
			len(connection.ProcessName) > 500 || len(connection.Executable) > 2000 || connection.Direction != "outbound_candidate" || seen[identity] {
			return errors.New("endpoint network connection metadata is invalid")
		}
		seen[identity] = true
	}
	return nil
}

func validatePostureInventory(inventory *model.EndpointPostureInventory) error {
	if inventory == nil {
		return nil
	}
	if inventory.CollectedAt.IsZero() || len(inventory.Evidence) == 0 || len(inventory.Evidence) > 100 {
		return errors.New("endpoint security-posture inventory is invalid")
	}
	seen := map[string]bool{}
	for _, evidence := range inventory.Evidence {
		if strings.TrimSpace(evidence.ID) == "" || len(evidence.ID) > 100 || strings.TrimSpace(evidence.Title) == "" || len(evidence.Title) > 200 || len(evidence.Detail) > 1000 ||
			(evidence.Status != "pass" && evidence.Status != "fail" && evidence.Status != "unknown") || seen[evidence.ID] {
			return errors.New("endpoint security-posture evidence is invalid")
		}
		seen[evidence.ID] = true
	}
	return nil
}

func validateListeningInventory(inventory *model.EndpointListeningInventory) error {
	if inventory == nil {
		return nil
	}
	if inventory.CollectedAt.IsZero() || len(inventory.Services) > 20000 {
		return errors.New("endpoint listening-service inventory is invalid")
	}
	seen := map[string]bool{}
	for _, service := range inventory.Services {
		identity := fmt.Sprintf("%s\x00%s\x00%d\x00%d", service.Protocol, service.Address, service.Port, service.ProcessID)
		if (service.Protocol != "tcp" && service.Protocol != "udp") || service.Port < 1 || service.Port > 65535 || service.ProcessID < 0 ||
			len(service.ProcessName) > 500 || len(service.Executable) > 2000 || seen[identity] {
			return errors.New("endpoint listening-service record is invalid")
		}
		if _, err := netip.ParseAddr(service.Address); err != nil {
			return errors.New("endpoint listening-service address is invalid")
		}
		seen[identity] = true
	}
	return nil
}

func validateSoftwareInventory(inventory *model.EndpointSoftwareInventory) error {
	if inventory == nil {
		return nil
	}
	if inventory.CollectedAt.IsZero() || len(inventory.Items) > 10000 {
		return errors.New("endpoint software inventory is invalid")
	}
	seen := map[string]bool{}
	for _, item := range inventory.Items {
		identity := strings.ToLower(strings.TrimSpace(item.Name) + "\x00" + strings.TrimSpace(item.Version) + "\x00" + item.Architecture)
		if strings.TrimSpace(item.Name) == "" || len(item.Name) > 500 || len(item.Version) > 200 || len(item.Publisher) > 500 || len(item.Architecture) > 50 ||
			(item.Source != "dpkg" && item.Source != "rpm" && item.Source != "apk" && item.Source != "windows_registry") || seen[identity] {
			return errors.New("endpoint software inventory item is invalid")
		}
		seen[identity] = true
	}
	return nil
}

func validateOSInventory(inventory *model.EndpointOSInventory) error {
	if inventory == nil {
		return nil
	}
	if inventory.Family != "linux" && inventory.Family != "windows" {
		return errors.New("endpoint OS inventory family is unsupported")
	}
	if strings.TrimSpace(inventory.Name) == "" || strings.TrimSpace(inventory.Version) == "" || strings.TrimSpace(inventory.Kernel) == "" ||
		(inventory.Architecture != "amd64" && inventory.Architecture != "arm64") || inventory.CollectedAt.IsZero() || len(inventory.Patches) > 10000 {
		return errors.New("endpoint OS inventory is invalid")
	}
	seen := map[string]bool{}
	for _, patch := range inventory.Patches {
		if strings.TrimSpace(patch.ID) == "" || len(patch.ID) > 200 || len(patch.Description) > 500 || seen[patch.ID] {
			return errors.New("endpoint OS patch inventory is invalid")
		}
		seen[patch.ID] = true
	}
	return nil
}

func (s *Service) OSInventory(endpointID string) (model.EndpointOSInventory, error) {
	return s.store.EndpointOSInventory(endpointID)
}

func (s *Service) SoftwareInventory(endpointID string) (model.EndpointSoftwareInventory, error) {
	return s.store.EndpointSoftwareInventory(endpointID)
}

func (s *Service) ListeningInventory(endpointID string) (model.EndpointListeningInventory, error) {
	return s.store.EndpointListeningInventory(endpointID)
}

func (s *Service) PostureInventory(endpointID string) (model.EndpointPostureInventory, error) {
	return s.store.EndpointPostureInventory(endpointID)
}

func (s *Service) CVEMatches(endpointID string) ([]model.EndpointCVEMatch, error) {
	return s.store.EndpointCVEMatches(endpointID)
}

func (s *Service) NetworkInventory(endpointID string) (model.EndpointNetworkInventory, error) {
	return s.store.EndpointNetworkInventory(endpointID)
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
		model.CollectorNetworkTelemetry: true,
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
