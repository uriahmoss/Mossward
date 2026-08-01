package agentidentity

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"mossward/internal/model"
	"mossward/internal/store"
)

const (
	enrollmentTokenBytes    = 32
	enrollmentTokenLifetime = 15 * time.Minute
	endpointNameLimit       = 200
)

type EndpointStore interface {
	CreateAgentEnrollmentToken(model.AgentEnrollmentToken, model.AuditEvent) error
	ListAgentEnrollmentTokens(time.Time) ([]model.AgentEnrollmentToken, error)
	AgentEnrollmentTokenName([]byte, time.Time) (string, error)
	ConsumeAgentEnrollmentToken([]byte, model.Endpoint, time.Time, model.AuditEvent) error
	ListEndpoints() ([]model.Endpoint, error)
	EndpointBySerial(string) (model.Endpoint, error)
	MarkEndpointSeen(string, time.Time) error
}

type Service struct {
	store EndpointStore
	pki   *PKI
	now   func() time.Time
}

type EnrollmentResult struct {
	Endpoint       model.Endpoint `json:"endpoint"`
	CertificatePEM string         `json:"certificate_pem"`
	CAChainPEM     string         `json:"ca_chain_pem"`
}

func NewService(repository EndpointStore, pki *PKI) *Service {
	return &Service{store: repository, pki: pki, now: func() time.Time { return time.Now().UTC() }}
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
	return s.store.ListEndpoints()
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
		if r.Method != http.MethodPost || r.URL.Path != "/api/agent/v1/check-in" {
			http.NotFound(w, r)
			return
		}
		endpoint, err := s.endpointFromConnection(r.TLS)
		if err != nil {
			http.Error(w, "authenticated endpoint required", http.StatusUnauthorized)
			return
		}
		now := s.now()
		if err := s.store.MarkEndpointSeen(endpoint.ID, now); err != nil {
			http.Error(w, "endpoint state unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "accepted", "endpoint_id": endpoint.ID, "server_time": now})
	})
}

func (s *Service) verifyConnection(connection tls.ConnectionState) error {
	_, err := s.endpointFromConnection(&connection)
	return err
}

func (s *Service) endpointFromConnection(connection *tls.ConnectionState) (model.Endpoint, error) {
	if connection == nil || len(connection.PeerCertificates) == 0 {
		return model.Endpoint{}, errors.New("client certificate missing")
	}
	certificate := connection.PeerCertificates[0]
	endpoint, err := s.store.EndpointBySerial(certificate.SerialNumber.String())
	if err != nil || endpoint.Status != model.EndpointActive {
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
