package agentidentity

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"mossward/internal/model"
	"mossward/internal/store"
)

type memoryEndpointStore struct {
	token    model.AgentEnrollmentToken
	endpoint model.Endpoint
	consumed bool
	lastSeen *time.Time
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
