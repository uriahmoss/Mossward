package store

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"mossward/internal/model"
)

func TestEndpointEnrollmentTokenIsSingleUse(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, err := repository.db.Exec(`INSERT INTO users(id,email,display_name,role,status,created_at,updated_at)
		VALUES('admin','admin@example.test','Admin','administrator','active',?,?)`, formatTime(now), formatTime(now))
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte("token"))
	token := model.AgentEnrollmentToken{ID: "enrollment", Name: "Endpoint", TokenHash: hash[:], CreatedBy: "admin",
		CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	if err := repository.CreateAgentEnrollmentToken(token, model.AuditEvent{OccurredAt: now, ActorID: "admin", Action: "test", Severity: model.AuditInfo}); err != nil {
		t.Fatal(err)
	}
	name, err := repository.AgentEnrollmentTokenName(hash[:], now)
	if err != nil || name != "Endpoint" {
		t.Fatalf("unexpected token lookup: %q %v", name, err)
	}
	endpoint := model.Endpoint{ID: "endpoint", Name: name, Status: model.EndpointActive, CertificateSerial: "123",
		CertificatePEM: "certificate", EnrolledAt: now, ExpiresAt: now.Add(24 * time.Hour)}
	event := model.AuditEvent{OccurredAt: now, Action: "endpoint.enrolled", Severity: model.AuditInfo}
	if err := repository.ConsumeAgentEnrollmentToken(hash[:], endpoint, now, event); err != nil {
		t.Fatal(err)
	}
	if err := repository.ConsumeAgentEnrollmentToken(hash[:], endpoint, now, event); !errors.Is(err, ErrInvalidEnrollmentToken) {
		t.Fatalf("expected single-use rejection, got %v", err)
	}
	endpoints, err := repository.ListEndpoints()
	if err != nil || len(endpoints) != 1 || endpoints[0].ID != endpoint.ID {
		t.Fatalf("unexpected endpoints: %#v %v", endpoints, err)
	}
}

func TestEndpointCertificateLifecycle(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, err := repository.db.Exec(`INSERT INTO endpoints(id,name,status,certificate_serial,certificate_pem,enrolled_at,expires_at)
		VALUES('endpoint','Endpoint','active','old','old-cert',?,?)`, formatTime(now), formatTime(now.Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	renewed := now.Add(time.Minute)
	endpoint := model.Endpoint{ID: "endpoint", Name: "Endpoint", Status: model.EndpointActive, CertificateSerial: "new",
		CertificatePEM: "new-cert", EnrolledAt: now, ExpiresAt: now.Add(90 * 24 * time.Hour), RenewedAt: &renewed}
	event := model.AuditEvent{OccurredAt: renewed, Action: "endpoint.certificate.renewed", Severity: model.AuditInfo}
	if err := repository.RenewEndpointCertificate("old", endpoint, event); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.EndpointBySerial("old"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old serial remains active: %v", err)
	}
	if err := repository.RevokeEndpoint("endpoint", "retired", renewed, model.AuditEvent{OccurredAt: renewed, Action: "endpoint.revoked", Severity: model.AuditWarning}); err != nil {
		t.Fatal(err)
	}
	stored, err := repository.EndpointBySerial("new")
	if err != nil || stored.Status != model.EndpointRevoked || stored.RevokedAt == nil || stored.RevocationReason != "retired" {
		t.Fatalf("unexpected revoked endpoint: %#v %v", stored, err)
	}
}

func TestEndpointCollectorPolicyDefaultsDenyAndIsAudited(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, err := repository.db.Exec(`INSERT INTO endpoints(id,name,status,certificate_serial,certificate_pem,enrolled_at,expires_at)
		VALUES('endpoint','Endpoint','active','serial','certificate',?,?)`, formatTime(now), formatTime(now.Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := repository.EndpointBySerial("serial")
	if err != nil || len(endpoint.AllowedCollectors) != 0 {
		t.Fatalf("default collector policy = %v, error = %v", endpoint.AllowedCollectors, err)
	}
	collectors := []model.CollectorID{model.CollectorOperatingSystem, model.CollectorSecurityPosture}
	event := model.AuditEvent{OccurredAt: now, Action: "endpoint.collectors.updated", Severity: model.AuditWarning}
	if err := repository.SetEndpointCollectors("endpoint", collectors, event); err != nil {
		t.Fatal(err)
	}
	endpoint, err = repository.EndpointBySerial("serial")
	if err != nil || len(endpoint.AllowedCollectors) != 2 {
		t.Fatalf("collector policy = %v, error = %v", endpoint.AllowedCollectors, err)
	}
	var count int
	if err := repository.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE action='endpoint.collectors.updated'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("audit event count = %d, error = %v", count, err)
	}
}
