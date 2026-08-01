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
