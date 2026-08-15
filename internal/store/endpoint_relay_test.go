package store

import (
	"errors"
	"testing"
	"time"

	"mossward/internal/model"
)

func TestEndpointRelayPromotionRevocationRetainsHistory(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, err := repository.db.Exec(`INSERT INTO endpoints(id,name,status,certificate_serial,certificate_pem,enrolled_at,expires_at) VALUES('endpoint','Endpoint','active','serial','cert',?,?)`, formatTime(now), formatTime(now.Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	authorization := model.EndpointRelayAuthorization{ID: "relay-1", EndpointID: "endpoint", Status: model.EndpointRelayActive,
		PromotionReason: "guarded segment", PromotedBy: "admin", PromotedAt: now}
	promoteEvent := model.AuditEvent{OccurredAt: now, Action: "endpoint.relay.promoted", Severity: model.AuditWarning, TargetType: "endpoint", TargetID: "endpoint"}
	if err := repository.PromoteEndpointRelay(authorization, promoteEvent); err != nil {
		t.Fatal(err)
	}
	if err := repository.PromoteEndpointRelay(authorization, promoteEvent); !errors.Is(err, ErrEndpointRelayAlreadyActive) {
		t.Fatalf("duplicate promotion error = %v", err)
	}
	revokeEvent := model.AuditEvent{OccurredAt: now, Action: "endpoint.relay.revoked", Severity: model.AuditWarning, TargetType: "endpoint", TargetID: "endpoint"}
	if err := repository.RevokeEndpointRelay("endpoint", "network retired", "admin", now.Add(time.Minute), revokeEvent); err != nil {
		t.Fatal(err)
	}
	authorizations, err := repository.ListEndpointRelayAuthorizations()
	if err != nil || len(authorizations) != 1 || authorizations[0].Status != model.EndpointRelayRevoked || authorizations[0].RevokedAt == nil {
		t.Fatalf("relay history = %#v, error = %v", authorizations, err)
	}
	authorization.ID = "relay-2"
	authorization.PromotedAt = now.Add(2 * time.Minute)
	if err := repository.PromoteEndpointRelay(authorization, promoteEvent); err != nil {
		t.Fatal(err)
	}
	authorizations, err = repository.ListEndpointRelayAuthorizations()
	if err != nil || len(authorizations) != 2 || authorizations[0].Status != model.EndpointRelayActive {
		t.Fatalf("relay re-promotion history = %#v, error = %v", authorizations, err)
	}
	var count int
	if err := repository.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE action IN ('endpoint.relay.promoted','endpoint.relay.revoked')`).Scan(&count); err != nil || count != 3 {
		t.Fatalf("relay audit count = %d, error = %v", count, err)
	}
}
