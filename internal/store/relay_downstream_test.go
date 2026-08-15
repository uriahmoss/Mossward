package store

import (
	"errors"
	"testing"
	"time"

	"mossward/internal/model"
)

func TestRelayDownstreamAllowlistIsExclusiveAndRevokedWithRelay(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, endpoint := range []struct{ id, serial string }{{"relay", "relay-serial"}, {"downstream", "downstream-serial"}, {"other-relay", "other-serial"}} {
		_, err := repository.db.Exec(`INSERT INTO endpoints(id,name,status,certificate_serial,certificate_pem,enrolled_at,expires_at) VALUES(?,?,'active',?,'cert',?,?)`, endpoint.id, endpoint.id, endpoint.serial, formatTime(now), formatTime(now.Add(time.Hour)))
		if err != nil {
			t.Fatal(err)
		}
	}
	event := model.AuditEvent{OccurredAt: now, Action: "endpoint.relay.promoted", Severity: model.AuditWarning, TargetType: "endpoint", TargetID: "relay"}
	for _, relayID := range []string{"relay", "other-relay"} {
		authorization := model.EndpointRelayAuthorization{ID: "authorization-" + relayID, EndpointID: relayID, Status: model.EndpointRelayActive, PromotionReason: "test", PromotedBy: "admin", PromotedAt: now}
		if err := repository.PromoteEndpointRelay(authorization, event); err != nil {
			t.Fatal(err)
		}
	}
	downstream := model.RelayDownstreamAuthorization{ID: "downstream-authorization", RelayEndpointID: "relay", DownstreamEndpointID: "downstream",
		Status: model.EndpointRelayActive, AuthorizationReason: "guarded host", AuthorizedBy: "admin", AuthorizedAt: now}
	downstreamEvent := model.AuditEvent{OccurredAt: now, Action: "endpoint.relay_downstream.authorized", Severity: model.AuditWarning, TargetType: "endpoint", TargetID: "downstream"}
	if err := repository.AuthorizeRelayDownstream(downstream, downstreamEvent); err != nil {
		t.Fatal(err)
	}
	downstream.ID, downstream.RelayEndpointID = "duplicate", "other-relay"
	if err := repository.AuthorizeRelayDownstream(downstream, downstreamEvent); !errors.Is(err, ErrRelayDownstreamAlreadyActive) {
		t.Fatalf("duplicate downstream assignment error = %v", err)
	}
	downstream.DownstreamEndpointID = "other-relay"
	if err := repository.AuthorizeRelayDownstream(downstream, downstreamEvent); !errors.Is(err, ErrRelayDownstreamSelfAssignment) {
		t.Fatalf("self-assignment error = %v", err)
	}
	revokeEvent := model.AuditEvent{OccurredAt: now, Action: "endpoint.relay.revoked", Severity: model.AuditWarning, TargetType: "endpoint", TargetID: "relay"}
	if err := repository.RevokeEndpointRelay("relay", "retired", "admin", now.Add(time.Minute), revokeEvent); err != nil {
		t.Fatal(err)
	}
	authorizations, err := repository.ListRelayDownstreamAuthorizations()
	if err != nil || len(authorizations) != 1 || authorizations[0].Status != model.EndpointRelayRevoked || authorizations[0].RevocationReason != "relay authorization revoked" {
		t.Fatalf("downstream history = %#v, error = %v", authorizations, err)
	}
}
