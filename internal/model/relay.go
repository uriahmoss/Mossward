package model

import "time"

type EndpointRelayStatus string

const (
	EndpointRelayActive  EndpointRelayStatus = "active"
	EndpointRelayRevoked EndpointRelayStatus = "revoked"
)

type EndpointRelayAuthorization struct {
	ID               string              `json:"id"`
	EndpointID       string              `json:"endpoint_id"`
	Status           EndpointRelayStatus `json:"status"`
	PromotionReason  string              `json:"promotion_reason"`
	PromotedBy       string              `json:"promoted_by"`
	PromotedAt       time.Time           `json:"promoted_at"`
	RevocationReason string              `json:"revocation_reason,omitempty"`
	RevokedBy        string              `json:"revoked_by,omitempty"`
	RevokedAt        *time.Time          `json:"revoked_at,omitempty"`
}

type EndpointRelayTransitionRequest struct {
	Reason string `json:"reason"`
}

type RelayDownstreamAuthorization struct {
	ID                   string              `json:"id"`
	RelayEndpointID      string              `json:"relay_endpoint_id"`
	DownstreamEndpointID string              `json:"downstream_endpoint_id"`
	Status               EndpointRelayStatus `json:"status"`
	AuthorizationReason  string              `json:"authorization_reason"`
	AuthorizedBy         string              `json:"authorized_by"`
	AuthorizedAt         time.Time           `json:"authorized_at"`
	RevocationReason     string              `json:"revocation_reason,omitempty"`
	RevokedBy            string              `json:"revoked_by,omitempty"`
	RevokedAt            *time.Time          `json:"revoked_at,omitempty"`
}
