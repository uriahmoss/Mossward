package agentupdatecatalog

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"mossward/internal/agentupdate"
	"mossward/internal/model"
)

const maximumRevocationReasonLength = 500

type Store interface {
	CreateAgentUpdateRelease(model.AgentUpdateRelease, model.AuditEvent) error
	ListAgentUpdateReleases() ([]model.AgentUpdateRelease, error)
	ApproveAgentUpdateRelease(string, string, time.Time, model.AuditEvent) error
	RevokeAgentUpdateRelease(string, string, string, time.Time, model.AuditEvent) error
	AssignAgentUpdate(string, string, string, time.Time, model.AuditEvent) error
}

type Service struct {
	store Store
	keyID string
	key   ed25519.PublicKey
	now   func() time.Time
}

func New(store Store, keyID string, key ed25519.PublicKey) *Service {
	if keyID == "" || len(key) != ed25519.PublicKeySize {
		return nil
	}
	return &Service{store: store, keyID: keyID, key: append(ed25519.PublicKey(nil), key...), now: func() time.Time { return time.Now().UTC() }}
}

func (s *Service) Import(envelope []byte, actorID, sourceIP string) (model.AgentUpdateRelease, error) {
	now := s.now()
	manifest, err := agentupdate.Verify(bytes.NewReader(envelope), s.key, s.keyID, now)
	if err != nil {
		return model.AgentUpdateRelease{}, err
	}
	digest := sha256.Sum256(envelope)
	release := model.AgentUpdateRelease{ID: hex.EncodeToString(digest[:16]), Version: manifest.Version,
		OperatingSystem: manifest.OperatingSystem, Architecture: manifest.Architecture,
		ArtifactSHA256: manifest.ArtifactSHA256, ArtifactSize: manifest.ArtifactSize, SigningKeyID: s.keyID,
		Envelope: append([]byte(nil), envelope...), Status: model.AgentUpdateStaged, CreatedBy: actorID, CreatedAt: now}
	event := model.AuditEvent{OccurredAt: now, ActorID: actorID, Action: "agent_update.imported", Severity: model.AuditWarning,
		TargetType: "agent_update", TargetID: release.ID, SourceIP: sourceIP, Details: "{}"}
	if err := s.store.CreateAgentUpdateRelease(release, event); err != nil {
		return model.AgentUpdateRelease{}, err
	}
	return release, nil
}

func (s *Service) List() ([]model.AgentUpdateRelease, error) {
	return s.store.ListAgentUpdateReleases()
}

func (s *Service) Approve(id, actorID, sourceIP string) error {
	now := s.now()
	event := model.AuditEvent{OccurredAt: now, ActorID: actorID, Action: "agent_update.approved", Severity: model.AuditWarning,
		TargetType: "agent_update", TargetID: id, SourceIP: sourceIP, Details: "{}"}
	return s.store.ApproveAgentUpdateRelease(id, actorID, now, event)
}

func (s *Service) Revoke(id, reason, actorID, sourceIP string) error {
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > maximumRevocationReasonLength {
		return errors.New("update revocation reason must be between 1 and 500 characters")
	}
	now := s.now()
	event := model.AuditEvent{OccurredAt: now, ActorID: actorID, Action: "agent_update.revoked", Severity: model.AuditWarning,
		TargetType: "agent_update", TargetID: id, SourceIP: sourceIP, Details: "{}"}
	return s.store.RevokeAgentUpdateRelease(id, actorID, reason, now, event)
}

func (s *Service) Assign(endpointID, releaseID, actorID, sourceIP string) error {
	endpointID, releaseID = strings.TrimSpace(endpointID), strings.TrimSpace(releaseID)
	if endpointID == "" || releaseID == "" {
		return errors.New("endpoint and update release are required")
	}
	now := s.now()
	event := model.AuditEvent{OccurredAt: now, ActorID: actorID, Action: "agent_update.assigned", Severity: model.AuditWarning,
		TargetType: "endpoint", TargetID: endpointID, SourceIP: sourceIP, Details: "{}"}
	return s.store.AssignAgentUpdate(endpointID, releaseID, actorID, now, event)
}
