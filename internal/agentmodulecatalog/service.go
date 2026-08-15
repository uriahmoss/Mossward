package agentmodulecatalog

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"mossward/internal/agentmodule"
	"mossward/internal/model"
)

type Store interface {
	SaveAgentModulePublisher(agentmodule.Publisher, model.AuditEvent) error
	AgentModulePublisher(string) (agentmodule.Publisher, error)
	ListAgentModulePublishers() ([]agentmodule.Publisher, error)
	CreateAgentModuleRelease(agentmodule.Release, model.AuditEvent) error
	ListAgentModuleReleases() ([]agentmodule.Release, error)
	TransitionAgentModuleRelease(string, agentmodule.ReleaseStatus, agentmodule.ReleaseStatus, string, string, time.Time, model.AuditEvent) error
	SaveAgentModuleAssignment(agentmodule.Assignment, model.AuditEvent) error
	ListAgentModuleAssignments() ([]agentmodule.Assignment, error)
	SetAgentModulesEnabled(bool, model.AuditEvent) error
	LinkEndpointAsset(string, string, model.AuditEvent) error
}

type Service struct {
	store Store
	now   func() time.Time
}

func New(store Store) *Service {
	return &Service{store: store, now: func() time.Time { return time.Now().UTC() }}
}

func (s *Service) SavePublisher(keyID, name string, publicKey ed25519.PublicKey, enabled bool, actorID, sourceIP string) error {
	keyID, name = strings.TrimSpace(keyID), strings.TrimSpace(name)
	if keyID == "" || name == "" || len(publicKey) != ed25519.PublicKeySize {
		return errors.New("publisher key ID, name, and Ed25519 public key are required")
	}
	now := s.now()
	publisher := agentmodule.Publisher{KeyID: keyID, Name: name, PublicKey: append([]byte(nil), publicKey...), Enabled: enabled, CreatedBy: actorID, CreatedAt: now}
	return s.store.SaveAgentModulePublisher(publisher, audit(now, actorID, "agent_module.publisher.saved", "agent_module_publisher", keyID, sourceIP))
}

func (s *Service) Publishers() ([]agentmodule.Publisher, error) {
	return s.store.ListAgentModulePublishers()
}

func (s *Service) Import(envelope []byte, actorID, sourceIP string) (agentmodule.Release, error) {
	keyID, err := envelopePublisher(envelope)
	if err != nil {
		return agentmodule.Release{}, err
	}
	publisher, err := s.store.AgentModulePublisher(keyID)
	if err != nil || !publisher.Enabled {
		return agentmodule.Release{}, errors.New("module publisher is not trusted")
	}
	manifest, pkg, err := agentmodule.Verify(bytes.NewReader(envelope), ed25519.PublicKey(publisher.PublicKey), publisher.KeyID)
	if err != nil {
		return agentmodule.Release{}, err
	}
	if manifest.Kind == agentmodule.KindDeclarative {
		if err := agentmodule.ValidateDeclarativePackage(pkg, manifest); err != nil {
			return agentmodule.Release{}, err
		}
	}
	digest := sha256.Sum256(envelope)
	now := s.now()
	release := agentmodule.Release{ID: hex.EncodeToString(digest[:16]), Manifest: manifest, Envelope: append([]byte(nil), envelope...), Status: agentmodule.ReleaseStaged, CreatedBy: actorID, CreatedAt: now}
	err = s.store.CreateAgentModuleRelease(release, audit(now, actorID, "agent_module.release.imported", "agent_module_release", release.ID, sourceIP))
	return release, err
}

func envelopePublisher(envelope []byte) (string, error) {
	var decoded agentmodule.Envelope
	if err := json.Unmarshal(envelope, &decoded); err != nil {
		return "", errors.New("module envelope is invalid")
	}
	var manifest struct {
		PublisherKeyID string `json:"publisher_key_id"`
	}
	if err := json.Unmarshal(decoded.Manifest, &manifest); err != nil || strings.TrimSpace(manifest.PublisherKeyID) == "" {
		return "", errors.New("module publisher is missing")
	}
	return manifest.PublisherKeyID, nil
}

func (s *Service) Releases() ([]agentmodule.Release, error) { return s.store.ListAgentModuleReleases() }
func (s *Service) Assignments() ([]agentmodule.Assignment, error) {
	return s.store.ListAgentModuleAssignments()
}

func (s *Service) Approve(id, actorID, sourceIP string) error {
	now := s.now()
	return s.store.TransitionAgentModuleRelease(id, agentmodule.ReleaseStaged, agentmodule.ReleaseApproved, actorID, "", now, audit(now, actorID, "agent_module.release.approved", "agent_module_release", id, sourceIP))
}

func (s *Service) Revoke(id, reason, actorID, sourceIP string) error {
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > 500 {
		return errors.New("revocation reason must be between 1 and 500 characters")
	}
	now := s.now()
	return s.store.TransitionAgentModuleRelease(id, agentmodule.ReleaseApproved, agentmodule.ReleaseRevoked, actorID, reason, now, audit(now, actorID, "agent_module.release.revoked", "agent_module_release", id, sourceIP))
}

func (s *Service) Assign(releaseID, targetType, targetID string, ringPercent int, enabled bool, actorID, sourceIP string) error {
	if ringPercent < 1 || ringPercent > 100 {
		return errors.New("deployment ring percentage must be between 1 and 100")
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return err
	}
	now := s.now()
	assignment := agentmodule.Assignment{ID: hex.EncodeToString(idBytes), ReleaseID: releaseID, TargetType: targetType, TargetID: targetID,
		RingPercent: ringPercent, Enabled: enabled, CreatedBy: actorID, CreatedAt: now}
	return s.store.SaveAgentModuleAssignment(assignment, audit(now, actorID, "agent_module.assignment.saved", "agent_module_assignment", assignment.ID, sourceIP))
}

func (s *Service) SetEnabled(enabled bool, actorID, sourceIP string) error {
	now := s.now()
	return s.store.SetAgentModulesEnabled(enabled, audit(now, actorID, "agent_module.emergency_state.updated", "agent_modules", "global", sourceIP))
}

func (s *Service) LinkEndpointAsset(endpointID, assetID, actorID, sourceIP string) error {
	now := s.now()
	return s.store.LinkEndpointAsset(endpointID, assetID, audit(now, actorID, "endpoint.asset.linked", "endpoint", endpointID, sourceIP))
}

func audit(at time.Time, actorID, action, targetType, targetID, sourceIP string) model.AuditEvent {
	return model.AuditEvent{OccurredAt: at, ActorID: actorID, Action: action, Severity: model.AuditWarning, TargetType: targetType, TargetID: targetID, SourceIP: sourceIP, Details: "{}"}
}
