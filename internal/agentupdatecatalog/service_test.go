package agentupdatecatalog

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"mossward/internal/agentupdate"
	"mossward/internal/model"
)

type memoryStore struct {
	release model.AgentUpdateRelease
}

func (s *memoryStore) CreateAgentUpdateRelease(release model.AgentUpdateRelease, _ model.AuditEvent) error {
	if s.release.ID != "" {
		return errors.New("duplicate")
	}
	s.release = release
	return nil
}
func (s *memoryStore) ListAgentUpdateReleases() ([]model.AgentUpdateRelease, error) {
	return []model.AgentUpdateRelease{s.release}, nil
}
func (s *memoryStore) ApproveAgentUpdateRelease(id, actorID string, at time.Time, _ model.AuditEvent) error {
	if id != s.release.ID || s.release.Status != model.AgentUpdateStaged {
		return errors.New("not found")
	}
	s.release.Status, s.release.ApprovedBy, s.release.ApprovedAt = model.AgentUpdateApproved, actorID, &at
	return nil
}
func (s *memoryStore) RevokeAgentUpdateRelease(id, actorID, reason string, at time.Time, _ model.AuditEvent) error {
	if id != s.release.ID || s.release.Status != model.AgentUpdateApproved {
		return errors.New("not found")
	}
	s.release.Status, s.release.RevokedBy, s.release.RevokedAt, s.release.RevocationReason = model.AgentUpdateRevoked, actorID, &at, reason
	return nil
}
func (s *memoryStore) AssignAgentUpdate(_, releaseID, _ string, _ time.Time, _ model.AuditEvent) error {
	if releaseID != s.release.ID || s.release.Status != model.AgentUpdateApproved {
		return errors.New("not found")
	}
	return nil
}

func TestImportVerifiesSignatureAndStagesBeforeApproval(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	repository := &memoryStore{}
	service := New(repository, "release-key", publicKey)
	service.now = func() time.Time { return now }
	envelope := updateEnvelope(t, now, "release-key", privateKey)
	release, err := service.Import(envelope, "admin", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if release.Status != model.AgentUpdateStaged || release.Version != "1.2.3" || release.CreatedBy != "admin" {
		t.Fatalf("imported release = %#v", release)
	}
	if err := service.Approve(release.ID, "approver", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if repository.release.Status != model.AgentUpdateApproved || repository.release.ApprovedBy != "approver" {
		t.Fatalf("approved release = %#v", repository.release)
	}
	if err := service.Assign("endpoint-1", release.ID, "approver", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
}

func TestImportRejectsTamperingAndRevokeRequiresReason(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	repository := &memoryStore{}
	service := New(repository, "release-key", publicKey)
	service.now = func() time.Time { return now }
	envelope := updateEnvelope(t, now, "release-key", privateKey)
	envelope[len(envelope)-2] ^= 1
	if _, err := service.Import(envelope, "admin", "127.0.0.1"); err == nil {
		t.Fatal("tampered release was imported")
	}
	if err := service.Revoke("release", " ", "admin", "127.0.0.1"); err == nil {
		t.Fatal("empty revocation reason was accepted")
	}
}

func updateEnvelope(t *testing.T, now time.Time, keyID string, privateKey ed25519.PrivateKey) []byte {
	t.Helper()
	manifest := agentupdate.Manifest{SchemaVersion: 1, Version: "1.2.3", OperatingSystem: "linux", Architecture: "amd64",
		ArtifactURL: "https://updates.example.test/agent", ArtifactSHA256: strings.Repeat("a", 64), ArtifactSize: 1024,
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), HealthTimeoutSeconds: 60}
	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	signed := append(append([]byte{}, keyID...), 0)
	signed = append(signed, payload...)
	envelope, err := json.Marshal(agentupdate.Envelope{KeyID: keyID, Manifest: base64.RawStdEncoding.EncodeToString(payload),
		Signature: base64.RawStdEncoding.EncodeToString(ed25519.Sign(privateKey, signed))})
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}
