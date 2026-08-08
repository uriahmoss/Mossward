package store

import (
	"errors"
	"testing"
	"time"

	"mossward/internal/model"
)

func TestAgentUpdateReleaseRequiresSeparateApprovalAndSupportsRevocation(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, err := repository.db.Exec(`INSERT INTO users(id,email,display_name,role,status,created_at,updated_at)
		VALUES('admin','admin@example.test','Admin','administrator','active',?,?)`, formatTime(now), formatTime(now))
	if err != nil {
		t.Fatal(err)
	}
	release := model.AgentUpdateRelease{ID: "release-1", Version: "1.2.3", OperatingSystem: "linux", Architecture: "amd64",
		ArtifactSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ArtifactSize: 1024,
		SigningKeyID: "release-key", Envelope: []byte(`{"signed":true}`), Status: model.AgentUpdateStaged,
		CreatedBy: "admin", CreatedAt: now}
	if err := repository.CreateAgentUpdateRelease(release, model.AuditEvent{OccurredAt: now, ActorID: "admin", Action: "agent_update.imported", Severity: model.AuditWarning}); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.AgentUpdateEnvelope(release.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unapproved update envelope was available: %v", err)
	}
	if err := repository.ApproveAgentUpdateRelease(release.ID, "admin", now.Add(time.Minute), model.AuditEvent{OccurredAt: now.Add(time.Minute), ActorID: "admin", Action: "agent_update.approved", Severity: model.AuditWarning}); err != nil {
		t.Fatal(err)
	}
	envelope, err := repository.AgentUpdateEnvelope(release.ID)
	if err != nil || string(envelope) != string(release.Envelope) {
		t.Fatalf("approved envelope = %q, error = %v", envelope, err)
	}
	if err := repository.RevokeAgentUpdateRelease(release.ID, "admin", "signing concern", now.Add(2*time.Minute), model.AuditEvent{OccurredAt: now.Add(2 * time.Minute), ActorID: "admin", Action: "agent_update.revoked", Severity: model.AuditWarning}); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.AgentUpdateEnvelope(release.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked update envelope was available: %v", err)
	}
	releases, err := repository.ListAgentUpdateReleases()
	if err != nil || len(releases) != 1 || releases[0].Status != model.AgentUpdateRevoked || releases[0].RevocationReason != "signing concern" {
		t.Fatalf("release catalog = %#v, error = %v", releases, err)
	}
}

func TestAgentUpdateReleaseVersionPlatformIsImmutable(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, err := repository.db.Exec(`INSERT INTO users(id,email,display_name,role,status,created_at,updated_at)
		VALUES('admin','admin@example.test','Admin','administrator','active',?,?)`, formatTime(now), formatTime(now))
	if err != nil {
		t.Fatal(err)
	}
	release := model.AgentUpdateRelease{ID: "release-1", Version: "1.2.3", OperatingSystem: "windows", Architecture: "amd64",
		ArtifactSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ArtifactSize: 1024,
		SigningKeyID: "release-key", Envelope: []byte(`{}`), Status: model.AgentUpdateStaged, CreatedBy: "admin", CreatedAt: now}
	event := model.AuditEvent{OccurredAt: now, ActorID: "admin", Action: "agent_update.imported", Severity: model.AuditWarning}
	if err := repository.CreateAgentUpdateRelease(release, event); err != nil {
		t.Fatal(err)
	}
	release.ID, release.ArtifactSHA256 = "release-2", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := repository.CreateAgentUpdateRelease(release, event); err == nil {
		t.Fatal("duplicate version and platform replaced an immutable release")
	}
}

func TestAgentUpdateAssignmentOffersMatchingReleaseAndTracksInstall(t *testing.T) {
	repository, now := updateAssignmentStore(t, "linux")
	event := model.AuditEvent{OccurredAt: now, ActorID: "admin", Action: "agent_update.assigned", Severity: model.AuditWarning}
	if err := repository.AssignAgentUpdate("endpoint-1", "release-1", "admin", now, event); err != nil {
		t.Fatal(err)
	}
	offer, err := repository.AgentUpdateOffer("endpoint-1", now.Add(time.Minute))
	if err != nil || string(offer) != `{"signed":true}` {
		t.Fatalf("update offer = %q, error = %v", offer, err)
	}
	checkIn := model.AgentCheckIn{SchemaVersion: 1, SoftwareVersion: "1.2.3", OperatingSystem: "linux", Architecture: "amd64"}
	if err := repository.RecordEndpointCheckIn("endpoint-1", checkIn, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	var status string
	var installedAt *string
	if err := repository.db.QueryRow(`SELECT status,installed_at FROM agent_update_assignments WHERE endpoint_id='endpoint-1'`).Scan(&status, &installedAt); err != nil {
		t.Fatal(err)
	}
	if status != "installed" || installedAt == nil {
		t.Fatalf("assignment status = %q, installed_at = %v", status, installedAt)
	}
	if offer, err := repository.AgentUpdateOffer("endpoint-1", now.Add(3*time.Minute)); err != nil || offer != nil {
		t.Fatalf("installed update was offered again: %q, error = %v", offer, err)
	}
}

func TestAgentUpdateAssignmentRejectsPlatformMismatch(t *testing.T) {
	repository, now := updateAssignmentStore(t, "windows")
	event := model.AuditEvent{OccurredAt: now, ActorID: "admin", Action: "agent_update.assigned", Severity: model.AuditWarning}
	if err := repository.AssignAgentUpdate("endpoint-1", "release-1", "admin", now, event); err == nil {
		t.Fatal("cross-platform update assignment was accepted")
	}
}

func updateAssignmentStore(t *testing.T, endpointOS string) (*SQLiteStore, time.Time) {
	t.Helper()
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, err := repository.db.Exec(`INSERT INTO users(id,email,display_name,role,status,created_at,updated_at)
		VALUES('admin','admin@example.test','Admin','administrator','active',?,?)`, formatTime(now), formatTime(now))
	if err != nil {
		t.Fatal(err)
	}
	_, err = repository.db.Exec(`INSERT INTO endpoints(id,name,status,certificate_serial,certificate_pem,enrolled_at,expires_at,software_version,operating_system,architecture)
		VALUES('endpoint-1','Host','active','serial','certificate',?,?,'1.0.0',?,'amd64')`,
		formatTime(now), formatTime(now.Add(24*time.Hour)), endpointOS)
	if err != nil {
		t.Fatal(err)
	}
	release := model.AgentUpdateRelease{ID: "release-1", Version: "1.2.3", OperatingSystem: "linux", Architecture: "amd64",
		ArtifactSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ArtifactSize: 1024,
		SigningKeyID: "release-key", Envelope: []byte(`{"signed":true}`), Status: model.AgentUpdateStaged,
		CreatedBy: "admin", CreatedAt: now}
	if err := repository.CreateAgentUpdateRelease(release, model.AuditEvent{OccurredAt: now, ActorID: "admin", Action: "agent_update.imported", Severity: model.AuditWarning}); err != nil {
		t.Fatal(err)
	}
	if err := repository.ApproveAgentUpdateRelease(release.ID, "admin", now, model.AuditEvent{OccurredAt: now, ActorID: "admin", Action: "agent_update.approved", Severity: model.AuditWarning}); err != nil {
		t.Fatal(err)
	}
	return repository, now
}
