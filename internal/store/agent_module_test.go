package store

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"mossward/internal/agentmodule"
	"mossward/internal/model"
)

func TestAgentModuleCatalogAssignmentRingAndEmergencyStop(t *testing.T) {
	repository := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = repository.db.Exec(`INSERT INTO users(id,email,display_name,role,status,created_at,updated_at) VALUES('admin','admin@example.test','Admin','administrator','active',?,?)`, formatTime(now), formatTime(now))
	if err != nil {
		t.Fatal(err)
	}
	_, err = repository.db.Exec(`INSERT INTO endpoints(id,name,status,certificate_serial,certificate_pem,enrolled_at,expires_at,software_version,operating_system,architecture) VALUES('endpoint-1','Host','active','serial','cert',?,?, '1.2.0','linux','amd64')`, formatTime(now), formatTime(now.Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	pkg, _ := json.Marshal(agentmodule.DeclarativePackage{SchemaVersion: 1, Checks: []agentmodule.DeclarativeCheck{{ID: "com.test.check", Source: agentmodule.PermissionReadOSInfo, Field: "version", Operator: "exists", Severity: "info"}}})
	manifest := testModuleManifest()
	envelope, err := agentmodule.Sign(manifest, pkg, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	release := agentmodule.Release{ID: "release-1", Manifest: manifest, Envelope: envelope, Status: agentmodule.ReleaseStaged, CreatedBy: "admin", CreatedAt: now}
	event := model.AuditEvent{OccurredAt: now, ActorID: "admin", Action: "test", Severity: model.AuditWarning}
	if err := repository.CreateAgentModuleRelease(release, event); err != nil {
		t.Fatal(err)
	}
	if err := repository.TransitionAgentModuleRelease(release.ID, agentmodule.ReleaseStaged, agentmodule.ReleaseApproved, "admin", "", now, event); err != nil {
		t.Fatal(err)
	}
	assignment := agentmodule.Assignment{ID: "assignment-1", ReleaseID: release.ID, TargetType: "endpoint", TargetID: "endpoint-1", RingPercent: 100, Enabled: true, CreatedBy: "admin", CreatedAt: now}
	if err := repository.SaveAgentModuleAssignment(assignment, event); err != nil {
		t.Fatal(err)
	}
	offers, err := repository.AgentModuleOffers("endpoint-1", "1.2.0", "linux", "amd64")
	if err != nil || len(offers) != 1 || offers[0].ReleaseID != release.ID {
		t.Fatalf("offers = %#v, error = %v", offers, err)
	}
	if err := repository.SetAgentModulesEnabled(false, event); err != nil {
		t.Fatal(err)
	}
	offers, err = repository.AgentModuleOffers("endpoint-1", "1.2.0", "linux", "amd64")
	if err != nil || len(offers) != 1 || !offers[0].Disabled {
		t.Fatalf("emergency offer = %#v, error = %v", offers, err)
	}
}

func testModuleManifest() agentmodule.Manifest {
	return agentmodule.Manifest{SchemaVersion: 1, ModuleAPIVersion: 1, ID: "com.test.inventory", Name: "Inventory", Version: "1.0.0", MinimumAgentVersion: "1.0.0",
		OperatingSystems: []string{"linux"}, Architectures: []string{"amd64"}, Capabilities: []agentmodule.Capability{agentmodule.CapabilityInventory}, Kind: agentmodule.KindDeclarative,
		Permissions: []agentmodule.Permission{agentmodule.PermissionReadOSInfo}, PackageSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", PackageSize: 1,
		PublisherKeyID: "publisher", MemoryLimitMB: 32, TimeoutSeconds: 10}
}
