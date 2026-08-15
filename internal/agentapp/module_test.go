package agentapp

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"

	"mossward/internal/agentmodule"
)

func TestModuleOfferInstallHealthAndEmergencyDisable(t *testing.T) {
	previousOS, previousArchitecture, previousVersion := moduleOperatingSystem, moduleArchitecture, Version
	moduleOperatingSystem, moduleArchitecture, Version = "linux", "amd64", "1.2.0"
	t.Cleanup(func() {
		moduleOperatingSystem, moduleArchitecture, Version = previousOS, previousArchitecture, previousVersion
	})
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkg, _ := json.Marshal(agentmodule.DeclarativePackage{SchemaVersion: 1, Checks: []agentmodule.DeclarativeCheck{{ID: "com.test.check", Source: agentmodule.PermissionReadOSInfo, Field: "version", Operator: "exists", Severity: "info"}}})
	manifest := agentmodule.Manifest{SchemaVersion: 1, ModuleAPIVersion: 1, ID: "com.test.inventory", Name: "Inventory", Version: "1.0.0", MinimumAgentVersion: "0.1.0",
		OperatingSystems: []string{"linux", "windows"}, Architectures: []string{"amd64", "arm64"}, Capabilities: []agentmodule.Capability{agentmodule.CapabilityInventory}, Kind: agentmodule.KindDeclarative,
		Permissions: []agentmodule.Permission{agentmodule.PermissionReadOSInfo}, PublisherKeyID: "publisher", MemoryLimitMB: 32, TimeoutSeconds: 10}
	envelope, err := agentmodule.Sign(manifest, pkg, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := applyModuleOffers(directory, []agentmodule.Offer{{ReleaseID: "release-1", Envelope: envelope}}, map[string]ed25519.PublicKey{"publisher": publicKey}); err != nil {
		t.Fatal(err)
	}
	reports := moduleHealth(directory)
	if len(reports) != 1 || !reports[0].Healthy {
		t.Fatalf("module health = %#v", reports)
	}
	if err := applyModuleOffers(directory, []agentmodule.Offer{{Disabled: true}}, nil); err != nil {
		t.Fatal(err)
	}
	reports = moduleHealth(directory)
	if reports[0].Healthy || reports[0].Error == "" {
		t.Fatalf("disabled module health = %#v", reports)
	}
}
