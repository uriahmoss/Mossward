package agentmodule

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
)

func TestManifestValidationAcceptsVersionedCapabilityDeclaration(t *testing.T) {
	if err := validManifest().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestManifestValidationRejectsUnknownOrDuplicateDeclarations(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Manifest)
	}{
		{name: "schema", change: func(m *Manifest) { m.SchemaVersion++ }},
		{name: "api", change: func(m *Manifest) { m.ModuleAPIVersion++ }},
		{name: "identifier", change: func(m *Manifest) { m.ID = "Run Shell" }},
		{name: "version", change: func(m *Manifest) { m.Version = "latest" }},
		{name: "operating system", change: func(m *Manifest) { m.OperatingSystems = []string{"plan9"} }},
		{name: "architecture", change: func(m *Manifest) { m.Architectures = []string{"386"} }},
		{name: "capability", change: func(m *Manifest) { m.Capabilities = []Capability{"shell"} }},
		{name: "duplicate", change: func(m *Manifest) { m.Capabilities = []Capability{CapabilityInventory, CapabilityInventory} }},
		{name: "empty", change: func(m *Manifest) { m.Capabilities = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := validManifest()
			test.change(&manifest)
			if err := manifest.Validate(); err == nil {
				t.Fatal("invalid module manifest was accepted")
			}
		})
	}
}

func validManifest() Manifest {
	return Manifest{SchemaVersion: ManifestSchemaVersion, ModuleAPIVersion: ModuleAPIVersion,
		ID: "com.mossward.inventory", Name: "System inventory", Version: "1.2.3", MinimumAgentVersion: "1.0.0",
		OperatingSystems: []string{"linux", "windows"}, Architectures: []string{"amd64", "arm64"},
		Capabilities: []Capability{CapabilityInventory, CapabilityConfigurationCheck}, Kind: KindDeclarative,
		Permissions: []Permission{PermissionReadOSInfo}, PackageSHA256: strings.Repeat("a", 64), PackageSize: 10,
		PublisherKeyID: "publisher-1", MemoryLimitMB: 32, TimeoutSeconds: 10}
}

func TestSignedPackageVerificationAndCompatibility(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := json.Marshal(DeclarativePackage{SchemaVersion: 1, Checks: []DeclarativeCheck{{
		ID: "com.mossward.os", Source: PermissionReadOSInfo, Field: "version", Operator: "exists", Severity: "info",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	manifest := validManifest()
	envelope, err := Sign(manifest, pkg, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	verified, verifiedPackage, err := Verify(strings.NewReader(string(envelope)), publicKey, "publisher-1")
	if err != nil {
		t.Fatal(err)
	}
	if !verified.Compatible("1.3.0", "linux", "amd64") || verified.Compatible("0.9.0", "linux", "amd64") {
		t.Fatal("module compatibility check returned an unexpected result")
	}
	if err := ValidateDeclarativePackage(verifiedPackage, verified); err != nil {
		t.Fatal(err)
	}
	envelope[len(envelope)-2] ^= 1
	if _, _, err := Verify(strings.NewReader(string(envelope)), publicKey, "publisher-1"); err == nil {
		t.Fatal("tampered module package was accepted")
	}
}
