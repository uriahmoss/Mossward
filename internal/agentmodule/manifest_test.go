package agentmodule

import "testing"

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
		Capabilities: []Capability{CapabilityInventory, CapabilityConfigurationCheck}}
}
