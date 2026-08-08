package agentmodule

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

const (
	ManifestSchemaVersion = 1
	ModuleAPIVersion      = 1
	maximumModuleName     = 100
)

type Capability string

const (
	CapabilityInventory          Capability = "inventory"
	CapabilityConfigurationCheck Capability = "configuration_check"
	CapabilityFileMetadata       Capability = "file_metadata"
	CapabilityNetworkMetadata    Capability = "network_metadata"
	CapabilityProcessMetadata    Capability = "process_metadata"
)

type Manifest struct {
	SchemaVersion       int          `json:"schema_version"`
	ModuleAPIVersion    int          `json:"module_api_version"`
	ID                  string       `json:"id"`
	Name                string       `json:"name"`
	Version             string       `json:"version"`
	MinimumAgentVersion string       `json:"minimum_agent_version"`
	OperatingSystems    []string     `json:"operating_systems"`
	Architectures       []string     `json:"architectures"`
	Capabilities        []Capability `json:"capabilities"`
}

var (
	moduleIDPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$`)
	versionPattern  = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
	supportedOS     = []string{"linux", "windows"}
	supportedArch   = []string{"amd64", "arm64"}
	supportedCaps   = []Capability{
		CapabilityInventory,
		CapabilityConfigurationCheck,
		CapabilityFileMetadata,
		CapabilityNetworkMetadata,
		CapabilityProcessMetadata,
	}
)

func (m Manifest) Validate() error {
	if m.SchemaVersion != ManifestSchemaVersion {
		return fmt.Errorf("module manifest schema version must be %d", ManifestSchemaVersion)
	}
	if m.ModuleAPIVersion != ModuleAPIVersion {
		return fmt.Errorf("module API version must be %d", ModuleAPIVersion)
	}
	if !moduleIDPattern.MatchString(m.ID) {
		return errors.New("module ID must be a lowercase dotted identifier")
	}
	if name := strings.TrimSpace(m.Name); name == "" || len(name) > maximumModuleName {
		return fmt.Errorf("module name must be between 1 and %d characters", maximumModuleName)
	}
	if !versionPattern.MatchString(m.Version) || !versionPattern.MatchString(m.MinimumAgentVersion) {
		return errors.New("module and minimum agent versions must use semantic versioning")
	}
	if err := validateDeclarations("operating system", m.OperatingSystems, supportedOS); err != nil {
		return err
	}
	if err := validateDeclarations("architecture", m.Architectures, supportedArch); err != nil {
		return err
	}
	return validateDeclarations("capability", m.Capabilities, supportedCaps)
}

func validateDeclarations[T comparable](name string, values, allowed []T) error {
	if len(values) == 0 {
		return fmt.Errorf("module must declare at least one %s", name)
	}
	seen := make(map[T]struct{}, len(values))
	for _, value := range values {
		if !slices.Contains(allowed, value) {
			return fmt.Errorf("module declares an unsupported %s", name)
		}
		if _, duplicate := seen[value]; duplicate {
			return fmt.Errorf("module declares a duplicate %s", name)
		}
		seen[value] = struct{}{}
	}
	return nil
}
