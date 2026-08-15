package agentmodule

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const (
	ManifestSchemaVersion = 1
	ModuleAPIVersion      = 1
	maximumModuleName     = 100
)

type Capability string
type ModuleKind string
type Permission string

const (
	CapabilityInventory          Capability = "inventory"
	CapabilityConfigurationCheck Capability = "configuration_check"
	CapabilityFileMetadata       Capability = "file_metadata"
	CapabilityNetworkMetadata    Capability = "network_metadata"
	CapabilityProcessMetadata    Capability = "process_metadata"

	KindDeclarative ModuleKind = "declarative"
	KindNative      ModuleKind = "native"

	PermissionReadOSInfo       Permission = "read_os_info"
	PermissionReadPackages     Permission = "read_packages"
	PermissionReadProcesses    Permission = "read_processes"
	PermissionReadConnections  Permission = "read_connections"
	PermissionReadFileMetadata Permission = "read_file_metadata"
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
	Kind                ModuleKind   `json:"kind"`
	Permissions         []Permission `json:"permissions"`
	Entrypoint          string       `json:"entrypoint,omitempty"`
	PackageSHA256       string       `json:"package_sha256"`
	PackageSize         int64        `json:"package_size"`
	PublisherKeyID      string       `json:"publisher_key_id"`
	MemoryLimitMB       int          `json:"memory_limit_mb"`
	TimeoutSeconds      int          `json:"timeout_seconds"`
}

var (
	moduleIDPattern      = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$`)
	versionPattern       = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
	sha256Pattern        = regexp.MustCompile(`^[0-9a-f]{64}$`)
	supportedOS          = []string{"linux", "windows"}
	supportedArch        = []string{"amd64", "arm64"}
	supportedCaps        = []Capability{CapabilityInventory, CapabilityConfigurationCheck, CapabilityFileMetadata, CapabilityNetworkMetadata, CapabilityProcessMetadata}
	supportedPermissions = []Permission{PermissionReadOSInfo, PermissionReadPackages, PermissionReadProcesses,
		PermissionReadConnections, PermissionReadFileMetadata}
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
	if m.Kind != KindDeclarative && m.Kind != KindNative {
		return errors.New("module kind must be declarative or native")
	}
	if m.Kind == KindDeclarative && m.Entrypoint != "" {
		return errors.New("declarative modules cannot declare a native entrypoint")
	}
	if m.Kind == KindNative && !validEntrypoint(m.Entrypoint) {
		return errors.New("native module entrypoint must be a package-relative file name")
	}
	if !sha256Pattern.MatchString(m.PackageSHA256) || m.PackageSize <= 0 || m.PackageSize > MaximumPackageBytes {
		return errors.New("module package digest or size is invalid")
	}
	if strings.TrimSpace(m.PublisherKeyID) == "" {
		return errors.New("module publisher key ID is required")
	}
	if m.MemoryLimitMB < MinimumMemoryLimitMB || m.MemoryLimitMB > MaximumMemoryLimitMB {
		return errors.New("module memory limit is outside the supported range")
	}
	if m.TimeoutSeconds < MinimumTimeoutSeconds || m.TimeoutSeconds > MaximumTimeoutSeconds {
		return errors.New("module timeout is outside the supported range")
	}
	if err := validateDeclarations("operating system", m.OperatingSystems, supportedOS); err != nil {
		return err
	}
	if err := validateDeclarations("architecture", m.Architectures, supportedArch); err != nil {
		return err
	}
	if err := validateDeclarations("capability", m.Capabilities, supportedCaps); err != nil {
		return err
	}
	return validateDeclarations("permission", m.Permissions, supportedPermissions)
}

func (m Manifest) Compatible(agentVersion, operatingSystem, architecture string) bool {
	return versionPattern.MatchString(agentVersion) && compareVersions(agentVersion, m.MinimumAgentVersion) >= 0 &&
		slices.Contains(m.OperatingSystems, operatingSystem) && slices.Contains(m.Architectures, architecture)
}

func compareVersions(left, right string) int {
	leftParts, rightParts := strings.SplitN(left, "-", 2), strings.SplitN(right, "-", 2)
	leftCore, rightCore := strings.Split(leftParts[0], "."), strings.Split(rightParts[0], ".")
	for index := range 3 {
		leftValue, _ := strconv.Atoi(leftCore[index])
		rightValue, _ := strconv.Atoi(rightCore[index])
		if leftValue != rightValue {
			return leftValue - rightValue
		}
	}
	if len(leftParts) == len(rightParts) {
		return 0
	}
	if len(leftParts) == 1 {
		return 1
	}
	return -1
}

func validEntrypoint(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && !strings.ContainsAny(value, `/\\`) && value != "." && value != ".."
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
